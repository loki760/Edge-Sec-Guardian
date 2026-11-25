"""Train CIC-IoT classifiers and select a validation operating point."""

import argparse
import json
import os
import pickle
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import perf_counter_ns

import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    auc, average_precision_score, confusion_matrix, precision_recall_curve,
    roc_auc_score,
)
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_limits

from nf_flow_extractor import MODEL_FEATURE_COLUMNS
from select_ciciot_features import load_selection_splits


DEFAULT_TARGET_FPRS = (0.015, 0.020, 0.025)
BASELINE_TARGET_FPR = 0.03


def calibrate_threshold(labels, probabilities, target_fpr=BASELINE_TARGET_FPR, *, prefer_recall=False):
    """Score every attainable validation operating point using interior cutoffs."""
    order = np.argsort(probabilities)
    scores = np.asarray(probabilities)[order]
    labels = np.asarray(labels, dtype=int)[order]
    cutoffs = np.unique(np.clip(
        np.append(scores, [0.5, np.nextafter(1.0, 0.0)]),
        np.finfo(float).tiny, np.nextafter(1.0, 0.0),
    ))
    # At a tied score, all examples move across the boundary together.
    below = np.searchsorted(scores, cutoffs, side="left")
    fn = np.r_[0, labels.cumsum()][below]
    tp = labels.sum() - fn
    fp = len(labels) - below - tp
    fpr = fp / (len(labels) - labels.sum())
    f1 = 2 * tp / (2 * tp + fp + fn)
    allowed = np.flatnonzero(fpr <= target_fpr)
    objective = "recall" if prefer_recall else "F1"
    method = f"maximize validation {objective} subject to FPR <= {target_fpr:.2%}"
    ranking = tp if prefer_recall else f1
    if not len(allowed):
        allowed = range(len(cutoffs))
        ranking = f1
        method = f"validation best F1 because no interior cutoff met FPR <= {target_fpr:.2%}"
    best = max(allowed, key=lambda i: (ranking[i], -fpr[i], -abs(cutoffs[i] - 0.5)))
    return float(cutoffs[best]), method


def validation_point(frame, probabilities, target_fpr, *, prefer_recall=False):
    high, method = calibrate_threshold(frame["label"], probabilities, target_fpr,
                                       prefer_recall=prefer_recall)
    return dict(target_fpr=target_fpr, high_threshold=high, med_threshold=high / 2,
                threshold_method=method, validation=evaluate(frame, probabilities, high))


def recall_rank(point):
    validation = point["validation"]
    feasible = validation["fpr"] <= point["target_fpr"]
    primary = validation["recall"] if feasible else validation["f1"]
    return feasible, primary, -validation["fpr"], -point["target_fpr"]


def family_weights(train, weights):
    """Temper attack imbalance with inverse square-root family frequency."""
    attacks = train["label"] == 1
    counts = train.loc[attacks, "attack_family"].value_counts()
    factors = train.loc[attacks, "attack_family"].map(counts).to_numpy(dtype=float) ** -0.5
    adjusted = weights.copy()
    adjusted[attacks] *= factors / factors.mean()
    return adjusted


def missed_scores(frame, probabilities, point):
    high, medium = point["high_threshold"], point["med_threshold"]
    misses = frame.loc[(frame["label"] == 1) & (probabilities < high), ["attack_family"]].copy()
    misses["score"] = probabilities[(frame["label"] == 1) & (probabilities < high)]
    return {family: dict(missed=len(group), below_medium=int((group.score < medium).sum()),
                         medium_to_high=int((group.score >= medium).sum()),
                         min=float(group.score.min()), median=float(group.score.median()),
                         max=float(group.score.max()))
            for family, group in misses.groupby("attack_family")}


def evaluate(frame, probabilities, threshold):
    labels = frame["label"]
    predicted = probabilities >= threshold
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, fn, tp = map(int, matrix.ravel())
    precision, recall, _ = precision_recall_curve(labels, probabilities)
    attacks = frame.loc[labels == 1, ["attack_family"]].copy()
    attacks["detected"] = predicted[labels.to_numpy() == 1]
    return {
        "rows": len(labels), "accuracy": (tp + tn) / len(labels),
        "precision": tp / (tp + fp) if tp + fp else 0.0, "recall": tp / (tp + fn),
        "f1": 2 * tp / (2 * tp + fp + fn), "fpr": fp / (fp + tn),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc": float(auc(recall, precision)),
        "average_precision": float(average_precision_score(labels, probabilities)),
        "confusion_matrix": matrix.tolist(),
        "per_family_recall": attacks.groupby("attack_family")["detected"].mean().to_dict(),
    }


def warm_latency(model, row):
    model.predict_proba(row)
    elapsed = []
    for _ in range(50):
        start = perf_counter_ns()
        model.predict_proba(row)
        elapsed.append((perf_counter_ns() - start) / 1_000_000)
    return float(np.median(elapsed))


def comparison_report(metrics):
    lines = [
        "# CIC-IoT model comparison", "",
        f"Input: `{metrics['input']}`", "",
        "All candidates used identical feature columns and splits. The original candidates "
        "use inverse-frequency class weights. The family-weighted Histogram Gradient "
        "Boosting candidate additionally weights attack rows by inverse square-root family "
        "frequency, normalized to preserve the total attack weight. All weights use training rows.", "",
        "Feasible validation points take priority, ranked by attack recall, lower achieved "
        "FPR, then tighter target. If every point is infeasible, validation F1 takes priority. "
        "Test evaluation follows selection. Medium thresholds are half the high threshold "
        "and indicate risk without an ML alert.", "",
        f"Selected algorithm: **{metrics['winner']}**", "",
        f"Train / validation / test flow counts: {metrics['split_rows']['train']} / "
        f"{metrics['split_rows']['val']} / {metrics['split_rows']['test']}.", "",
        "PR-AUC uses trapezoidal integration. The confusion matrix gives true class by "
        "row and predicted class by column, ordered benign then attack. Latency is the "
        "median of 50 warm, single-row predict_proba calls on this host with one worker thread.", "",
    ]
    before = metrics["baseline"]
    after = metrics["models"][metrics["winner"]]
    lines.extend(["## Validation grid", "",
                  "| Candidate | FPR target | High threshold | Validation FPR | Validation recall | Feasible |",
                  "|---|---:|---:|---:|---:|---|"])
    for name, result in metrics["models"].items():
        for row in result["validation_grid"]:
            val = row["validation"]
            lines.append(f"| {name} | {row['target_fpr']:.2%} | {row['high_threshold']:.9f} | "
                         f"{val['fpr']:.4%} | {val['recall']:.4%} | "
                         f"{'Yes' if val['fpr'] <= row['target_fpr'] else 'No'} |")
    lines.extend(["", "## Before and after", "",
                  f"Before uses {before['candidate']} with the original 3% validation FPR "
                  f"policy. After uses {metrics['winner']} at a {after['target_fpr']:.2%} target.", "",
                  "| Operating point | Before | After |", "|---|---:|---:|"])
    for key in ("high_threshold", "med_threshold"):
        lines.append(f"| {key} | {before[key]:.12f} | {after[key]:.12f} |")
    for key in ("recall", "fpr"):
        lines.append(f"| Validation {key} | {before['validation'][key]:.9f} | "
                     f"{after['validation'][key]:.9f} |")
    for key in ("accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"):
        lines.append(f"| Test {key} | {before['test'][key]:.9f} | {after['test'][key]:.9f} |")
    lines.extend(["", "| Test attack family | Recall before | Recall after |",
                  "|---|---:|---:|"])
    for family, recall in before["test"]["per_family_recall"].items():
        lines.append(f"| {family} | {recall:.9f} | {after['test']['per_family_recall'][family]:.9f} |")
    lines.extend(["", "## Baseline test misses", "",
                  "The medium band includes its lower boundary and excludes the high threshold.", "",
                  "| Attack family | Missed | Below medium | Medium band | Min score | Median score | Max score |",
                  "|---|---:|---:|---:|---:|---:|---:|"])
    for family, row in before["test_missed_scores"].items():
        lines.append(f"| {family} | {row['missed']} | {row['below_medium']} | "
                     f"{row['medium_to_high']} | {row['min']:.9f} | {row['median']:.9f} | {row['max']:.9f} |")
    lines.append("")
    for name, result in metrics["models"].items():
        test = result["test"]
        lines.extend([
            f"## {name}", "",
            f"High threshold: {result['high_threshold']:.17g} "
            f"({result['threshold_method']}). Medium threshold: {result['med_threshold']:.17g} "
            "(heuristic, half of high).", "",
            f"Validation F1: {result['validation']['f1']:.4f}. "
            f"Validation FPR: {result['validation']['fpr']:.4f}.", "",
            "| Test metric | Value |", "|---|---:|",
        ])
        for key in ("accuracy", "precision", "recall", "f1", "fpr", "roc_auc",
                    "pr_auc", "average_precision"):
            lines.append(f"| {key} | {test[key]:.5f} |")
        lines.extend([
            "", f"Confusion matrix: `{test['confusion_matrix']}`", "",
            f"Serialized bundle: {result['serialized_size_kb']:.2f} KiB. "
            f"Warm inference: {result['warm_single_row_ms']:.4f} ms.", "",
            "| Test attack family | Recall |", "|---|---:|",
        ])
        for family, recall in test["per_family_recall"].items():
            lines.append(f"| {family} | {recall:.5f} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def save_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def train_and_evaluate(input_path, features_path, model_path, metrics_path,
                       report_path="reports/MODEL_COMPARISON.md", target_fprs=DEFAULT_TARGET_FPRS):
    if not target_fprs or any(not 0 < value < 1 for value in target_fprs):
        raise ValueError("FPR targets must be strictly between 0 and 1")
    paths = [Path(p).resolve() for p in
             (input_path, features_path, model_path, metrics_path, report_path)]
    if len(set(paths)) != len(paths):
        raise ValueError("Dataset, selection, model, metrics and report need distinct paths")
    selection = json.loads(paths[1].read_text(encoding="utf-8"))
    columns = selection.get("feature_columns") if isinstance(selection, dict) else None
    if (not isinstance(columns, list) or not columns
            or any(c not in MODEL_FEATURE_COLUMNS for c in columns)
            or len(set(columns)) != len(columns)):
        raise ValueError("Selection must contain unique, recognized feature_columns")
    data, splits = load_selection_splits(paths[0], selection)
    train, val = (data.iloc[splits[key]] for key in ("train", "val"))
    for key, frame in (("train", train), ("val", val)):
        if set(frame["label"]) != {0, 1}:
            raise ValueError(f"{key} split needs both benign and attack rows")
    weights = compute_sample_weight("balanced", train["label"])
    hgb_options = dict(max_iter=200, max_depth=8, learning_rate=0.08,
                       early_stopping=False, random_state=42)
    candidates = {
        "RandomForestClassifier": (RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=1),
                                   weights),
        "HistGradientBoostingClassifier": (HistGradientBoostingClassifier(**hgb_options), weights),
        "Family-weighted HistGradientBoostingClassifier": (
            HistGradientBoostingClassifier(**hgb_options), family_weights(train, weights)),
    }
    models, results, baseline_points = {}, {}, {}
    metrics = {"schema_version": 1, "input": str(input_path), "feature_columns": columns,
               "input_sha256": selection["input_sha256"], "split_hashes": selection["split_hashes"],
               "split_rows": {k: len(v) for k, v in splits.items()}, "models": results}
    with threadpool_limits(limits=1):
        for name, (model, sample_weights) in candidates.items():
            model.fit(train[columns], train["label"], sample_weight=sample_weights)
            probabilities = model.predict_proba(val[columns])[:, 1]
            grid = [validation_point(val, probabilities, target, prefer_recall=True)
                    for target in target_fprs]
            best = max(grid, key=recall_rank)
            results[name] = dict(best, validation_grid=grid)
            if name == type(model).__name__:
                baseline_points[name] = validation_point(val, probabilities, BASELINE_TARGET_FPR)
            models[name] = {
                "schema_version": 1, "model": model, "algorithm": type(model).__name__,
                "candidate": name, "target_fpr": best["target_fpr"],
                "sklearn_version": sklearn.__version__, "feature_columns": columns,
                "high_threshold": best["high_threshold"], "med_threshold": best["med_threshold"],
                "med_threshold_method": "heuristic: half the high threshold",
                "attack_families": sorted(train.loc[train["label"] == 1, "attack_family"].unique()),
            }
        winner = max(results, key=lambda name: recall_rank(results[name]))
        metrics["winner"] = winner
        baseline_name = max(baseline_points, key=lambda name: (
            baseline_points[name]["validation"]["fpr"] <= BASELINE_TARGET_FPR,
            baseline_points[name]["validation"]["f1"], -baseline_points[name]["validation"]["fpr"],
        ))
        baseline = metrics["baseline"] = dict(baseline_points[baseline_name], candidate=baseline_name)
        test = data.iloc[splits["test"]]
        if set(test["label"]) != {0, 1}:
            raise ValueError("Test split needs both classes to evaluate FPR, ROC-AUC and PR-AUC")
        for name, bundle in models.items():
            model = bundle["model"]
            probabilities = model.predict_proba(test[columns])[:, 1]
            if name == baseline_name:
                baseline["test"] = evaluate(test, probabilities, baseline["high_threshold"])
                baseline["test_missed_scores"] = missed_scores(test, probabilities, baseline)
            encoded = pickle.dumps(bundle, protocol=pickle.HIGHEST_PROTOCOL)
            results[name].update({
                "test": evaluate(test, probabilities, bundle["high_threshold"]),
                "serialized_size_kb": len(encoded) / 1024,
                "warm_single_row_ms": warm_latency(model, test[columns].iloc[:1]),
            })
            if name == winner:
                winning_bytes = encoded
    save_bytes(paths[4], comparison_report(metrics).encode("utf-8"))
    save_bytes(paths[3], (json.dumps(metrics, indent=2, allow_nan=False) + "\n").encode("utf-8"))
    save_bytes(paths[2], winning_bytes)
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/processed/ciciot_flows.csv")
    parser.add_argument("--features", default="artifacts/ciciot_selected_features.json")
    parser.add_argument("--model", default="artifacts/ciciot_model.pkl")
    parser.add_argument("--metrics", default="artifacts/ciciot_metrics.json")
    parser.add_argument("--report", default="reports/MODEL_COMPARISON.md")
    parser.add_argument("--target-fpr", type=float, action="append",
                        help="Validation FPR cap, repeatable (default: 0.015, 0.020, 0.025)")
    args = parser.parse_args()
    try:
        metrics = train_and_evaluate(args.input, args.features, args.model, args.metrics, args.report,
                                     args.target_fpr or DEFAULT_TARGET_FPRS)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Training failed: {error}\n")
    print(f"Saved {metrics['winner']} to {args.model}")


if __name__ == "__main__":
    main()



