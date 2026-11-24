"""Train two CIC-IoT classifiers and select the deployment model on validation."""

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


def calibrate_threshold(labels, probabilities):
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
    allowed = np.flatnonzero(fpr <= 0.03)
    method = "maximize validation F1 subject to FPR <= 3%"
    if not len(allowed):
        allowed = range(len(cutoffs))
        method = "validation best F1 because no interior cutoff met FPR <= 3%"
    best = max(allowed, key=lambda i: (f1[i], -fpr[i], -abs(cutoffs[i] - 0.5)))
    return float(cutoffs[best]), method


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
        "Both models used identical feature columns and splits, with inverse-frequency "
        "sample weights on training rows only. Each model used its own validation cutoff. "
        "Models meeting the 3% validation FPR target took priority. Among equally feasible "
        "models, validation F1 determined the winner, with lower FPR breaking ties and Random "
        "Forest winning an exact tie. Test rows were evaluated after model selection.", "",
        f"Selected algorithm: **{metrics['winner']}**", "",
        f"Train / validation / test flow counts: {metrics['split_rows']['train']} / "
        f"{metrics['split_rows']['val']} / {metrics['split_rows']['test']}.", "",
        "PR-AUC uses trapezoidal integration. The confusion matrix gives true class by "
        "row and predicted class by column, ordered benign then attack. Latency is the "
        "median of 50 warm, single-row predict_proba calls on this host with one worker thread.", "",
    ]
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
                       report_path="reports/MODEL_COMPARISON.md"):
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
    frames = {key: data.iloc[indices] for key, indices in splits.items()}
    train, val = frames["train"], frames["val"]
    for key in ("train", "val"):
        if set(frames[key]["label"]) != {0, 1}:
            raise ValueError(f"{key} split needs both benign and attack rows")
    weights = compute_sample_weight("balanced", train["label"])
    candidates = [
        RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=1),
        HistGradientBoostingClassifier(max_iter=200, max_depth=8, learning_rate=0.08,
                                       early_stopping=False, random_state=42),
    ]
    models, results = {}, {}
    metrics = {"schema_version": 1, "input": str(input_path), "feature_columns": columns,
               "input_sha256": selection["input_sha256"], "split_hashes": selection["split_hashes"],
               "split_rows": {k: len(v) for k, v in frames.items()}, "models": results}
    with threadpool_limits(limits=1):
        for model in candidates:
            name = type(model).__name__
            model.fit(train[columns], train["label"], sample_weight=weights)
            probabilities = model.predict_proba(val[columns])[:, 1]
            high, method = calibrate_threshold(val["label"], probabilities)
            medium = high / 2
            models[name] = {
                "schema_version": 1, "model": model, "algorithm": name,
                "sklearn_version": sklearn.__version__, "feature_columns": columns,
                "high_threshold": high, "med_threshold": medium,
                "med_threshold_method": "heuristic: half the high threshold",
                "attack_families": sorted(train.loc[train["label"] == 1, "attack_family"].unique()),
            }
            results[name] = {"high_threshold": high, "med_threshold": medium,
                             "threshold_method": method,
                             "validation": evaluate(val, probabilities, high)}
        winner = max(results, key=lambda n: (results[n]["validation"]["fpr"] <= 0.03,
                                              results[n]["validation"]["f1"],
                                              -results[n]["validation"]["fpr"]))
        metrics["winner"] = winner
        test = frames["test"]
        if set(test["label"]) != {0, 1}:
            raise ValueError("Test split needs both classes to evaluate FPR, ROC-AUC and PR-AUC")
        for name, bundle in models.items():
            model = bundle["model"]
            probabilities = model.predict_proba(test[columns])[:, 1]
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
    args = parser.parse_args()
    try:
        metrics = train_and_evaluate(args.input, args.features, args.model, args.metrics, args.report)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Training failed: {error}\n")
    print(f"Saved {metrics['winner']} to {args.model}")


if __name__ == "__main__":
    main()



