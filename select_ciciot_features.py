"""Compare flow-feature subsets using training and validation captures."""

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score, precision_score, recall_score

from eda_ciciot import read_flows, table
from nf_flow_extractor import MODEL_FEATURE_COLUMNS


PARTITIONS = ("train", "val", "test")
SPLIT_VERSION = 1


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def chronological_positions(capture):
    ordered = capture.sort_values("flow_start_ts", kind="stable")
    n = len(ordered)
    if n < 5:
        raise ValueError(f"At least five flows needed for chronological split of {ordered.source_pcap.iloc[0]}")
    first = max(2, min(int(.70 * n), n - 3))
    second = max(first + 2, min(int(.85 * n), n - 1))
    starts = ordered.flow_start_ts
    ends = starts + ordered.FLOW_DURATION_MILLISECONDS / 1000
    # Leave one entire flow before each boundary out and purge overlapping intervals.
    parts = []
    for lo, hi in [(0, first), (first, second)]:
        before = ordered.index[lo:hi - 1]
        parts.append(before[ends.loc[before] < starts.iloc[hi]].tolist())
    parts.append(ordered.index[second:].tolist())
    if not all(parts):
        raise ValueError(f"No non-overlapping chronological holdout for {ordered.source_pcap.iloc[0]}")
    return parts


def make_splits(frame):
    grouped = frame.groupby("source_pcap")[["attack_family", "label"]].nunique()
    if (grouped > 1).any().any():
        raise ValueError("One source_pcap has multiple families or labels")
    positions = {part: [] for part in PARTITIONS}
    audit = []
    for family, family_rows in frame.groupby("attack_family", sort=True):
        captures = list(family_rows.groupby("source_pcap", sort=True))
        captures.sort(key=lambda item: (-len(item[1]), item[0]))
        counts = np.zeros(3, dtype=int)
        targets = np.array([.70, .15, .15]) * len(family_rows)
        for sequence, (source, capture) in enumerate(captures):
            if len(captures) < 3:
                method = "chronological with embargo"
                parts = chronological_positions(capture)
            else:
                method = "whole capture"
                empty = np.flatnonzero(counts == 0)
                eligible = empty if len(empty) == len(captures) - sequence else range(3)
                # Minimize squared distance to the target row counts after placing this file.
                target = max(eligible, key=lambda index: targets[index] - counts[index])
                parts = [[], [], []]
                parts[target] = capture.index.tolist()
            sizes = [len(part) for part in parts]
            counts += sizes
            for name, indices in zip(PARTITIONS, parts):
                positions[name].extend(indices)
            audit.append(dict(source_pcap=source, attack_family=family, method=method,
                              **dict(zip(PARTITIONS, sizes)), embargo=len(capture) - sum(sizes)))
    return {k: np.array(sorted(v), dtype=np.int64) for k, v in positions.items()}, audit


def split_hashes(splits):
    return {name: hashlib.sha256(indices.astype("<i8").tobytes()).hexdigest()
            for name, indices in splits.items()}


def load_selection_splits(input_path, selection):
    if selection.get("split_version") != SPLIT_VERSION:
        raise ValueError("Unknown feature selection split version")
    if selection.get("input_sha256") != file_digest(input_path):
        raise ValueError("Feature selection input SHA256 does not match this CSV")
    frame = read_flows(input_path)
    splits, _ = make_splits(frame)
    if selection.get("split_hashes") != split_hashes(splits):
        raise ValueError("Partition membership differs from feature selection")
    return frame, splits


def candidate_subsets(train):
    features = list(MODEL_FEATURE_COLUMNS)
    flags = {"SYN_RATIO", "ACK_RATIO", "FIN_RATIO", "RST_RATIO", "PSH_RATIO", "URG_RATIO"}
    volume = [c for c in features if c not in flags | {"PROTOCOL_NUM", "TTL_MEAN"}]
    correlations = train[features].corr().abs()
    chosen = []
    for name in features:
        if train[name].nunique() > 1 and not (correlations.loc[name, chosen] >= .98).any():
            chosen.append(name)
    if not chosen:
        raise ValueError("No varying model features in training data")
    return {"A: all features": features, "B: volume and timing": volume,
            "C: volume, timing and flags": [c for c in features if c in volume or c in flags],
            "D: training EDA": chosen}


def select_features(input_path, output_path="artifacts/ciciot_selected_features.json",
                    report_path="reports/FEATURE_SELECTION.md"):
    frame = read_flows(input_path)
    splits, audit = make_splits(frame)
    train, val = (frame.iloc[splits[name]] for name in ("train", "val"))
    for name, part in [("training", train), ("validation", val)]:
        if part.label.nunique() != 2:
            raise ValueError(f"Both classes required in {name}")
        if not np.isfinite(part[list(MODEL_FEATURE_COLUMNS)]).all().all():
            raise ValueError(f"Non-finite feature in {name}")
    candidates = candidate_subsets(train)
    scores = []
    best_key = None
    for name, columns in candidates.items():
        forest = RandomForestClassifier(n_estimators=50, class_weight="balanced", random_state=42)
        forest.fit(train[columns], train.label)
        predicted = forest.predict(val[columns])
        f1 = float(f1_score(val.label, predicted, zero_division=0))
        scores.append(dict(subset=name, features=len(columns), f1=f1,
                           precision=float(precision_score(val.label, predicted, zero_division=0)),
                           recall=float(recall_score(val.label, predicted, zero_division=0))))
        key = (f1, -len(columns))
        if best_key is None or key > best_key:
            best_key, winner, best_model = key, name, forest
    selected = candidates[winner]
    sample = val.sample(n=min(5000, len(val)), random_state=42)
    perm = permutation_importance(best_model, sample[selected], sample.label,
                                  scoring="f1", n_repeats=3, random_state=42)
    importance = dict(zip(selected, perm.importances_mean.tolist()))
    result = dict(schema_version=1, split_version=SPLIT_VERSION, input_sha256=file_digest(input_path),
                  split_hashes=split_hashes(splits), split_counts={k: len(v) for k, v in splits.items()},
                  split_audit=audit, candidates=candidates, validation_scores=scores,
                  selected_subset=winner, feature_columns=selected, permutation_importance=importance)
    report = [
        "# Flow feature selection", f"Input `{Path(input_path).name}`, SHA256 `{result['input_sha256']}`.",
        "## Split membership", "Targets are 70% training, 15% validation and 15% test. "
        "Within each family, whole captures are assigned largest first to the partition "
        "furthest below target, reserving one file per partition. Families with fewer than "
        "three captures use chronological blocks in each file. One flow immediately before "
        "each boundary and earlier flows ending at or after the next block are withheld. "
        "These blocks still share capture conditions, limiting generalization claims.",
        table(pd.DataFrame(audit)),
        "## Validation comparison", "Each subset uses a 50-tree random forest with balanced "
        "training class weights and seed 42. The highest validation attack F1 wins. "
        "Ties favor fewer features, then the first listed subset. D removes training constants "
        "and later contract-order features with absolute Pearson correlation ≥0.98 to an "
        "already retained feature. Validation and test retain their original class mix.",
        table(pd.DataFrame(scores)), f"Selected **{winner}**. Ordered inputs: " + ", ".join(selected) + ".",
        "## Validation permutation importance", f"Mean decrease in attack F1 over three permutations "
        f"on {len(sample):,} uniformly sampled validation flows (seed 42).",
        table(pd.DataFrame(sorted(importance.items(), key=lambda x: -x[1]),
                           columns=["feature", "mean F1 decrease"]))]
    for path in [Path(output_path), Path(report_path)]:
        path.parent.mkdir(parents=True, exist_ok=True)
    Path(report_path).write_text("\n\n".join(report) + "\n", encoding="utf-8")
    Path(output_path).write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/processed/ciciot_flows.csv")
    parser.add_argument("--output", default="artifacts/ciciot_selected_features.json")
    parser.add_argument("--report", default="reports/FEATURE_SELECTION.md")
    args = parser.parse_args()
    try:
        select_features(args.input, args.output, args.report)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Feature selection failed: {error}\n")
