"""Describe the extracted CIC-IoT-2023 flows and their capture-derived labels."""

import argparse
import csv
from pathlib import Path

import numpy as np
import pandas as pd

from nf_flow_extractor import MODEL_FEATURE_COLUMNS


def read_flows(path):
    metadata = ["source_pcap", "flow_start_ts", "attack_family", "label"]
    with open(path, encoding="utf-8-sig", newline="") as stream:
        header = next(csv.reader(stream), [])
    if len(set(header)) != len(header) or set(header) != set(metadata + list(MODEL_FEATURE_COLUMNS)):
        raise ValueError("Expected four capture/label columns and exactly the 29 model features")
    frame = pd.read_csv(path, dtype={"source_pcap": str, "attack_family": str})
    if frame.empty or frame[metadata].isna().any().any():
        raise ValueError("Empty dataset or missing capture metadata/label")
    if not frame["label"].isin([0, 1]).all():
        raise ValueError("Expected binary numeric labels 0 and 1")
    if not np.isfinite(pd.to_numeric(frame["flow_start_ts"])).all():
        raise ValueError("Expected finite flow_start_ts")
    for name in MODEL_FEATURE_COLUMNS:
        frame[name] = pd.to_numeric(frame[name], errors="raise")
    return frame


def table(frame):
    """Format a Markdown table without pandas' optional tabulate dependency."""
    def cell(value):
        if pd.isna(value):
            return "—"
        if isinstance(value, (float, np.floating)):
            return f"{value:.5g}"
        return str(value).replace("|", "\\|").replace("\n", " ")

    rows = [frame.columns, ["---"] * len(frame.columns), *frame.itertuples(index=False, name=None)]
    return "\n".join("| " + " | ".join(map(cell, row)) + " |" for row in rows)


def run_eda(input_path, report_path="reports/CIC_IOT_2023_EDA.md", plot_dir="reports/eda"):
    frame = read_flows(input_path)
    features = list(MODEL_FEATURE_COLUMNS)
    raw = frame[features]
    clean = raw.replace([np.inf, -np.inf], np.nan)
    stats = clean.describe(percentiles=[.05, .25, .5, .75, .95]).T
    stats["missing/NaN"] = raw.isna().sum()
    stats["infinite"] = np.isinf(raw).sum()
    stats["zero %"] = raw.eq(0).mean() * 100
    stats["unique finite"] = clean.nunique()
    captures = frame.groupby(["source_pcap", "attack_family", "label"]).size().rename("flows")
    mixed = int((frame.groupby("source_pcap")["label"].nunique() > 1).sum())
    overlap = frame.groupby(features, dropna=False, sort=False)[["label", "source_pcap"]].nunique()
    classes = frame.label.value_counts().sort_index().rename("flows").to_frame()
    classes["share %"] = 100 * classes.flows / len(frame)
    protocols = pd.crosstab(frame.source_pcap, frame.PROTOCOL_NUM).rename(
        columns={1: "ICMP flows", 6: "TCP flows", 17: "UDP flows"})
    corr = clean.corr()
    report = [
        "# CIC-IoT-2023 exploratory analysis",
        f"Input `{Path(input_path).name}` contains {len(frame):,} flows from "
        f"{frame.source_pcap.nunique()} captures and {frame.attack_family.nunique()} families.",
        "## Capture and class counts", table(classes.reset_index()), table(captures.reset_index()),
        "## Feature quality", "Statistics use finite values. The 50% column is the median. "
        "Standard deviations use the sample convention. Zero percentages use all rows.",
        table(stats.rename_axis("feature").reset_index()),
        "## Class and family distributions",
    ]
    for field in ["label", "attack_family"]:
        for name, group in clean.groupby(frame[field]):
            dist = group.quantile([.1, .5, .9]).T
            dist.columns = ["p10", "median", "p90"]
            report.extend([f"### {field} = {name} ({len(group):,} flows)",
                           table(dist.rename_axis("feature").reset_index())])
    report.extend(["## Leakage and mixed traffic",
                   f"Exact duplicate rows beyond the first: {frame.duplicated().sum():,}. "
                   f"Duplicate feature vectors beyond the first: {raw.duplicated().sum():,}. "
                   f"Distinct vectors assigned both labels: {(overlap.label > 1).sum():,}. "
                   f"Distinct vectors repeated across capture files: {(overlap.source_pcap > 1).sum():,}. "
                   f"Captures assigned both labels: {mixed}.",
                   "Labels come from capture names or the supplied mapping. Background traffic "
                   "can inherit an attack label. Per-flow ground truth is unavailable. Capture "
                   "identity, family, timestamps and labels are excluded from model inputs. "
                   "Chronological holdouts can share devices and traffic patterns with training. "
                   "This descriptive report covers the entire input. Feature selection derives "
                   "its own statistics from the training partition.",
                   "### Protocol composition within captures", table(protocols.reset_index()),
                   "## Pearson correlations", "A dash indicates an undefined correlation.",
                   table(corr.rename_axis("feature").reset_index())])
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        report.append("Plots unavailable because matplotlib is missing.")
    else:
        output = Path(plot_dir)
        output.mkdir(parents=True, exist_ok=True)
        fig, ax = plt.subplots(figsize=(8, 4))
        frame.attack_family.value_counts().sort_values().plot.barh(ax=ax)
        ax.set_xlabel("Flows")
        fig.tight_layout()
        fig.savefig(output / "family_counts.png")
        plt.close(fig)
        fig, ax = plt.subplots(figsize=(11, 10))
        image = ax.imshow(corr, vmin=-1, vmax=1, cmap="coolwarm")
        ax.set_xticks(range(len(features)), features, rotation=90, fontsize=7)
        ax.set_yticks(range(len(features)), features, fontsize=7)
        fig.colorbar(image, ax=ax, shrink=.7)
        fig.tight_layout()
        fig.savefig(output / "correlations.png")
        plt.close(fig)
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n\n".join(report) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/processed/ciciot_flows.csv")
    parser.add_argument("--report", default="reports/CIC_IOT_2023_EDA.md")
    parser.add_argument("--plot-dir", default="reports/eda")
    args = parser.parse_args()
    try:
        run_eda(args.input, args.report, args.plot_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, f"EDA failed: {error}\n")
