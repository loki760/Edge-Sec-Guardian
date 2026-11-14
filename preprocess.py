"""Validate UNSW-NB15 CSV records without fitting any preprocessing."""

import csv
import math

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder


FEATURE_COLUMNS = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt",
    "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]
CATEGORICAL_COLUMNS = ["proto", "service", "state"]
NUMERIC_COLUMNS = [name for name in FEATURE_COLUMNS if name not in CATEGORICAL_COLUMNS]
METADATA_COLUMNS = ["id", "attack_cat", "label"]


def _reject_first(mask, column, reason):
    """Report a zero-based data row, excluding the CSV header."""
    if mask.any():
        row = mask[mask].index[0]
        raise ValueError(f"Column '{column}', data row {row}: {reason}")


def _numeric(values, column):
    numbers = pd.to_numeric(values, errors="coerce")
    _reject_first(~numbers.map(math.isfinite), column, "expected a finite number")
    return numbers


def load_csv(path, require_label=False):
    """Return ordered raw features and, when required, integer binary labels.

    Optional prediction metadata is ignored, including any supplied label.
    CSV parsing preserves literal categorical tokens such as 'None' and '-'.
    """
    try:
        with open(path, encoding="utf-8-sig", newline="") as source:
            reader = csv.reader(source, strict=True)
            header = next(reader, None)
            if not header:
                raise ValueError("CSV is empty or has no header")
            duplicates = sorted({name for name in header if header.count(name) > 1})
            if duplicates:
                raise ValueError(f"Duplicate CSV columns: {duplicates}")
            required = FEATURE_COLUMNS + (METADATA_COLUMNS if require_label else [])
            missing = [name for name in required if name not in header]
            unexpected = [name for name in header if name not in FEATURE_COLUMNS + METADATA_COLUMNS]
            if missing or unexpected:
                raise ValueError(f"UNSW schema mismatch: missing={missing}, unexpected={unexpected}")
            rows = []
            for row_number, row in enumerate(reader):
                if len(row) != len(header):
                    raise ValueError(f"Data row {row_number}: expected {len(header)} cells, got {len(row)}")
                rows.append(row)
    except (csv.Error, UnicodeError) as error:
        raise ValueError(f"Invalid UTF-8 CSV: {error}") from error
    if not rows:
        raise ValueError("CSV contains no data rows")
    frame = pd.DataFrame(rows, columns=header)
    features = frame[FEATURE_COLUMNS].copy()
    for column in CATEGORICAL_COLUMNS:
        features[column] = features[column].str.strip()
        _reject_first(features[column].eq(""), column, "empty category")
    for column in NUMERIC_COLUMNS:
        features[column] = _numeric(features[column], column)
    labels = None
    if require_label:
        identifiers = _numeric(frame["id"], "id")
        _reject_first(identifiers.mod(1).ne(0), "id", "expected an integer identifier")
        _reject_first(frame["attack_cat"].str.strip().eq(""), "attack_cat", "empty metadata")
        labels = _numeric(frame["label"], "label")
        _reject_first(~labels.isin([0, 1]), "label", "expected binary label 0 or 1")
        labels = labels.astype(int)
    return features, labels


def build_preprocessor():
    """Create an unfitted transformer; only the ML training pipeline fits it."""
    return ColumnTransformer(
        [("numeric", "passthrough", NUMERIC_COLUMNS),
         ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=True),
          CATEGORICAL_COLUMNS)],
        sparse_threshold=1.0,
    )
