"""Train the fixed UNSW-NB15 baseline and evaluate the separate held-out split."""

import argparse
import json
import pickle
from pathlib import Path
import sys

import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
)
from sklearn.pipeline import Pipeline

from preprocess import FEATURE_COLUMNS, build_preprocessor, load_csv


def train_and_evaluate(train_path, test_path, model_path, metrics_path):
    """Fit only training rows, save the fitted bundle, and return test metrics."""
    train_path, test_path = Path(train_path), Path(test_path)
    model_path, metrics_path = Path(model_path), Path(metrics_path)
    if train_path.resolve() == test_path.resolve():
        raise ValueError("Training and testing must use separate dataset files")
    if model_path.resolve() == metrics_path.resolve():
        raise ValueError("Model and metrics paths must be different")
    for output in (model_path, metrics_path):
        if output.resolve() in (train_path.resolve(), test_path.resolve()):
            raise ValueError("Output paths must not overwrite input datasets")
    X_train, y_train = load_csv(train_path, require_label=True)
    X_test, y_test = load_csv(test_path, require_label=True)
    if set(y_train.unique()) != {0, 1}:
        raise ValueError("Training data must contain both binary classes 0 and 1")
    pipeline = Pipeline([
        ("preprocess", build_preprocessor()),
        ("classifier", RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1,
        )),
    ])
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)
    metrics = {
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "random_state": 42,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, pos_label=1, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        "confusion_matrix_labels": [0, 1],
    }
    bundle = {
        "schema_version": 1,
        "feature_columns": list(FEATURE_COLUMNS),
        "sklearn_version": sklearn.__version__,
        "pipeline": pipeline,
    }
    for output in (model_path, metrics_path):
        output.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("wb") as destination:
        pickle.dump(bundle, destination, protocol=pickle.HIGHEST_PROTOCOL)
    with metrics_path.open("w", encoding="utf-8") as destination:
        json.dump(metrics, destination, indent=2, allow_nan=False)
        destination.write("\n")
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", default="data/raw/UNSW_NB15_training-set.csv")
    parser.add_argument("--test", default="data/raw/UNSW_NB15_testing-set.csv")
    parser.add_argument("--model", default="artifacts/model.pkl")
    parser.add_argument("--metrics", default="artifacts/metrics.json")
    args = parser.parse_args()
    try:
        metrics = train_and_evaluate(args.train, args.test, args.model, args.metrics)
    except (OSError, ValueError) as error:
        print(f"Training failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
