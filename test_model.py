"""Isolated synthetic unit fixtures; these are not benchmark results."""

import copy
import json
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
import sklearn
from sklearn.exceptions import NotFittedError

from predict import load_model, predict_row
from preprocess import FEATURE_COLUMNS, load_csv
from train_model import train_and_evaluate


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        rows = []
        for number in range(12):
            row = {column: float(number) for column in FEATURE_COLUMNS}
            row.update(proto="tcp", service="-", state="FIN")
            row.update(id=number, attack_cat="Normal" if number < 6 else "Attack",
                       label=int(number >= 6))
            rows.append(row)
        cls.train = cls.root / "train.csv"
        cls.test = cls.root / "test.csv"
        pd.DataFrame(rows).to_csv(cls.train, index=False)
        held_out = pd.DataFrame([rows[0], rows[-1]])
        held_out["proto"] = "unseen_test_protocol"
        held_out.to_csv(cls.test, index=False)
        cls.model = cls.root / "model.pkl"
        cls.metrics_file = cls.root / "metrics.json"
        cls.metrics = train_and_evaluate(cls.train, cls.test, cls.model, cls.metrics_file)
        cls.bundle = load_model(cls.model)
        cls.X, _ = load_csv(cls.test)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_pipeline_and_leakage_exclusion(self):
        pipeline = self.bundle["pipeline"]
        self.assertEqual(list(pipeline.feature_names_in_), FEATURE_COLUMNS)
        self.assertTrue({"id", "label", "attack_cat"}.isdisjoint(pipeline.feature_names_in_))
        classifier = pipeline.named_steps["classifier"]
        self.assertEqual(classifier.n_estimators, 100)
        self.assertEqual(classifier.random_state, 42)
        self.assertEqual(classifier.n_jobs, -1)
        encoder = pipeline.named_steps["preprocess"].named_transformers_["categorical"]
        self.assertNotIn("unseen_test_protocol", encoder.categories_[0])
        self.assertEqual(encoder.handle_unknown, "ignore")
        self.assertTrue(encoder.sparse_output)

    def test_metrics_are_actual_predictions(self):
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score

        _, labels = load_csv(self.test, require_label=True)
        predicted = self.bundle["pipeline"].predict(self.X)
        expected = {
            "train_rows": 12, "test_rows": 2, "random_state": 42,
            "accuracy": accuracy_score(labels, predicted),
            "precision": precision_score(labels, predicted, zero_division=0),
            "recall": recall_score(labels, predicted, zero_division=0),
            "f1": f1_score(labels, predicted, zero_division=0),
            "confusion_matrix": confusion_matrix(labels, predicted, labels=[0, 1]).tolist(),
            "confusion_matrix_labels": [0, 1],
        }
        self.assertEqual(self.metrics, expected)
        self.assertEqual(json.loads(self.metrics_file.read_text()), expected)

    def test_save_reload_preserves_predictions_and_probabilities(self):
        pipeline = self.bundle["pipeline"]
        reloaded = load_model(self.model)["pipeline"]
        self.assertEqual(pipeline.predict(self.X).tolist(), reloaded.predict(self.X).tolist())
        self.assertEqual(pipeline.predict_proba(self.X).tolist(), reloaded.predict_proba(self.X).tolist())

    def test_prediction_fields_and_no_fitting(self):
        bundle = copy.deepcopy(self.bundle)
        with patch.object(bundle["pipeline"], "fit", side_effect=AssertionError("must not fit")):
            for index in range(2):
                result = predict_row(bundle, self.X.iloc[[index]])
                self.assertEqual(set(result), {"label", "prediction", "attack_probability"})
                self.assertEqual(result["label"], int(bundle["pipeline"].predict(self.X.iloc[[index]])[0]))
                self.assertEqual(result["prediction"], ["normal", "attack"][result["label"]])
                self.assertGreaterEqual(result["attack_probability"], 0)
                self.assertLessEqual(result["attack_probability"], 1)

    def test_probability_selects_class_one(self):
        bundle = copy.deepcopy(self.bundle)
        classifier = bundle["pipeline"].named_steps["classifier"]
        classifier.classes_ = classifier.classes_[::-1]
        import numpy as np
        with patch.object(bundle["pipeline"], "predict", return_value=np.array([1])):
            with patch.object(bundle["pipeline"], "predict_proba", return_value=np.array([[0.8, 0.2]])):
                self.assertEqual(predict_row(bundle, self.X.iloc[[0]])["attack_probability"], 0.8)

    def test_invalid_prediction_rows(self):
        row = self.X.iloc[[0]]
        invalid = [self.X, self.X.iloc[:0], row.drop(columns="dur"),
                   row.assign(label=0), row[FEATURE_COLUMNS[::-1]],
                   row.assign(dur=float("inf")), row.assign(dur="bad"),
                   row.assign(proto=""), row.assign(proto=" tcp "), row.to_dict()]
        for frame in invalid:
            with self.subTest(frame=type(frame).__name__):
                with self.assertRaises(ValueError):
                    predict_row(self.bundle, frame)

    def test_incompatible_and_malformed_bundles(self):
        changes = [{"schema_version": 2}, {"schema_version": True},
                   {"feature_columns": FEATURE_COLUMNS[::-1]},
                   {"sklearn_version": sklearn.__version__ + ".other"},
                   {"pipeline": None}, {"extra": 1}]
        for change in changes:
            with self.subTest(change=list(change)):
                bundle = dict(self.bundle)
                bundle.update(change)
                path = self.root / "invalid.pkl"
                path.write_bytes(pickle.dumps(bundle))
                with self.assertRaises(ValueError):
                    load_model(path)
        for content in (b"", b"not a pickle", pickle.dumps([])):
            path = self.root / "invalid.pkl"
            path.write_bytes(content)
            with self.assertRaises(ValueError):
                load_model(path)

    def test_unfitted_model_rejected(self):
        from sklearn.base import clone
        bundle = dict(self.bundle, pipeline=clone(self.bundle["pipeline"]))
        path = self.root / "unfitted.pkl"
        path.write_bytes(pickle.dumps(bundle))
        with self.assertRaises((ValueError, NotFittedError)):
            load_model(path)

    def test_missing_model(self):
        with self.assertRaises(OSError):
            load_model(self.root / "missing.pkl")

    def test_training_rejects_legacy_schema(self):
        path = self.root / "legacy.csv"
        path.write_text("flow_duration,label\n1,0\n")
        with self.assertRaises(ValueError):
            train_and_evaluate(path, self.test, self.model, self.metrics_file)

    def test_training_rejects_overlapping_paths(self):
        for paths in (
            (self.train, self.train, self.model, self.metrics_file),
            (self.train, self.test, self.train, self.metrics_file),
            (self.train, self.test, self.model, self.test),
            (self.train, self.test, self.model, self.model),
        ):
            with self.subTest(paths=paths):
                with self.assertRaises(ValueError):
                    train_and_evaluate(*paths)


if __name__ == "__main__":
    unittest.main()
