"""Synthetic unit fixtures only; these are not benchmark or training data."""

import csv
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sklearn.exceptions import NotFittedError
from sklearn.utils.validation import check_is_fitted

import download_data
from preprocess import (
    CATEGORICAL_COLUMNS, FEATURE_COLUMNS, NUMERIC_COLUMNS,
    build_preprocessor, load_csv,
)


class PreprocessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "fixture.csv"
        self.header = ["id"] + FEATURE_COLUMNS + ["attack_cat", "label"]
        self.row = {column: "1" for column in self.header}
        self.row.update(proto="tcp", service="-", state="FIN", attack_cat="Normal", label="0")

    def write_csv(self, rows=None, header=None):
        header = self.header if header is None else header
        rows = [self.row] if rows is None else rows
        with self.path.open("w", encoding="utf-8", newline="") as destination:
            writer = csv.writer(destination)
            writer.writerow(header)
            for row in rows:
                writer.writerow([row.get(column, "") for column in header])
        return self.path

    def test_exact_schema_order_labels_and_unchanged_bytes(self):
        self.write_csv([self.row, dict(self.row, label="1", id="2")], self.header[::-1])
        original = self.path.read_bytes()
        features, labels = load_csv(self.path, require_label=True)
        self.assertEqual(len(FEATURE_COLUMNS), 42)
        self.assertEqual(len(NUMERIC_COLUMNS), 39)
        self.assertEqual(CATEGORICAL_COLUMNS, ["proto", "service", "state"])
        self.assertEqual(list(features.columns), FEATURE_COLUMNS)
        self.assertEqual(labels.tolist(), [0, 1])
        self.assertEqual(labels.dtype.kind, "i")
        self.assertTrue(set(["id", "attack_cat", "label"]).isdisjoint(features.columns))
        self.assertEqual(original, self.path.read_bytes())

    def test_prediction_features_only_and_ignored_metadata(self):
        features, labels = load_csv(self.write_csv(header=FEATURE_COLUMNS))
        self.assertEqual(features.shape, (1, 42))
        self.assertIsNone(labels)
        self.write_csv([dict(self.row, label="not ground truth", id="", attack_cat="")])
        other, labels = load_csv(self.path)
        self.assertTrue(features.equals(other))
        self.assertIsNone(labels)

    def test_bom_prefixed_header_and_unchanged_bytes(self):
        self.write_csv([self.row, dict(self.row, label="1", id="2")])
        original = b"\xef\xbb\xbf" + self.path.read_bytes()
        self.path.write_bytes(original)
        for require_label in [False, True]:
            with self.subTest(require_label=require_label):
                features, labels = load_csv(self.path, require_label=require_label)
                self.assertEqual(list(features.columns), FEATURE_COLUMNS)
                self.assertEqual(features.shape, (2, 42))
                if require_label:
                    self.assertEqual(labels.tolist(), [0, 1])
                else:
                    self.assertIsNone(labels)
        result = download_data.verify_file(self.path, 2)
        self.assertEqual(result["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(self.path.read_bytes(), original)

    def test_missing_duplicate_unexpected_columns(self):
        for header, message in [
            (self.header[1:], "missing"),
            (self.header + ["dur"], "Duplicate"),
            (self.header + ["extra"], "unexpected"),
        ]:
            with self.subTest(header=header):
                self.write_csv(header=header)
                with self.assertRaisesRegex(ValueError, message):
                    load_csv(self.path, require_label=True)
        with self.assertRaisesRegex(ValueError, "missing"):
            load_csv(self.write_csv(header=FEATURE_COLUMNS), require_label=True)

    def test_invalid_numeric_and_categorical_values(self):
        for column, values in [("dur", ["", " ", "bad", "NaN", "inf", "-inf"]),
                               ("proto", ["", "  "])]:
            for value in values:
                with self.subTest(column=column, value=value):
                    self.write_csv([dict(self.row, **{column: value})])
                    with self.assertRaisesRegex(ValueError, f"{column}.*row 0"):
                        load_csv(self.path)

    def test_labels_and_metadata_validation(self):
        for column, value in [("label", "2"), ("label", "0.5"), ("label", ""),
                              ("id", "bad"), ("id", "1.5"), ("attack_cat", " ")]:
            with self.subTest(column=column, value=value):
                self.write_csv([dict(self.row, **{column: value})])
                with self.assertRaisesRegex(ValueError, column):
                    load_csv(self.path, require_label=True)

    def test_categorical_tokens_and_numeric_values_preserved(self):
        self.write_csv([dict(self.row, proto=" None ", service=" - ", state=" na ", dur="-1.25")])
        features, _ = load_csv(self.path)
        self.assertEqual(features.loc[0, CATEGORICAL_COLUMNS].tolist(), ["None", "-", "na"])
        self.assertEqual(features.loc[0, "dur"], -1.25)

    def test_empty_ragged_and_malformed_csv(self):
        for content in ["", ",".join(self.header) + "\n", ",".join(self.header) + "\n1\n",
                        ",".join(self.header) + '\n"unterminated']:
            with self.subTest(content=content[:25]):
                self.path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_csv(self.path)
        self.path.write_bytes(b"\xff")
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            load_csv(self.path)

    def test_file_errors_and_legacy_rejection(self):
        with self.assertRaises(OSError):
            load_csv(self.path)
        with self.assertRaisesRegex(ValueError, "UNSW schema mismatch"):
            load_csv(Path(__file__).parent / "data" / "features.csv")

    def test_transformer_unfitted_and_unseen_category(self):
        train, _ = load_csv(self.write_csv([self.row, dict(self.row, proto="udp")]))
        transformer = build_preprocessor()
        with self.assertRaises(NotFittedError):
            check_is_fitted(transformer)
        with self.assertRaises(NotFittedError):
            transformer.transform(train)
        encoded_train = transformer.fit_transform(train)
        encoder = transformer.named_transformers_["categorical"]
        categories_before = [values.copy() for values in encoder.categories_]
        held_out = train.iloc[[0]].copy()
        held_out["proto"] = "unseen-protocol"
        transformed = transformer.transform(held_out)
        self.assertEqual(transformed.shape, (1, encoded_train.shape[1]))
        self.assertEqual(transformed.format, "csr")
        self.assertEqual(transformed[0, :39].toarray().tolist(), [[1.0] * 39])
        self.assertEqual(transformed[0, 39:].sum(), 2)
        for before, after in zip(categories_before, encoder.categories_):
            self.assertEqual(before.tolist(), after.tolist())

    def test_acquisition_verification_checks_counts_and_hash(self):
        self.write_csv([self.row, dict(self.row, label="1")])
        result = download_data.verify_file(self.path, 2)
        self.assertEqual(result["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(result["labels"], {0: 1, 1: 1})
        with self.assertRaisesRegex(ValueError, "expected 3 records"):
            download_data.verify_file(self.path, 3)
        self.write_csv()
        with self.assertRaisesRegex(ValueError, "both binary labels"):
            download_data.verify_file(self.path, 1)

    def test_download_preserves_bytes_and_refuses_overwrite(self):
        self.write_csv([self.row, dict(self.row, label="1")])
        original = self.path.read_bytes()
        response = io.BytesIO(original)
        url = "https://unsw-my.sharepoint.com/example.csv"
        response.geturl = lambda: url
        destination = self.path.parent / "download.csv"
        with patch("download_data.urlopen", return_value=response):
            download_data.download_file(url, destination, 2)
        self.assertEqual(destination.read_bytes(), original)
        with self.assertRaises(FileExistsError):
            download_data.download_file(url, destination, 2)

    def test_bad_download_not_published_and_no_substitution(self):
        destination = self.path.parent / "download.csv"
        response = io.BytesIO(b"<html>Sign in</html>")
        response.geturl = lambda: "https://unsw-my.sharepoint.com/example.csv"
        with patch("download_data.urlopen", return_value=response):
            with self.assertRaises(ValueError):
                download_data.download_file(response.geturl(), destination, 2)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.path.parent.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "official UNSW"):
            download_data.download_file("https://example.com/substitute.csv", destination, 2)

    def test_verification_report_retains_acquisition_history(self):
        self.write_csv([self.row, dict(self.row, label="1")])
        result = download_data.verify_file(self.path, 2)
        readme = self.path.parent / "data" / "README.md"
        readme.parent.mkdir()
        readme.write_text(
            "Source documentation\n<!-- verification:start -->\n"
            "No successful local official-split verification yet.\n<!-- verification:end -->\n",
            encoding="utf-8",
        )
        with patch("download_data.__file__", str(self.path.parent / "download_data.py")):
            download_data._record_verification([("fixture.csv", result, "Original acquisition URL")])
            download_data._record_verification([("fixture.csv", result, "Existing file")])
        report = readme.read_text(encoding="utf-8")
        self.assertIn("Source documentation", report)
        self.assertIn("Original acquisition URL", report)
        self.assertIn("Existing file", report)
        self.assertIn(result["sha256"], report)


if __name__ == "__main__":
    unittest.main()
