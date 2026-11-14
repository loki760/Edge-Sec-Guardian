"""CLI unit tests: synthetic CSVs and mocked ML/LLM, never an end-to-end run."""

import csv
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

import cli
from preprocess import FEATURE_COLUMNS


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "synthetic.csv"
        self.rows = []
        for duration, protocol in [(1, "tcp"), (2, "udp")]:
            row = {column: 1 for column in FEATURE_COLUMNS}
            row.update(dur=duration, proto=protocol, service="-", state="FIN",
                       id=123, attack_cat="ground truth", label=0)
            self.rows.append(row)
        self.write_csv()
        self.bundle = object()
        self.result = {"label": 1, "prediction": "attack", "attack_probability": 0.87654}
        # This isolated test module supplies only the agreed ML interface.
        prediction_module = ModuleType("predict")
        self.load_model = prediction_module.load_model = Mock(return_value=self.bundle)
        self.predict_row = prediction_module.predict_row = Mock(return_value=self.result)
        modules = patch.dict(sys.modules, {"predict": prediction_module})
        modules.start()
        self.addCleanup(modules.stop)
        explanation = patch.object(cli, "explain_prediction", return_value="Mocked unit-test prose.")
        self.explain = explanation.start()
        self.addCleanup(explanation.stop)

    def write_csv(self):
        with self.path.open("w", encoding="utf-8", newline="") as destination:
            writer = csv.DictWriter(destination, fieldnames=list(self.rows[0]))
            writer.writeheader()
            writer.writerows(self.rows)

    def run_cli(self, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["cli.py", *map(str, arguments)]):
            with redirect_stdout(output), redirect_stderr(errors):
                try:
                    status = cli.main()
                except SystemExit as error:
                    status = error.code
        return status, output.getvalue(), errors.getvalue()

    def test_default_row_model_output_and_no_ollama(self):
        status, output, errors = self.run_cli("--input", self.path,
                                              "--ollama-url", "unused without --explain")
        self.assertEqual(status, 0)
        self.assertEqual(errors, "")
        self.assertEqual(output, "Row: 0\nPrediction: attack (label=1)\nAttack probability: 0.8765\n")
        self.load_model.assert_called_once_with("artifacts/model.pkl")
        bundle, selected = self.predict_row.call_args.args
        self.assertIs(bundle, self.bundle)
        self.assertEqual(selected.shape, (1, 42))
        self.assertEqual(selected.iloc[0]["dur"], 1)
        self.explain.assert_not_called()

    def test_explicit_row_and_model_normal_result(self):
        self.predict_row.return_value = {"label": 0, "prediction": "normal", "attack_probability": 0.125}
        status, output, errors = self.run_cli("--input", self.path, "--row", 1,
                                              "--model", "trusted.pkl")
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("Row: 1\nPrediction: normal (label=0)", output)
        self.assertIn("Attack probability: 0.1250", output)
        self.load_model.assert_called_once_with("trusted.pkl")
        selected = self.predict_row.call_args.args[1]
        self.assertEqual(selected.index.tolist(), [1])
        self.assertEqual(selected.iloc[0]["proto"], "udp")

    def test_usage_errors_and_help(self):
        for args in [(), ("--input", self.path, "--row", "bad"),
                     ("--input", self.path, "--unknown")]:
            with self.subTest(args=args):
                status, output, errors = self.run_cli(*args)
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertIn("usage:", errors)
        status, output, errors = self.run_cli("--help")
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("--explain", output)
        self.load_model.assert_not_called()

    def test_invalid_row_indices(self):
        for row in [-1, 2, 100]:
            with self.subTest(row=row):
                status, output, errors = self.run_cli("--input", self.path, "--row", row)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")
                self.assertIn("--row", errors)
                self.assertNotIn("Traceback", errors)
        self.load_model.assert_not_called()

    def test_missing_input(self):
        status, output, errors = self.run_cli("--input", self.path.with_name("missing.csv"))
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("missing.csv", errors)
        self.load_model.assert_not_called()

    def test_bad_csv_and_invalid_unselected_record(self):
        self.rows[1]["dur"] = "invalid"
        self.write_csv()
        status, output, errors = self.run_cli("--input", self.path, "--row", 0)
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("dur", errors)
        self.assertIn("row 1", errors)
        self.path.write_text("legacy,columns\n1,2\n", encoding="utf-8")
        status, output, errors = self.run_cli("--input", self.path)
        self.assertEqual(status, 1)
        self.assertIn("schema mismatch", errors)
        self.load_model.assert_not_called()

    def test_model_failures(self):
        for error in [FileNotFoundError("missing model.pkl"),
                      ValueError("incompatible model"), RuntimeError("model runtime failure")]:
            with self.subTest(error=error):
                self.load_model.side_effect = error
                status, output, errors = self.run_cli("--input", self.path)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")
                self.assertIn(str(error), errors)
                self.assertNotIn("Traceback", errors)
        self.predict_row.assert_not_called()

    def test_prediction_failure(self):
        self.predict_row.side_effect = ValueError("incompatible feature row")
        status, output, errors = self.run_cli("--input", self.path, "--explain")
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("incompatible feature row", errors)
        self.explain.assert_not_called()

    def test_missing_prediction_module(self):
        with patch.dict(sys.modules, {"predict": None}):
            status, output, errors = self.run_cli("--input", self.path)
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("prediction module unavailable", errors)
        self.assertNotIn("Traceback", errors)

    def test_explanation_selected_row_native_values_and_no_ground_truth(self):
        status, output, errors = self.run_cli("--input", self.path, "--row", 1,
                                              "--explain", "--ollama-url",
                                              "http://host.docker.internal:11434")
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("Explanation: Mocked unit-test prose.", output)
        features, prediction = self.explain.call_args.args
        self.assertEqual(list(features), FEATURE_COLUMNS)
        self.assertEqual(features["proto"], "udp")
        self.assertEqual(features["dur"], 2)
        self.assertTrue(all(type(value) in (int, float, str) for value in features.values()))
        self.assertTrue({"id", "label", "attack_cat"}.isdisjoint(features))
        self.assertIs(prediction, self.result)
        self.assertEqual(self.explain.call_args.kwargs,
                         {"base_url": "http://host.docker.internal:11434"})

    def test_explanation_failure_keeps_prediction(self):
        for error in [RuntimeError("Ollama unavailable"), RuntimeError("model missing"),
                      RuntimeError("timed out"), ValueError("invalid local URL")]:
            with self.subTest(error=error):
                self.explain.side_effect = error
                status, output, errors = self.run_cli("--input", self.path, "--explain")
                self.assertEqual(status, 1)
                self.assertIn("Prediction: attack (label=1)", output)
                self.assertIn("Attack probability: 0.8765", output)
                self.assertNotIn("Explanation:", output)
                self.assertEqual(errors, f"Explanation unavailable: {error}\n")


if __name__ == "__main__":
    unittest.main()
