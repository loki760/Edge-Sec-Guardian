"""Synthetic unit tests for validation-only threshold decisions."""

import unittest

import numpy as np
import pandas as pd

from train_ciciot_model import DEFAULT_TARGET_FPRS, recall_rank, validation_point
from select_ciciot_features import make_splits


class CaptureSplitTests(unittest.TestCase):
    def test_small_capture_can_be_pinned_wholly_to_training(self):
        frame = pd.DataFrame({"source_pcap": ["a.pcap"] * 20 + ["b.pcap"] * 19
                                           + ["c.pcap"] * 18 + ["pi.pcap"] * 3,
                              "label": 0, "attack_family": "Benign"})
        default, _ = make_splits(frame)
        self.assertTrue(set(frame.index[-3:]) <= set(default["test"]))
        pinned, _ = make_splits(frame, ["pi.pcap"])
        self.assertTrue(set(frame.index[-3:]) <= set(pinned["train"]))
        captures = {key: set(frame.iloc[indices]["source_pcap"]) for key, indices in pinned.items()}
        self.assertTrue(captures["val"] and captures["test"])
        self.assertTrue(captures["train"].isdisjoint(captures["val"] | captures["test"]))
        self.assertTrue(captures["val"].isdisjoint(captures["test"]))


class ThresholdTests(unittest.TestCase):
    def test_each_cap_bounds_inclusive_tied_scores(self):
        benign = [0.0] * 195 + [0.7, 0.8, 0.8, 0.9, 0.9]
        attack = [0.7, 0.8, 0.9, 0.95]
        probabilities = np.array(benign + attack)
        frame = pd.DataFrame({"label": [0] * 200 + [1] * 4, "attack_family": "fixture"})
        points = [validation_point(frame, probabilities, target, prefer_recall=True)
                  for target in DEFAULT_TARGET_FPRS]
        # The last point gives identical classifications at 0.5 and 0.7.
        self.assertEqual([point["high_threshold"] for point in points], [0.9, 0.8, 0.5])
        self.assertEqual([point["validation"]["fpr"] for point in points], [0.01, 0.02, 0.025])
        self.assertEqual([point["validation"]["recall"] for point in points], [0.5, 0.75, 1.0])
        self.assertEqual(max(points, key=recall_rank)["target_fpr"], 0.025)
        for point in points:
            self.assertEqual(point["med_threshold"], point["high_threshold"] / 2)

    def test_infeasible_cutoff_and_identical_operating_points(self):
        frame = pd.DataFrame({"label": [0, 0, 1, 1], "attack_family": "fixture"})
        fallback = validation_point(frame, np.ones(4), 0.015, prefer_recall=True)
        self.assertTrue(0 < fallback["high_threshold"] < 1)
        self.assertEqual(fallback["validation"]["fpr"], 1)
        self.assertIn("no interior cutoff met", fallback["threshold_method"])
        perfect = np.array([0.1, 0.2, 0.8, 0.9])
        points = [validation_point(frame, perfect, target, prefer_recall=True)
                  for target in (0.025, 0.020)]
        self.assertEqual(max([fallback, *points], key=recall_rank)["target_fpr"], 0.020)


if __name__ == "__main__":
    unittest.main()
