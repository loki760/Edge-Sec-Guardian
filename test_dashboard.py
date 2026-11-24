import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dashboard import Dashboard, capture, demo_score, make_server
from nf_flow_extractor import FEATURE_COLUMNS, iter_pcap_flows
from risk_fusion import RiskFusionScorer


class DashboardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "alerts.db"
        self.state = Dashboard(self.db, demo_score, "Demo rules")
        self.rows = list(iter_pcap_flows(Path(__file__).parent / "data/nf_test_sample.pcap"))
        for row in self.rows:
            self.state.accept(row)

    def test_alert_and_feedback_survive_restart(self):
        alert, = self.state.snapshot()["alerts"]
        self.assertEqual(alert["features"], self.rows[0]["features"])
        self.assertTrue(self.state.feedback(alert["id"], "confirmed"))
        self.assertEqual(Dashboard(self.db).snapshot()["alerts"][0]["feedback"], "confirmed")
        self.assertFalse(self.state.feedback(99, "dismissed"))
        with self.assertRaises(ValueError):
            self.state.feedback(1, "bad")

    def test_scorer_only_receives_features_and_traffic_is_bounded(self):
        def score(features):
            self.assertEqual(list(features), FEATURE_COLUMNS)
            return {"verdict": "Clear"}
        self.state.scorer = score
        for _ in range(52):
            self.state.accept(self.rows[0])
        self.assertEqual(len(self.state.snapshot()["traffic"]), 50)

    def test_dashboard_replay_without_scorer(self):
        state = Dashboard(self.db)
        args = SimpleNamespace(interface=None, interval=0, loop=False,
                               replay_pcap=Path(__file__).parent / "data/nf_test_sample.pcap")
        capture(args, state, threading.Event())
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "Replay complete")
        self.assertEqual(snapshot["counters"]["flows_emitted"], len(self.rows))
        self.assertEqual([row["verdict"] for row in snapshot["traffic"]], ["Unscored"] * len(self.rows))

    def test_http_state_and_feedback(self):
        server = make_server("127.0.0.1", 0, self.state)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_port}"
        with urlopen(base + "/") as response:
            self.assertIn(b"Live traffic", response.read())
        with urlopen(base + "/api/state") as response:
            self.assertEqual(response.headers.get_content_type(), "application/json")
            state = json.load(response)
        self.assertTrue(state["offline"])
        self.assertEqual(len(state["traffic"]), len(self.rows))
        path = base + "/api/alerts/1/feedback"
        for value, expected in [("dismissed", 200), ("bad", 400)]:
            req = Request(path, data=json.dumps({"feedback": value}).encode(),
                          headers={"Content-Type": "application/json"})
            if expected == 200:
                with urlopen(req) as response:
                    self.assertEqual(response.status, expected)
            else:
                with self.assertRaises(HTTPError) as error:
                    urlopen(req)
                self.assertEqual(error.exception.code, expected)
                error.exception.close()
        self.assertEqual(self.state.snapshot()["alerts"][0]["feedback"], "dismissed")

    def test_rules_only_scan_window_and_reset(self):
        scorer = RiskFusionScorer()
        row = self.rows[0]
        features = dict(row["features"], IN_PKTS=1, OUT_PKTS=0, PKTS_PER_SEC=0)
        metadata = dict(row["metadata"], protocol="TCP", flow_end_ts=0)
        for port in range(8):
            score = scorer(features, dict(metadata, dst_port=port, flow_end_ts=port))
            self.assertEqual(score["prediction"], int(port == 7))
        self.assertIsNone(score["ml_probability"])
        self.assertEqual(score["signals"], ["Rule: distinct destination port burst"])
        self.assertEqual(scorer(features, dict(metadata, flow_end_ts=20))["prediction"], 0)
        scorer.reset()
        self.assertEqual(scorer(features, metadata)["prediction"], 0)

    def test_ml_only_and_combined_signals(self):
        import pandas as pd
        import sklearn
        from sklearn.tree import DecisionTreeClassifier

        features = dict(self.rows[0]["features"], IN_PKTS=10, PROTOCOL_NUM=6, SYN_RATIO=1, ACK_RATIO=0)
        model = DecisionTreeClassifier(random_state=42).fit(pd.DataFrame({"IN_PKTS": [1, 10]}), [0, 1])
        bundle = dict(schema_version=1, model=model, algorithm="DecisionTreeClassifier",
                      feature_columns=["IN_PKTS"], sklearn_version=sklearn.__version__,
                      med_threshold=0.3, high_threshold=0.7, med_threshold_method="heuristic",
                      attack_families=["test"])
        metadata = self.rows[0]["metadata"]
        ml = RiskFusionScorer(bundle, enable_rules=False)(features, metadata)
        both = RiskFusionScorer(bundle)(features, metadata)
        self.assertEqual(ml["ml_probability"], 1)
        self.assertEqual(len(ml["signals"]), 1)
        self.assertTrue(ml["signals"][0].startswith("ML:"))
        self.assertIn("Rule: SYN-heavy TCP flow", both["signals"])
        self.assertEqual(both["ml_probability"], ml["ml_probability"])


if __name__ == "__main__":
    unittest.main()
