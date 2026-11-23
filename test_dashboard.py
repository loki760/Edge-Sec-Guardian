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
        self.assertEqual(snapshot["counters"]["flows_emitted"], 3)
        self.assertEqual([row["verdict"] for row in snapshot["traffic"]], ["Unscored"] * 3)

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
        self.assertEqual(len(state["traffic"]), 3)
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


if __name__ == "__main__":
    unittest.main()
