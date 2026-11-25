from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dashboard import Dashboard, capture, capture_live, demo_score, make_server
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

    def test_alert_details_round_trip_through_storage(self):
        for explanation in (
            {},
            {"explanation_status": "pending"},
            {"ai_explanation": "Synthetic explanation.", "recommended_action": "Review this flow."},
        ):
            with self.subTest(explanation=explanation):
                score = dict(verdict="Flagged", ml_probability=0.972, risk_score=0.975,
                             detector_ms=2.2, signals=["ML: test"], **explanation)
                self.state.scorer = lambda features: score
                self.state.accept(self.rows[0])
                current = self.state.snapshot()
                restarted = Dashboard(self.db).snapshot()
                with closing(sqlite3.connect(self.db)) as db:
                    saved = json.loads(db.execute("SELECT flow FROM alerts ORDER BY id DESC LIMIT 1").fetchone()[0])
                status = explanation.get("explanation_status", "ready" if explanation else "disabled")
                for flow in (current["traffic"][0], current["alerts"][0], restarted["alerts"][0], saved):
                    self.assertEqual(flow["ml_probability"], 0.972)
                    self.assertEqual(flow["risk_score"], 0.975)
                    self.assertEqual(flow["detector_ms"], 2.2)
                    self.assertEqual(flow["explanation_status"], status)
                    self.assertEqual(flow["ai_explanation"], explanation.get("ai_explanation"))
                    self.assertEqual(flow["recommended_action"], explanation.get("recommended_action"))

    def test_old_alert_keeps_its_detector_summary_separate(self):
        old = dict(self.rows[0], verdict="Flagged", explanation="Demo thresholds matched",
                   signals=["Demo thresholds matched"])
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("INSERT INTO alerts(flow) VALUES (?)", (json.dumps(old),))
        alert = self.state.snapshot()["alerts"][0]
        self.assertEqual(alert["signals"], old["signals"])
        self.assertEqual(alert["explanation"], old["explanation"])
        self.assertEqual(alert["explanation_status"], "disabled")
        for key in ("ml_probability", "risk_score", "detector_ms", "ai_explanation", "recommended_action"):
            self.assertIsNone(alert[key])

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
        self.assertEqual(state["alerts"][0]["explanation_status"], "disabled")
        self.assertIsNone(state["alerts"][0]["ai_explanation"])
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

    def test_udp_and_icmp_flood_bursts_and_sustained_flows(self):
        row = self.rows[0]
        for protocol, number in [("UDP", 17), ("ICMP", 1)]:
            for duration in (100, 1000):
                with self.subTest(protocol=protocol, duration=duration):
                    scorer = RiskFusionScorer()
                    features = dict(row["features"], PROTOCOL_NUM=number, IN_PKTS=100,
                                    OUT_PKTS=10, FLOW_DURATION_MILLISECONDS=duration)
                    metadata = dict(row["metadata"], protocol=protocol, src_port=52000, dst_port=9000)
                    score = scorer(features, metadata)
                    self.assertEqual(score["verdict"], "Flagged")
                    self.assertEqual(score["signals"], [f"Rule: {protocol} flood pattern"])
                    self.assertIsNone(score["ml_probability"])
                    self.assertEqual(RiskFusionScorer(enable_rules=False)(
                        features, metadata)["signals"], [])

    def test_udp_and_icmp_flood_rules_screen_out_small_or_balanced_flows(self):
        row = self.rows[0]
        for protocol, number in [("UDP", 17), ("ICMP", 1)]:
            for forward, reverse, duration in [(12, 0, 1), (100, 11, 100),
                                                (100, 0, 0), (100, 0, 1200),
                                                (100, 0, 999)]:
                with self.subTest(protocol=protocol, counts=(forward, reverse), duration=duration):
                    features = dict(row["features"], PROTOCOL_NUM=number, IN_PKTS=forward,
                                    OUT_PKTS=reverse, FLOW_DURATION_MILLISECONDS=duration,
                                    PKTS_PER_SEC=(forward + reverse) * 1000 / duration if duration else 0)
                    score = RiskFusionScorer()(features, dict(row["metadata"], protocol=protocol))
                    self.assertEqual(score["verdict"], "Clear")
                    self.assertEqual(score["signals"], [])

    def test_local_management_and_discovery_do_not_reach_scorer(self):
        row = self.rows[0]
        scorer = RiskFusionScorer(management_ips=["10.42.0.1"], dashboard_port=8080)
        peer, pi = "10.42.0.2", "10.42.0.1"
        for source, dest, sport, dport, protocol, expected in (
            (peer, pi, 52000, 8080, "TCP", "local_management"),
            (pi, peer, 22, 52000, "TCP", "local_management"),
            (peer, "224.0.0.251", 5353, 5353, "UDP", "multicast_or_broadcast"),
            (peer, "255.255.255.255", 68, 67, "UDP", "multicast_or_broadcast"),
        ):
            with self.subTest(destination=dest, port=dport):
                metadata = dict(row["metadata"], src_ip=source, dst_ip=dest,
                                src_port=sport, dst_port=dport, protocol=protocol)
                score = scorer({}, metadata)  # Excluded flows do not need model or rule features.
                self.assertEqual(score["verdict"], "Unscored")
                self.assertEqual(score["scope_exclusion"], expected)
                self.assertIsNone(score["ml_probability"])
        self.assertFalse(scorer.sources)
        metadata = dict(row["metadata"], src_ip=peer, dst_ip="198.51.100.80",
                        src_port=52000, dst_port=8080)
        self.assertNotIn("scope_exclusion", scorer(row["features"], metadata))

    def test_bidirectional_quic_is_exempt_from_udp_flood_rule(self):
        row = self.rows[0]
        for ports in ((52000, 443), (443, 52000)):
            metadata = dict(row["metadata"], protocol="UDP", src_port=ports[0], dst_port=ports[1])
            features = dict(row["features"], PROTOCOL_NUM=17, IN_PKTS=1000, OUT_PKTS=1,
                            FLOW_DURATION_MILLISECONDS=200, PKTS_PER_SEC=5005)
            self.assertEqual(RiskFusionScorer()(features, metadata)["signals"], [])
            features["OUT_PKTS"] = 0
            self.assertIn("Rule: UDP flood pattern", RiskFusionScorer()(features, metadata)["signals"])

    def test_port_scan_still_triggers_with_management_exclusion(self):
        row = self.rows[0]
        scorer = RiskFusionScorer(management_ips=["10.42.0.1"])
        scored = []
        for port in range(1, 81):
            metadata = dict(row["metadata"], protocol="TCP", src_ip="10.42.0.2",
                            dst_ip="10.42.0.1", dst_port=port, flow_end_ts=port / 10)
            scored.append(scorer(row["features"], metadata))
        self.assertTrue(any(score["risk_level"] == "High" and
                            "Rule: distinct destination port burst" in score["signals"] for score in scored))

    def test_dns_replies_and_separate_opening_flows_do_not_share_scan_state(self):
        row = self.rows[0]
        scorer = RiskFusionScorer()
        reply = dict(row["metadata"], src_ip="10.42.0.1", dst_ip="10.42.0.2", src_port=53)
        features = dict(row["features"], IN_PKTS=1, OUT_PKTS=0, SYN_RATIO=0, ACK_RATIO=1, PKTS_PER_SEC=0)
        for flags in (0x10, 0x12):
            for port in range(52000, 52012):
                score = scorer(features, dict(reply, dst_port=port, tcp_initial_flags=flags))
                self.assertNotIn("Rule: distinct destination port burst", score["signals"])
        self.assertFalse(scorer.sources)
        for number in (6, 17):
            for index in range(2, 4):
                for port in range(1, 5):
                    metadata = dict(row["metadata"], dst_ip=f"198.51.100.{index}", dst_port=port,
                                    protocol="TCP" if number == 6 else "UDP")
                    score = scorer(dict(features, PROTOCOL_NUM=number), metadata)
                    self.assertNotIn("Rule: distinct destination port burst", score["signals"])
        self.assertEqual(len(scorer.sources), 4)

    def test_bidirectional_https_bursts_need_corroboration(self):
        row = self.rows[0]
        for forward, reverse, flags, syn in [(316, 940, 2, .0016), (8, 7, 16, 0), (100, 4, 2, .01)]:
            features = dict(row["features"], IN_PKTS=forward, OUT_PKTS=reverse, PKTS_PER_SEC=1400,
                            ACK_RATIO=.99, SYN_RATIO=syn)
            score = RiskFusionScorer()(features, dict(row["metadata"], tcp_initial_flags=flags))
            self.assertEqual(score["verdict"], "Clear")
        features.update(IN_PKTS=100, OUT_PKTS=0, ACK_RATIO=0, SYN_RATIO=1)
        score = RiskFusionScorer()(features, dict(row["metadata"], tcp_initial_flags=2))
        self.assertIn("Rule: extreme packet rate", score["signals"])
        self.assertEqual(score["risk_level"], "High")

    def test_single_midstream_web_reply_cannot_become_ml_alert(self):
        import pandas as pd
        import sklearn
        from sklearn.tree import DecisionTreeClassifier

        model = DecisionTreeClassifier(random_state=42).fit(pd.DataFrame({"IN_PKTS": [1, 10]}), [1, 0])
        scorer = RiskFusionScorer(dict(schema_version=1, model=model, algorithm="DecisionTreeClassifier",
                                       feature_columns=["IN_PKTS"], sklearn_version=sklearn.__version__,
                                       med_threshold=.3, high_threshold=.7, med_threshold_method="heuristic",
                                       attack_families=["test"]))
        row = self.rows[0]
        metadata = dict(row["metadata"], src_port=443, dst_port=53894)
        for flag, bits in (("ACK_RATIO", 16), ("FIN_RATIO", 1), ("RST_RATIO", 4), ("ACK_RATIO", 18)):
            with self.subTest(flags=bits):
                features = dict(row["features"], IN_PKTS=1, OUT_PKTS=0, PKTS_PER_SEC=0,
                                SYN_RATIO=int(bool(bits & 2)), ACK_RATIO=0, FIN_RATIO=0, RST_RATIO=0)
                features[flag] = 1
                score = scorer(features, dict(metadata, tcp_initial_flags=bits))
                self.assertEqual(score["scope_exclusion"], "isolated_tcp_reply")
                self.assertIsNone(score["ml_probability"])
                self.assertEqual(score["signals"], [])
        features.update(SYN_RATIO=1, ACK_RATIO=0)
        self.assertEqual(scorer(features, dict(metadata, tcp_initial_flags=2))["risk_level"], "High")

    def test_live_capture_can_continue_when_scoring_queue_is_full(self):
        entered, release = threading.Event(), threading.Event()
        accepted = []

        def accept(row):
            accepted.append(row)
            entered.set()
            release.wait(5)

        def stream(_interface, submit, _engine, _stop):
            try:
                submit(1)
                self.assertTrue(entered.wait(5))
                submit(2)
                submit(3)
            finally:
                release.set()

        with patch("dashboard.stream_live_flows", side_effect=stream), \
             patch("dashboard.LIVE_FLOW_QUEUE_CAPACITY", 1), patch.object(self.state, "accept", side_effect=accept):
            capture_live("fixture", self.state, threading.Event())
        self.assertEqual(accepted, [1, 2])
        self.assertEqual(self.state.engine.counters()["flows_dropped"], 1)


class MockExplainer:
    mode = "ollama"

    def __init__(self, *, paused=False, unsafe=False):
        self.started = threading.Event()
        self.release = threading.Event()
        if not paused:
            self.release.set()
        self.unsafe = unsafe

    def generate(self, prompt, schema):
        self.started.set()
        if not self.release.wait(5):
            raise RuntimeError("Test worker timed out")
        fields = dict(explanation="There was an unusual burst of network activity.",
                      recommended_action="Check whether a device was running an expected network task.")
        if self.unsafe:
            fields["recommended_action"] = "Automatically block this device."
        return json.dumps(fields), {"ttft_ms": 1.0, "tokens_per_sec": 12.0}


class ExplanationQueueTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "alerts.db"
        self.row = next(iter_pcap_flows(Path(__file__).parent / "data/nf_test_sample.pcap"))
        self.level = "High"
        self.verdict = "Flagged"
        self.signals = ["ML: attack probability reached the validation threshold"]

    def new_dashboard(self, backend, **options):
        def score(features):
            return dict(verdict=self.verdict, risk_level=self.level, risk_score=0.9,
                        signals=list(self.signals))

        state = Dashboard(self.db, score, explainer=backend, **options)
        self.addCleanup(state.close)
        self.addCleanup(backend.release.set)
        return state

    def wait_for_status(self, snapshot, alert_id, status):
        deadline = monotonic() + 5
        while monotonic() < deadline:
            state = snapshot()
            alert = next(row for row in state["alerts"] if row["id"] == alert_id)
            if alert["explanation_status"] == status:
                return state, alert
            threading.Event().wait(0.02)
        self.fail(f"Alert {alert_id} did not reach {status}")

    def test_default_gate_skips_medium_and_clear_flows(self):
        backend = MockExplainer()
        state = self.new_dashboard(backend)
        self.verdict = "Clear"
        state.accept(self.row)
        self.verdict, self.level = "Flagged", "Medium"
        state.accept(self.row)
        snapshot = state.snapshot()
        self.assertEqual(len(snapshot["alerts"]), 1)
        self.assertEqual(snapshot["alerts"][0]["explanation_reason"], "below_threshold")
        self.assertEqual(snapshot["explainer"]["invocation_count"], 0)
        self.assertEqual(snapshot["explainer"]["skipped_count"], 1)
        self.level = "High"
        state.accept(self.row)
        snapshot, _ = self.wait_for_status(state.snapshot, 2, "ready")
        self.assertEqual(snapshot["explainer"]["invocation_count"], 1)

    def test_pending_to_ready_over_http_and_queue_overflow(self):
        backend = MockExplainer(paused=True)
        state = self.new_dashboard(backend, explain_min_level="medium", explanation_capacity=1)
        server = make_server("127.0.0.1", 0, state)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)

        def fetch():
            with urlopen(f"http://127.0.0.1:{server.server_port}/api/state", timeout=5) as response:
                return json.load(response)

        self.level = "Medium"
        self.verdict = "Clear"
        state.accept(self.row)
        self.assertEqual(fetch()["alerts"], [])
        self.verdict = "Flagged"
        state.accept(self.row)
        self.assertTrue(backend.started.wait(5))
        self.assertEqual(fetch()["alerts"][0]["explanation_status"], "pending")
        for source in ("192.0.2.20", "192.0.2.21"):
            state.accept(dict(self.row, metadata=dict(self.row["metadata"], src_ip=source)))
        snapshot = fetch()
        self.assertEqual([a["explanation_status"] for a in snapshot["alerts"]], ["skipped", "pending", "pending"])
        self.assertEqual(snapshot["alerts"][0]["explanation_reason"], "queue_full")
        self.assertEqual(snapshot["explainer"]["invocation_count"], 1)
        self.assertEqual(snapshot["explainer"]["skipped_count"], 1)
        state.feedback(1, "confirmed")
        backend.release.set()
        snapshot, alert = self.wait_for_status(fetch, 1, "ready")
        self.assertEqual(alert["feedback"], "confirmed")
        self.assertEqual(alert["verdict"], "Flagged")
        self.assertTrue(alert["ai_explanation"])
        self.assertTrue(alert["recommended_action"])
        self.assertEqual(alert["explanation_timing"]["ttft_ms"], 1.0)
        self.assertEqual(alert["explanation_timing"]["tokens_per_sec"], 12.0)
        self.assertGreater(snapshot["explainer"]["avg_latency_ms"], 0)
        self.assertEqual(snapshot["explainer"]["mode"], "ollama")
        self.assertEqual(alert, next(a for a in Dashboard(self.db).snapshot()["alerts"] if a["id"] == 1))

    def test_unsafe_response_is_discarded_and_timed(self):
        state = self.new_dashboard(MockExplainer(unsafe=True), explanation_cooldown=0)
        for _ in range(2):
            state.accept(self.row)
        snapshot, alert = self.wait_for_status(state.snapshot, 2, "error")
        self.assertEqual(snapshot["explainer"]["error_count"], 2)
        self.assertEqual(snapshot["explainer"]["invocation_count"], 2)
        self.assertIsNone(alert["ai_explanation"])
        self.assertIsNone(alert["recommended_action"])
        self.assertGreater(alert["explanation_timing"]["total_latency_ms"], 0)

    def test_burst_shares_pending_work_then_reuses_until_cooldown_expires(self):
        backend = MockExplainer(paused=True)
        state = self.new_dashboard(backend, explanation_capacity=1)
        with patch("dashboard.monotonic", return_value=100.0) as clock:
            self.signals.append("Rule: distinct destination port burst")
            state.accept(self.row)
            self.assertTrue(backend.started.wait(5))
            self.signals.reverse()
            for _ in range(20):
                state.accept(self.row)
            pending = state.snapshot()
            self.assertTrue(all(a["explanation_status"] == "pending" for a in pending["alerts"]))
            self.assertEqual(pending["explainer"]["invocation_count"], 1)
            self.assertEqual(pending["explainer"]["skipped_count"], 0)
            self.assertEqual(state.explanation_queue.qsize(), 0)
            backend.release.set()
            completed, alert = self.wait_for_status(state.snapshot, 21, "ready")
            self.assertEqual(alert["explanation_source_id"], 1)
            self.assertEqual(completed["explainer"]["reused_count"], 20)
            self.assertIsNone(alert["explanation_timing"])
            self.assertEqual(alert["ai_explanation"], completed["alerts"][-1]["ai_explanation"])
            clock.return_value = 129.0
            state.accept(self.row)
            cached = state.snapshot()
            self.assertEqual(cached["alerts"][0]["explanation_status"], "ready")
            self.assertEqual(cached["explainer"]["invocation_count"], 1)
            self.assertEqual(cached["explainer"]["reused_count"], 21)
            clock.return_value = 130.0
            state.accept(self.row)
            fresh, alert = self.wait_for_status(state.snapshot, 23, "ready")
            self.assertNotIn("explanation_source_id", alert)
            self.assertEqual(fresh["explainer"]["invocation_count"], 2)

    def test_startup_marks_interrupted_jobs_without_retrying(self):
        state = Dashboard(self.db, lambda _: {"verdict": "Flagged", "explanation_status": "pending"})
        state.accept(self.row)
        restarted = Dashboard(self.db)
        restarted.recover_interrupted_explanations()
        snapshot = restarted.snapshot()
        self.assertEqual(snapshot["alerts"][0]["explanation_status"], "skipped")
        self.assertEqual(snapshot["alerts"][0]["explanation_reason"], "interrupted")
        self.assertEqual(snapshot["explainer"]["skipped_count"], 1)
        self.assertEqual(snapshot["explainer"]["invocation_count"], 0)


if __name__ == "__main__":
    unittest.main()
