"""Test the benchmark with an offline PCAP and a mocked local explainer."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from scapy.all import Ether, IP, TCP, wrpcap

from benchmark import Measurements, main


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        root = Path(work.name)
        self.capture = root / "bench.pcap"
        self.model = root / "model.pkl"
        self.model.write_bytes(b"mocked detector loader")
        self.json = root / "out.json"
        self.md = root / "out.md"
        ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        packets = []
        for i in range(12):
            packet = ethernet / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=10, dport=80, flags="S")
            packet.time = 100 + i * 0.1
            packets.append(packet)
        wrpcap(str(self.capture), packets)
        self.args = ["--pcap", str(self.capture), "--model", str(self.model),
                     "--output-json", str(self.json), "--output-md", str(self.md)]

    def test_replay_reports_rules_alert_and_drains_mock_explanation(self):
        backend = Mock(mode="ollama")
        backend.generate.return_value = (
            json.dumps(dict(explanation="A device made several quick connection attempts.",
                            recommended_action="Check whether this device was running an expected task.")),
            dict(ttft_ms=2.0, tokens_per_sec=10.0),
        )
        with patch("benchmark.load_ciciot_bundle", return_value=None), patch(
                "benchmark.create_explainer", return_value=backend):
            self.assertEqual(main([*self.args, "--explainer", "ollama"]), 0)
        report = json.loads(self.json.read_text(encoding="utf-8"))
        fast, slow = report["detector"], report["explainer"]
        self.assertEqual((fast["total_packets"], fast["total_flows"], fast["alert_count"]), (12, 1, 1))
        self.assertGreater(fast["combined_ms"]["p50"], 0)
        self.assertIsNone(fast["packet_drop_count"])
        self.assertEqual(slow["invocation_count"], 1)
        self.assertEqual(slow["invocation_rate_percent"], 100.0)
        self.assertEqual(slow["ttft_ms"]["p95"], 2.0)
        self.assertEqual(slow["tokens_per_sec"]["p50"], 10.0)
        self.assertEqual(slow["error_count"], 0)
        self.assertGreater(report["system_health"]["peak_ram_mb"], 0)
        self.assertEqual(len(report["run"]["pcap_sha256"]), 64)
        self.assertIn("| packet drop count | Unavailable |", self.md.read_text(encoding="utf-8"))
        backend.generate.assert_called_once()

    def test_timed_replay_and_disabled_explanations(self):
        with patch("benchmark.load_ciciot_bundle", return_value=None):
            self.assertEqual(main([*self.args, "--duration-sec", "0.2"]), 0)
        report = json.loads(self.json.read_text(encoding="utf-8"))
        self.assertGreaterEqual(report["detector"]["replay_passes"], 1)
        self.assertGreaterEqual(report["run"]["capture_elapsed_sec"], 0.18)
        self.assertEqual(report["explainer"]["invocation_count"], 0)
        self.assertIsNone(report["explainer"]["ttft_ms"]["p50"])

    def test_reservoir_bounds_memory_and_keeps_exact_maximum(self):
        with patch("benchmark.SAMPLE_LIMIT", 4):
            measurements = Measurements()
            for number in range(20):
                measurements.add(number)
        summary = measurements.summary()
        self.assertEqual((summary["count"], summary["sampled"], summary["max"]), (20, 4, 19))


if __name__ == "__main__":
    unittest.main()
