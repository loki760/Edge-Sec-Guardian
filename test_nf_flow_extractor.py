import copy
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scapy.all import TCP, wrpcap

from make_nf_test_pcap import sample_packets
from nf_flow_extractor import FEATURE_COLUMNS, FlowEngine, iter_pcap_flows, stream_live_flows


class FlowTests(unittest.TestCase):
    def test_fixture_features_and_reuse(self):
        engine = FlowEngine()
        rows = list(iter_pcap_flows(Path(__file__).parent / "data/nf_test_sample.pcap", engine))
        expected = [
            [3, 2, 120, 80, 1000, 250, 750, 500, 250, 500, 500, 500, 0],
            [2, 0, 56, 0, 250, 250, 250, 250, 0, 0, 0, 0, 0],
            [1, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ]
        self.assertEqual([row["features"] for row in rows],
                         [dict(zip(FEATURE_COLUMNS, values)) for values in expected])
        self.assertEqual([r["metadata"]["emit_reason"] for r in rows], ["fin", "idle_timeout", "eof"])
        self.assertEqual(rows[1]["metadata"]["emit_delay_ms"], 15750)
        self.assertEqual(engine.counters()["packets_seen"], 8)
        self.assertEqual(engine.counters()["open_flows"], 0)

    def test_unrelated_tail_does_not_change_finalized_row(self):
        packets = sample_packets()
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "sample.pcap")
            wrpcap(path, packets[:5])
            original, = iter_pcap_flows(path)
            wrpcap(path, packets[5:], append=True)
            self.assertEqual(original, next(iter_pcap_flows(path)))

    def test_active_capacity_reset_and_skip(self):
        packets = sample_packets()
        engine = FlowEngine(active_timeout=1, max_open_flows=1)
        list(engine.feed(packets[0]))
        self.assertEqual(list(engine.expire(float(packets[0].time) + 1))[0]["metadata"]["emit_reason"],
                         "active_timeout")
        list(engine.feed(packets[0]))
        evicted, = engine.feed(packets[5])
        snapshot = copy.deepcopy(evicted)
        tcp = packets[0].copy()
        tcp[TCP].flags = "R"
        rows = list(engine.feed(tcp))
        self.assertEqual([r["metadata"]["emit_reason"] for r in rows], ["capacity", "rst"])
        list(engine.feed(tcp.payload.payload))
        self.assertEqual(engine.counters()["packets_skipped"], 1)
        self.assertEqual(evicted, snapshot)

    def test_live_silence_and_interrupt_flush_with_mock_socket(self):
        packets = sample_packets()
        for elapsed, reason in [(16, "idle_timeout"), (1, "interrupt")]:
            with self.subTest(reason=reason):
                stop = threading.Event()
                sock = Mock(closed=False)
                def sniff_once(**options):
                    options["prn"](packets[0])
                    stop.set()
                rows = []
                with patch("nf_flow_extractor.conf.L2listen", return_value=sock), \
                     patch("nf_flow_extractor.sniff", side_effect=sniff_once), \
                     patch("nf_flow_extractor.time.time", return_value=float(packets[0].time) + elapsed):
                    stream_live_flows("fixture", rows.append, stop=stop)
                self.assertEqual(rows[0]["metadata"]["emit_reason"], reason)
                self.assertEqual(rows[0]["features"]["IN_BYTES"], 40)
                sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
