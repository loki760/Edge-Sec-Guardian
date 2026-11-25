import copy
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scapy.all import Ether, IP, Raw, TCP, wrpcap
from scapy.utils import PcapNgWriter

from build_ciciot_dataset import capture_label

from make_nf_test_pcap import sample_packets
from nf_flow_extractor import FEATURE_COLUMNS, FlowEngine, iter_pcap_flows, stream_live_flows


class FlowTests(unittest.TestCase):
    def test_fixture_features_and_reuse(self):
        engine = FlowEngine()
        rows = list(iter_pcap_flows(Path(__file__).parent / "data/nf_test_sample.pcap", engine))
        expected = [
            [6, 3, 2, 120, 80, 1000, 5, 200, 1, 120/81, 40, 40, 40, 0, 64,
             .4, .8, .2, 0, 0, 0, 250, 750, 500, 250, 500, 500, 500, 0],
            [17, 2, 0, 56, 0, 250, 8, 224, 2, 56, 28, 28, 28, 0, 64,
             0, 0, 0, 0, 0, 0, 250, 250, 250, 0, 0, 0, 0, 0],
            [17, 1, 0, 28, 0, 0, 0, 0, 1, 28, 28, 28, 28, 0, 64] + [0] * 14,
            [1, 1, 1, 28, 28, 0, 0, 0, .5, 28/29, 28, 28, 28, 0, 64] + [0] * 14,
        ]
        self.assertEqual([row["features"] for row in rows],
                         [dict(zip(FEATURE_COLUMNS, values)) for values in expected])
        self.assertEqual([r["metadata"]["emit_reason"] for r in rows], ["fin", "idle_timeout", "eof", "eof"])
        self.assertEqual([r["metadata"]["tcp_initial_flags"] for r in rows], [2, None, None, None])
        self.assertEqual(rows[1]["metadata"]["emit_delay_ms"], 15750)
        self.assertEqual(engine.counters()["packets_seen"], 10)
        self.assertEqual(engine.counters()["open_flows"], 0)

    def test_varied_lengths_ttl_and_flags(self):
        first, second = sample_packets()[:2]
        second = second / Raw(b"x" * 20)
        second[IP].ttl = 32
        second[TCP].flags = "RPU"
        engine = FlowEngine()
        list(engine.feed(first))
        row, = engine.feed(second)
        x = row["features"]
        self.assertEqual([x[k] for k in ("PKT_LEN_MIN", "PKT_LEN_MAX", "PKT_LEN_MEAN",
                                         "PKT_LEN_STD", "TTL_MEAN")], [40, 60, 50, 10, 48])
        self.assertEqual([x[k] for k in ("SYN_RATIO", "RST_RATIO", "PSH_RATIO", "URG_RATIO")],
                         [.5] * 4)

    def test_live_offline_and_pcapng_equivalence(self):
        path = Path(__file__).parent / "data/nf_test_sample.pcap"
        expected = list(iter_pcap_flows(path))
        stop = threading.Event()
        packets = sample_packets()
        def feed_all(**options):
            for packet in packets:
                options["prn"](packet)
            stop.set()
        live = []
        with patch("nf_flow_extractor.conf.L2listen", return_value=Mock(closed=False)), \
             patch("nf_flow_extractor.sniff", side_effect=feed_all), \
             patch("nf_flow_extractor.time.time", return_value=float(packets[-1].time)):
            stream_live_flows("fixture", live.append, stop=stop)
        self.assertEqual([r["features"] for r in live], [r["features"] for r in expected])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pcapng"
            with PcapNgWriter(str(path)) as writer:
                for packet in packets:
                    writer.write(packet)
            self.assertEqual(list(iter_pcap_flows(path)), expected)

    def test_caps_stop_reader_and_flush(self):
        path = Path(__file__).parent / "data/nf_test_sample.pcap"
        for caps, seen, reason in [({"max_flows": 1}, 5, "flow_cap"),
                                    ({"max_packets": 2}, 2, "packet_cap")]:
            stats, engine = {}, FlowEngine()
            rows = list(iter_pcap_flows(path, engine, stats=stats, **caps))
            self.assertEqual(stats["reason"], reason)
            self.assertEqual(stats["packets_read"], seen)
            self.assertEqual(len(rows), 1)
            self.assertEqual(engine.counters()["open_flows"], 0)
            if reason == "packet_cap":
                self.assertEqual(rows[0]["metadata"]["emit_reason"], reason)
                self.assertEqual(rows[0]["features"]["OUT_PKTS"], 1)

    def test_label_map_and_ambiguous_names(self):
        path = Path("BenignTraffic1") / "DDoS-ICMP_Flood.pcap"
        for unknown in [path, Path("mystery.pcap")]:
            with self.assertRaisesRegex(ValueError, "Unknown or ambiguous"):
                capture_label(unknown, {})
        self.assertEqual(capture_label(path, {path.as_posix(): {"attack_family": "DDoS", "label": 1}}),
                         ("DDoS", 1))

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

    def test_linux_capture_uses_raw_frame_path_and_reports_capped_buffer(self):
        packet = sample_packets()[0]
        stop = threading.Event()
        raw = Mock(family=17)
        raw.setsockopt.side_effect = OSError("buffer capped")
        raw.getsockopt.side_effect = (8 * 1024 * 1024, struct.pack("=II", 8, 3))
        sock = Mock(ins=raw, LL=Ether)

        def receive():
            stop.set()
            return Ether, bytes(packet), float(packet.time)

        sock.recv_raw.side_effect = receive
        engine, rows = FlowEngine(), []
        with patch("nf_flow_extractor.sys", SimpleNamespace(platform="linux")), \
             patch("nf_flow_extractor.socket.AF_PACKET", 17, create=True), \
             patch("nf_flow_extractor.conf.L2listen", return_value=sock), patch("nf_flow_extractor.sniff") as sniff:
            stream_live_flows("fixture", rows.append, engine, stop)
        sniff.assert_not_called()
        sock.close.assert_called_once()
        self.assertEqual(rows[0]["metadata"]["tcp_initial_flags"], 2)
        self.assertEqual(engine.counters()["receive_buffer_bytes"], 8 * 1024 * 1024)
        self.assertEqual(engine.counters()["packets_dropped"], 3)
        self.assertEqual(engine.counters()["capture_backend"], "af_packet_ethernet")


if __name__ == "__main__":
    unittest.main()
