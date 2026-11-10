"""Small offline tests; no root access or live network traffic is needed."""

import csv
import math
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from scapy.all import Ether, IP, IPv6, ICMP, TCP, UDP, Raw, wrpcap

from extract_features import (
    FEATURE_COLUMNS, FLOW_COLUMNS, flow_to_row, parse_packet, read_flows,
)
from make_sample_pcap import make_sample_pcap


class ExtractFeaturesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.sample_path = Path(self.directory.name) / "sample.pcap"
        make_sample_pcap(self.sample_path)
        self.flows, self.ports, self.total, self.skipped = read_flows(self.sample_path)
        self.tcp_key = ("192.168.1.5", "192.168.1.10", 5000, 80, "TCP")
        self.tcp_packets = self.flows[self.tcp_key]
        self.tcp_row = flow_to_row(self.tcp_packets, self.ports)

    def write_packets(self, packets):
        path = Path(self.directory.name) / "extra.pcap"
        wrpcap(str(path), packets)
        return path

    def run_cli(self, input_path, output_path):
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("extract_features.py")),
             "--input", str(input_path), "--output", str(output_path)],
            capture_output=True, text=True,
        )

    def test_packet_fields_and_reverse_grouping(self):
        self.assertEqual(self.total, 6)
        self.assertEqual(self.skipped, 0)
        self.assertEqual(len(self.flows), 3)
        self.assertEqual(len(self.tcp_packets), 3)
        self.assertEqual(self.tcp_packets[0], {
            "source_ip": "192.168.1.5", "destination_ip": "192.168.1.10",
            "source_port": 5000, "destination_port": 80, "protocol": "TCP",
            "length": 54, "timestamp": 1000.0, "flags": 2,
        })
        self.assertEqual(self.tcp_packets[1]["source_port"], 80)

    def test_tcp_counts_duration_and_rates(self):
        row = self.tcp_row
        self.assertEqual(row["total_fwd_pkts"], 2)
        self.assertEqual(row["total_bwd_pkts"], 1)
        self.assertEqual(row["total_fwd_bytes"], 112)
        self.assertEqual(row["total_bwd_bytes"], 54)
        self.assertEqual(row["flow_duration"], 2.0)
        self.assertEqual(row["pkt_rate"], 1.5)
        self.assertEqual(row["byte_rate"], 83.0)

    def test_packet_lengths_and_inter_arrival_times(self):
        self.assertAlmostEqual(self.tcp_row["pkt_len_mean"], 166 / 3)
        self.assertAlmostEqual(self.tcp_row["pkt_len_std"], math.sqrt(32 / 9))
        self.assertEqual(self.tcp_row["pkt_len_max"], 58)
        self.assertEqual(self.tcp_row["iat_mean"], 1.0)
        self.assertEqual(self.tcp_row["iat_std"], 0.5)

    def test_tcp_flag_ratios(self):
        self.assertAlmostEqual(self.tcp_row["syn_ratio"], 2 / 3)
        self.assertAlmostEqual(self.tcp_row["rst_ratio"], 1 / 3)
        self.assertAlmostEqual(self.tcp_row["ack_ratio"], 2 / 3)

    def test_udp_counts_rates_and_zero_flags(self):
        key = ("192.168.1.5", "192.168.1.20", 6000, 53, "UDP")
        row = flow_to_row(self.flows[key], self.ports)
        self.assertEqual(row["total_fwd_pkts"], 1)
        self.assertEqual(row["total_bwd_pkts"], 1)
        self.assertEqual(row["total_fwd_bytes"], 46)
        self.assertEqual(row["total_bwd_bytes"], 50)
        self.assertEqual(row["flow_duration"], 1.0)
        self.assertEqual(row["pkt_rate"], 2.0)
        self.assertEqual(row["byte_rate"], 96.0)
        self.assertEqual(row["pkt_len_mean"], 48)
        self.assertEqual(row["pkt_len_std"], 2)
        self.assertEqual(row["iat_mean"], 1)
        self.assertEqual(row["iat_std"], 0)
        for name in ("syn_ratio", "rst_ratio", "ack_ratio"):
            self.assertEqual(row[name], 0)

    def test_unique_destination_ports_include_both_directions(self):
        self.assertEqual(self.ports["192.168.1.5"], {80, 53, 443})
        self.assertEqual(self.ports["192.168.1.10"], {5000})
        self.assertEqual(self.tcp_row["unique_dst_ports_by_src"], 3)

    def test_single_packet_flow(self):
        key = ("192.168.1.5", "192.168.1.10", 5001, 443, "TCP")
        row = flow_to_row(self.flows[key], self.ports)
        self.assertEqual(row["total_fwd_pkts"], 1)
        self.assertEqual(row["total_bwd_pkts"], 0)
        self.assertEqual(row["total_fwd_bytes"], 54)
        self.assertEqual(row["total_bwd_bytes"], 0)
        for name in ("flow_duration", "pkt_rate", "byte_rate", "iat_mean", "iat_std", "pkt_len_std"):
            self.assertEqual(row[name], 0)
        self.assertEqual(row["syn_ratio"], 1)

    def test_zero_duration_multiple_packets(self):
        packets = [packet.copy() for packet in self.tcp_packets]
        for packet in packets:
            packet["timestamp"] = 1000.0
        row = flow_to_row(packets, self.ports)
        for name in ("flow_duration", "pkt_rate", "byte_rate", "iat_mean", "iat_std"):
            self.assertEqual(row[name], 0)

    def test_out_of_order_timestamps_keep_first_packet_direction(self):
        packets = [self.tcp_packets[1], self.tcp_packets[2], self.tcp_packets[0]]
        row = flow_to_row(packets, self.ports)
        self.assertEqual(row["source_ip"], "192.168.1.10")
        self.assertEqual(row["total_fwd_pkts"], 1)
        self.assertEqual(row["total_bwd_pkts"], 2)
        self.assertEqual(row["flow_duration"], 2)
        self.assertEqual(row["iat_mean"], 1)
        self.assertEqual(row["iat_std"], 0.5)
        self.assertEqual(row["unique_dst_ports_by_src"], 1)

    def test_unsupported_malformed_and_fragmented_packets_are_skipped(self):
        ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        packets = [
            ethernet / IPv6() / UDP(),
            ethernet / IP() / ICMP(),
            ethernet / IP(flags="MF") / TCP(),
            ethernet / IP(frag=1) / Raw(b"fragment"),
            Ether(bytes(ethernet / IP() / TCP())[:30]),
            ethernet / IP() / TCP(dataofs=4),
            ethernet / IP() / UDP(len=7),
            ethernet / IP(len=200) / TCP(),
        ]
        flows, ports, total, skipped = read_flows(self.write_packets(packets))
        self.assertEqual(total, len(packets))
        self.assertEqual(skipped, len(packets))
        self.assertEqual(flows, {})
        self.assertEqual(ports, {})

    def test_missing_tcp_flags(self):
        packet = Ether(bytes(Ether() / IP() / TCP()))
        packet[TCP].flags = None
        parsed = parse_packet(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["flags"], 0)

    def test_tcp_and_udp_with_identical_endpoints_are_separate_flows(self):
        ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        packets = [
            ethernet / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
            ethernet / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=80),
        ]
        flows, ports, total, skipped = read_flows(self.write_packets(packets))
        self.assertEqual(len(flows), 2)
        self.assertEqual(ports["10.0.0.1"], {80})
        self.assertEqual(total, 2)
        self.assertEqual(skipped, 0)

    def test_csv_columns_and_cli(self):
        output_path = Path(self.directory.name) / "results" / "features.csv"
        result = self.run_cli(self.sample_path, output_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Packets processed: 6", result.stdout)
        self.assertIn("Flows found: 3", result.stdout)
        with output_path.open(newline="", encoding="utf-8") as output_file:
            reader = csv.DictReader(output_file)
            self.assertEqual(reader.fieldnames, FLOW_COLUMNS + FEATURE_COLUMNS)
            rows = list(reader)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(FEATURE_COLUMNS), 16)
        self.assertEqual(rows[0]["total_fwd_bytes"], "112")
        for row in rows:
            for name in FEATURE_COLUMNS:
                self.assertTrue(math.isfinite(float(row[name])))

    def test_empty_pcap_produces_header_only_csv(self):
        empty_path = Path(self.directory.name) / "empty.pcap"
        # A valid Ethernet PCAP global header, with no packet records.
        empty_path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        output_path = Path(self.directory.name) / "empty.csv"
        result = self.run_cli(empty_path, output_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Flows found: 0", result.stdout)
        with output_path.open(newline="", encoding="utf-8") as output_file:
            reader = csv.DictReader(output_file)
            self.assertEqual(reader.fieldnames, FLOW_COLUMNS + FEATURE_COLUMNS)
            self.assertEqual(list(reader), [])

    def test_invalid_empty_and_missing_files_fail_cleanly(self):
        invalid_path = Path(self.directory.name) / "invalid.pcap"
        output_path = Path(self.directory.name) / "invalid.csv"
        for contents in (b"not a PCAP file", b""):
            with self.subTest(contents=contents):
                invalid_path.write_bytes(contents)
                result = self.run_cli(invalid_path, output_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Error:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(output_path.exists())
        result = self.run_cli(Path(self.directory.name) / "missing.pcap", output_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error:", result.stderr)
        self.assertFalse(output_path.exists())

    def test_input_cannot_be_overwritten_by_output(self):
        original = self.sample_path.read_bytes()
        result = self.run_cli(self.sample_path, self.sample_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sample_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
