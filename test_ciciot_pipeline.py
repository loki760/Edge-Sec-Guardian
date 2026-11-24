"""Synthetic offline integration fixtures. No packets are sent on a network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.request import urlopen

from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap

from dashboard import Dashboard, make_server
from nf_flow_extractor import iter_pcap_flows
from risk_fusion import RiskFusionScorer, load_ciciot_bundle, validate_bundle


ROOT = Path(__file__).resolve().parent
FAMILIES = ["BenignTraffic", "DDoS-SYN_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood", "Recon-PortScan"]


def write_capture(path, family, index):
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    for flow in range(12):
        count = 12 if "Flood" in family else 2 if family == "BenignTraffic" else 1
        for seq in range(count):
            src, dst = "192.0.2.1", f"198.51.100.{flow + 1}"
            sport, dport = 40000 + index, 2000 + flow
            if family == "BenignTraffic" and seq == 1:
                src, dst, sport, dport = dst, src, dport, sport
            if "ICMP" in family:
                segment = ICMP()
            elif "UDP" in family:
                segment = UDP(sport=sport, dport=dport)
            else:
                flags = ("FA" if seq else "S") if family == "BenignTraffic" else "S"
                segment = TCP(sport=sport, dport=dport, flags=flags)
            packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / segment
            packet.time = 100 + index * 100 + flow * 0.4 + seq * (0.02 if family == "BenignTraffic" else 0.0001)
            packets.append(packet)
    wrpcap(str(path), packets)


class PipelineTests(unittest.TestCase):
    def test_offline_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for family in FAMILIES:
                for i in range(3):
                    write_capture(work / "raw" / family / f"part{i}.pcap", family, i)

            def run(script, *args):
                env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MPLBACKEND="Agg")
                result = subprocess.run([sys.executable, str(ROOT / script), *args], cwd=work,
                                        capture_output=True, text=True, env=env, timeout=240)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            run("build_ciciot_dataset.py", "--pcap-dir", "raw", "--output", "flows.csv")
            run("eda_ciciot.py", "--input", "flows.csv", "--report", "eda.md", "--plot-dir", "plots")
            run("select_ciciot_features.py", "--input", "flows.csv", "--output", "selected.json",
                "--report", "selection.md")
            run("train_ciciot_model.py", "--input", "flows.csv", "--features", "selected.json",
                "--model", "model.pkl", "--metrics", "metrics.json", "--report", "models.md")
            bundle = load_ciciot_bundle(work / "model.pkl")
            for key, bad in [("schema_version", 2), ("high_threshold", 1), ("med_threshold", -1),
                             ("feature_columns", ["src_ip"])]:
                with self.subTest(field=key), self.assertRaises(ValueError):
                    validate_bundle(dict(bundle, **{key: bad}))
            scorer = RiskFusionScorer(bundle)
            state = Dashboard(work / "alerts.db", scorer, "CIC model + traffic rules")
            for row in iter_pcap_flows(work / "raw" / FAMILIES[1] / "part0.pcap"):
                state.accept(row)
            with make_server("127.0.0.1", 0, state) as server:
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    with urlopen(f"http://127.0.0.1:{server.server_port}/api/state", timeout=10) as response:
                        snapshot = json.load(response)
                finally:
                    server.shutdown()
                    thread.join()
            self.assertEqual(len(snapshot["traffic"]), 12)
            for flow in snapshot["traffic"]:
                self.assertEqual(flow["verdict"], "Flagged")
                self.assertEqual(flow["prediction"], 1)
                self.assertTrue(0 <= flow["ml_probability"] <= 1)
                self.assertEqual(flow["risk_level"], "High")
                self.assertIn("Rule: SYN-heavy TCP flow", flow["signals"])
                self.assertGreaterEqual(flow["detector_ms"], 0)
            self.assertEqual(len(snapshot["alerts"]), 12)


if __name__ == "__main__":
    unittest.main()
