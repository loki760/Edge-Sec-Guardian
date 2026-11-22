"""Offline flow dashboard. Scoring is disabled unless explicitly supplied."""
import argparse
from collections import deque
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
import threading
from urllib.parse import urlsplit

from scapy.error import Scapy_Exception

from nf_flow_extractor import FlowEngine, iter_pcap_flows, stream_live_flows

try:
    import psutil
except ImportError:
    psutil = None

ROOT = Path(__file__).resolve().parent


def demo_score(features):
    signals = []
    if features["IN_PKTS"] >= 3:
        signals.append("At least 3 forward packets")
    if features["IN_BYTES"] >= 100:
        signals.append("At least 100 forward IP bytes")
    return dict(verdict="Flagged" if signals else "Clear", severity="Medium" if signals else "",
                signals=signals, explanation="Demo thresholds matched: " + ", ".join(signals) if signals else "")


def linux_cpu():
    try:
        times = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))
        return sum(times), times[3] + times[4]
    except (OSError, IndexError, ValueError):
        return None


def device_metrics(previous):
    cpu = ram = percent = temp = None
    current = linux_cpu()
    if current and previous and current[0] > previous[0]:
        cpu = round(100 * (1 - (current[1] - previous[1]) / (current[0] - previous[0])), 1)
    try:
        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            name, value = line.split(":", 1)
            memory[name] = int(value.split()[0])
        used = memory["MemTotal"] - memory["MemAvailable"]
        ram, percent = round(used / 1024, 1), round(100 * used / memory["MemTotal"], 1)
    except (OSError, KeyError, ValueError):
        if psutil:
            vm = psutil.virtual_memory()
            ram, percent = round((vm.total - vm.available) / 2**20, 1), vm.percent
    try:
        temp = float(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000
    except (ValueError, OSError):
        pass
    if not current and psutil:
        # HTTP requests use different threads, so sample both endpoints in this call.
        cpu = psutil.cpu_percent(interval=0.05)
    return dict(cpu_percent=cpu, ram_mb=ram, ram_percent=percent, temperature_c=temp), current


class Dashboard:
    def __init__(self, db_path, scorer=None, scoring="Unscored"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.scorer, self.scoring = scorer, scoring
        self.lock = threading.Lock()
        self.traffic = deque(maxlen=50)
        self.engine = FlowEngine()
        self.status = "Ready"
        self.cpu = linux_cpu()
        self.last_cpu_percent = None
        with closing(sqlite3.connect(self.db_path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY, flow TEXT NOT NULL, feedback TEXT
                CHECK(feedback IN ('confirmed', 'dismissed')))""")

    def accept(self, row):
        score = self.scorer(dict(row["features"])) if self.scorer else {"verdict": "Unscored"}
        flow = {**row, **score, "scoring": self.scoring}
        with self.lock:
            if score["verdict"] == "Flagged":
                with closing(sqlite3.connect(self.db_path)) as db, db:
                    db.execute("INSERT INTO alerts(flow) VALUES (?)", (json.dumps(flow),))
            self.traffic.appendleft(flow)

    def feedback(self, alert_id, value):
        if value not in ("confirmed", "dismissed"):
            raise ValueError("feedback must be confirmed or dismissed")
        with closing(sqlite3.connect(self.db_path)) as db, db:
            return bool(db.execute("UPDATE alerts SET feedback=? WHERE id=?", (value, alert_id)).rowcount)

    def snapshot(self):
        with self.lock, closing(sqlite3.connect(self.db_path)) as db:
            alerts = [dict(**json.loads(flow), id=i, feedback=f) for i, flow, f in db.execute(
                "SELECT id, flow, feedback FROM alerts ORDER BY id DESC LIMIT 50")]
            device, current = device_metrics(self.cpu)
            if device["cpu_percent"] is None:
                device["cpu_percent"] = self.last_cpu_percent
            self.cpu, self.last_cpu_percent = current, device["cpu_percent"]
            return dict(offline=True, status=self.status, scoring=self.scoring, device=device,
                        counters=self.engine.counters(), alerts=alerts, traffic=list(self.traffic))


def make_server(host, port, state):
    page = (ROOT / "static/index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, data, mime="application/json"):
            body = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/":
                self.reply(200, page, "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self.reply(200, state.snapshot())
            else:
                self.reply(404, {"error": "Unknown path"})

        def do_POST(self):
            match = re.fullmatch(r"/api/alerts/([1-9][0-9]{0,18})/feedback", self.path)
            if not match or int(match[1]) > 2**63 - 1:
                return self.reply(404, {"error": "Unknown alert"})
            origin = self.headers.get("Origin")
            if origin and urlsplit(origin).netloc != self.headers.get("Host"):
                return self.reply(403, {"error": "Cross-origin feedback"})
            if self.headers.get_content_type() != "application/json":
                return self.reply(415, {"error": "Use application/json"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024:
                    raise ValueError("Invalid request length")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Expected JSON object")
                found = state.feedback(int(match[1]), payload.get("feedback"))
            except (UnicodeError, ValueError) as exc:
                return self.reply(400, {"error": str(exc)})
            if found:
                self.reply(200, {"feedback": payload["feedback"]})
            else:
                self.reply(404, {"error": "Unknown alert"})

    return ThreadingHTTPServer((host, port), Handler)


def capture(args, state, stop):
    try:
        if args.interface:
            state.status = "Capturing"
            stream_live_flows(args.interface, state.accept, state.engine, stop)
        else:
            while not stop.is_set():
                state.engine = FlowEngine()
                state.status = "Replaying"
                for flow in iter_pcap_flows(args.replay_pcap, state.engine, stop):
                    state.accept(flow)
                    stop.wait(args.interval)
                if not args.loop or stop.wait(max(0.05, args.interval)):
                    break
            state.status = "Replay complete"
    except (OSError, ValueError, RuntimeError, sqlite3.Error, Scapy_Exception) as exc:
        state.status = f"Capture failed: {exc}"
        print(state.status, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--replay-pcap")
    group.add_argument("--interface")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between replayed rows")
    parser.add_argument("--loop", action="store_true", help="Repeat PCAP replay")
    parser.add_argument("--demo-rules", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval < 0 or (args.loop and args.interface):
        parser.error("Use a finite nonnegative interval and --loop only with replay")
    state = Dashboard(ROOT / "artifacts/alerts.db", demo_score if args.demo_rules else None,
                      "Demo rules" if args.demo_rules else "Unscored")
    stop = threading.Event()
    with make_server(args.host, args.port, state) as server:
        worker = threading.Thread(target=capture, args=(args, state, stop))
        worker.start()
        try:
            print(f"Listening on {args.host}:{server.server_port}", flush=True)
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            worker.join()
    return int(state.status.startswith("Capture failed"))


if __name__ == "__main__":
    sys.exit(main())
