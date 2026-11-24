"""Offline flow dashboard. Scoring is disabled unless explicitly supplied."""
import argparse
from collections import OrderedDict, deque
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
from queue import Queue
import re
import sqlite3
import sys
import threading
from time import monotonic, perf_counter
from urllib.parse import urlsplit

from scapy.error import Scapy_Exception
from threadpoolctl import threadpool_limits

from explain import build_alert_prompt, create_explainer, parse_alert_response
from nf_flow_extractor import FlowEngine, iter_pcap_flows, stream_live_flows
from risk_fusion import RiskFusionScorer, load_ciciot_bundle

try:
    import psutil
except ImportError:
    psutil = None

ROOT = Path(__file__).resolve().parent
EXPLANATION_LEVELS = {"high": 2, "medium": 1}
EXPLANATION_CACHE_SIZE = 512
DEFAULT_EXPLANATION_COOLDOWN = 30.0


def alert_details(flow):
    """Supply display fields for newly scored alerts and older saved rows."""
    flow = dict(ml_probability=None, risk_score=None, detector_ms=None,
                ai_explanation=None, recommended_action=None, explanation_timing=None) | flow
    # The existing "explanation" field summarizes detector signals.
    if flow.get("explanation_status") not in ("pending", "ready", "disabled", "skipped", "error"):
        flow["explanation_status"] = (
            "ready" if flow["ai_explanation"] or flow["recommended_action"] else "disabled"
        )
    return flow


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
    def __init__(self, db_path, scorer=None, scoring="Unscored", explainer=None,
                 explain_min_level="high", explanation_capacity=16,
                 explanation_cooldown=DEFAULT_EXPLANATION_COOLDOWN):
        if explain_min_level not in EXPLANATION_LEVELS or explanation_capacity < 1:
            raise ValueError("Expected a high or medium explain level and a positive queue capacity")
        if not math.isfinite(explanation_cooldown) or explanation_cooldown < 0:
            raise ValueError("Explanation cooldown must be finite and nonnegative")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.scorer, self.scoring = scorer, scoring
        self.lock = threading.Lock()
        self.traffic = deque(maxlen=50)
        self.engine = FlowEngine()
        self.status = "Ready"
        self.cpu = linux_cpu()
        self.last_cpu_percent = None
        self.explainer = explainer
        self.explain_min_level = EXPLANATION_LEVELS[explain_min_level]
        self.explanation_queue = Queue(maxsize=explanation_capacity)
        self.explanation_cooldown = explanation_cooldown
        self.pending_explanations = {}
        self.recent_explanations = OrderedDict()
        self.explanation_worker = None
        self.explainer_closed = False
        self.explainer_stats = dict(mode=explainer.mode if explainer is not None else "none", invocation_count=0,
                                    skipped_count=0, error_count=0, reused_count=0, last_latency_ms=None,
                                    avg_latency_ms=None)
        self.explanation_latency_sum = 0.0
        self.explanation_finished = 0
        with closing(sqlite3.connect(self.db_path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY, flow TEXT NOT NULL, feedback TEXT
                CHECK(feedback IN ('confirmed', 'dismissed')))""")
            if explainer is not None and explanation_cooldown:
                db.execute("""CREATE INDEX IF NOT EXISTS pending_explanation_source
                    ON alerts(json_extract(flow, '$.explanation_source_id'))
                    WHERE json_extract(flow, '$.explanation_status')='pending'""")
        if explainer is not None:
            self.explanation_worker = threading.Thread(target=self.explain_alerts, name="alert-explainer")
            self.explanation_worker.start()

    def accept(self, row):
        if isinstance(self.scorer, RiskFusionScorer):
            score = self.scorer(dict(row["features"]), dict(row["metadata"]))
        else:
            score = self.scorer(dict(row["features"])) if self.scorer else {"verdict": "Unscored"}
        flow = {**row, **score, "scoring": self.scoring}
        with self.lock:
            if score["verdict"] == "Flagged":
                flow = alert_details(flow)
                job = self.prepare_explanation(flow)
                with closing(sqlite3.connect(self.db_path)) as db, db:
                    alert_id = db.execute("INSERT INTO alerts(flow) VALUES (?)", (json.dumps(flow),)).lastrowid
                flow["id"] = alert_id
                if job is not None:
                    key = job[0]
                    if key is not None:
                        self.pending_explanations[key] = alert_id
                    self.explanation_queue.put_nowait((alert_id, *job))
                elif flow["explanation_status"] == "ready" and "explanation_source_id" in flow:
                    self.explainer_stats["reused_count"] += 1
            self.traffic.appendleft(flow)
        return flow

    def prepare_explanation(self, flow):
        """Reserve queue space under the dashboard lock before persisting the alert."""
        if self.explainer is None:
            return None
        level = EXPLANATION_LEVELS.get(str(flow.get("risk_level", "")).lower(), 0)
        reason = None
        if self.explainer_closed:
            reason = "shutdown"
        elif level < self.explain_min_level:
            reason = "below_threshold"
        if reason:
            flow.update(explanation_status="skipped", explanation_reason=reason)
            self.explainer_stats["skipped_count"] += 1
            return None
        key = None
        source = flow["metadata"].get("src_ip")
        if self.explanation_cooldown and source:
            key = (source, str(flow["risk_level"]).lower(), tuple(sorted(flow.get("signals", ()))))
            now = monotonic()
            while self.recent_explanations and next(iter(self.recent_explanations.values()))[0] <= now:
                self.recent_explanations.popitem(last=False)
            if key in self.recent_explanations:
                _, shared = self.recent_explanations[key]
                flow.update(shared)
                return None
            if key in self.pending_explanations:
                flow.update(explanation_status="pending", explanation_source_id=self.pending_explanations[key])
                return None
        if self.explanation_queue.full():
            flow.update(explanation_status="skipped", explanation_reason="queue_full")
            self.explainer_stats["skipped_count"] += 1
            return None
        try:
            job = build_alert_prompt(flow)
        except (KeyError, ValueError, TypeError, OverflowError):
            flow.update(explanation_status="error", explanation_reason="invalid_evidence")
            self.explainer_stats["error_count"] += 1
            return None
        flow["explanation_status"] = "pending"
        return key, *job

    def explain_alerts(self):
        while (job := self.explanation_queue.get()) is not None:
            alert_id, key, prompt, schema = job
            with self.lock:
                closing_worker = self.explainer_closed and not self.drain_explanations
                if closing_worker:
                    self.explainer_stats["skipped_count"] += 1
                else:
                    self.explainer_stats["invocation_count"] += 1
            if closing_worker:
                self.finish_explanation(alert_id, key, dict(explanation_status="skipped", explanation_reason="shutdown"))
                continue
            start = perf_counter()
            timing = dict(ttft_ms=None, tokens_per_sec=None)
            try:
                text, measurements = self.explainer.generate(prompt, schema)
                for metric in timing:
                    value = measurements.get(metric)
                    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                        timing[metric] = value
                result = parse_alert_response(text, schema)
                update = dict(explanation_status="ready", ai_explanation=result["explanation"],
                              recommended_action=result["recommended_action"])
            except Exception:
                # Isolate failures from the optional backend, including native bindings.
                update = dict(explanation_status="error", explanation_reason="generation_failed")
            timing["total_latency_ms"] = (perf_counter() - start) * 1000
            self.finish_explanation(alert_id, key, dict(update, explanation_timing=timing))

    def finish_explanation(self, alert_id, key, update):
        with self.lock:
            if key is not None:
                self.pending_explanations.pop(key, None)
            timing = update.get("explanation_timing")
            if timing is not None:
                latency = timing["total_latency_ms"]
                self.explanation_latency_sum += latency
                self.explanation_finished += 1
                self.explainer_stats.update(last_latency_ms=latency,
                                            avg_latency_ms=self.explanation_latency_sum / self.explanation_finished)
            if update["explanation_status"] == "error":
                self.explainer_stats["error_count"] += 1
            shared = {name: value for name, value in update.items() if name != "explanation_timing"}
            shared["explanation_source_id"] = alert_id
            followers = 0
            try:
                with closing(sqlite3.connect(self.db_path)) as db, db:
                    row = db.execute("SELECT flow FROM alerts WHERE id=?", (alert_id,)).fetchone()
                    if row:
                        db.execute("UPDATE alerts SET flow=? WHERE id=?",
                                   (json.dumps(json.loads(row[0]) | update), alert_id))
                    if key is not None:
                        followers = db.execute(
                            """UPDATE alerts SET flow=json_patch(flow, ?)
                               WHERE json_extract(flow, '$.explanation_status')='pending'
                               AND json_extract(flow, '$.explanation_source_id')=?""",
                            (json.dumps(shared), alert_id),
                        ).rowcount
            except (sqlite3.Error, ValueError) as exc:
                if update["explanation_status"] != "error":
                    self.explainer_stats["error_count"] += 1
                print(f"Could not save alert explanation: {exc}", file=sys.stderr)
                return
            if key is not None and update["explanation_status"] == "ready":
                self.recent_explanations[key] = (monotonic() + self.explanation_cooldown, shared)
                if len(self.recent_explanations) > EXPLANATION_CACHE_SIZE:
                    self.recent_explanations.popitem(last=False)
                self.explainer_stats["reused_count"] += followers
            for flow in self.traffic:
                if flow.get("id") == alert_id:
                    flow.update(update)
                elif flow.get("explanation_source_id") == alert_id:
                    flow.update(shared)

    def close(self, *, drain=False):
        """Stop the worker, optionally completing queued benchmark jobs."""
        with self.lock:
            if self.explanation_worker is None or self.explainer_closed:
                return
            self.explainer_closed = True
            self.drain_explanations = drain
        self.explanation_queue.put(None)
        self.explanation_worker.join()

    def recover_interrupted_explanations(self):
        """Mark jobs left by a previous, interrupted dashboard process."""
        with closing(sqlite3.connect(self.db_path)) as db, db:
            updated = db.execute(
                """UPDATE alerts SET flow=json_set(flow, '$.explanation_status', 'skipped',
                                                    '$.explanation_reason', 'interrupted')
                   WHERE json_extract(flow, '$.explanation_status')='pending'"""
            ).rowcount
        with self.lock:
            self.explainer_stats["skipped_count"] += updated

    def feedback(self, alert_id, value):
        if value not in ("confirmed", "dismissed"):
            raise ValueError("feedback must be confirmed or dismissed")
        with closing(sqlite3.connect(self.db_path)) as db, db:
            return bool(db.execute("UPDATE alerts SET feedback=? WHERE id=?", (value, alert_id)).rowcount)

    def snapshot(self):
        with self.lock, closing(sqlite3.connect(self.db_path)) as db:
            alerts = [dict(alert_details(json.loads(flow)), id=i, feedback=f) for i, flow, f in db.execute(
                "SELECT id, flow, feedback FROM alerts ORDER BY id DESC LIMIT 50")]
            device, current = device_metrics(self.cpu)
            if device["cpu_percent"] is None:
                device["cpu_percent"] = self.last_cpu_percent
            self.cpu, self.last_cpu_percent = current, device["cpu_percent"]
            return dict(offline=True, status=self.status, scoring=self.scoring, device=device,
                        counters=self.engine.counters(), alerts=alerts,
                        traffic=[dict(flow) for flow in self.traffic],
                        explainer=dict(self.explainer_stats))


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
    if isinstance(state.scorer, RiskFusionScorer) and state.scorer.bundle is not None:
        # One completed flow per prediction. Parallel OpenMP setup adds latency here.
        with threadpool_limits(limits=1, user_api="openmp"):
            return capture_flows(args, state, stop)
    return capture_flows(args, state, stop)


def capture_flows(args, state, stop):
    try:
        if args.interface:
            state.status = "Capturing"
            stream_live_flows(args.interface, state.accept, state.engine, stop)
        else:
            while not stop.is_set():
                state.engine = FlowEngine()
                if isinstance(state.scorer, RiskFusionScorer):
                    state.scorer.reset()
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
    scoring = parser.add_mutually_exclusive_group()
    scoring.add_argument("--demo-rules", action="store_true")
    scoring.add_argument("--model", help="Trusted CIC model bundle; enables ML and traffic rules")
    parser.add_argument("--alerts-db", default="artifacts/alerts.db", help="Local alert database")
    parser.add_argument("--explainer", choices=("none", "ollama", "executorch"), default="none")
    parser.add_argument("--explain-min-level", choices=tuple(EXPLANATION_LEVELS), default="high")
    parser.add_argument("--explain-cooldown", type=float, default=DEFAULT_EXPLANATION_COOLDOWN,
                        help="Seconds to reuse a matching explanation after completion (0 disables reuse)")
    parser.add_argument("--llama-model", help="Local ExecuTorch .pte model")
    parser.add_argument("--llama-tokenizer", help="Local tokenizer matching the ExecuTorch model")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Local Ollama server URL")
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval < 0 or (args.loop and args.interface):
        parser.error("Use a finite nonnegative interval and --loop only with replay")
    if not math.isfinite(args.explain_cooldown) or args.explain_cooldown < 0:
        parser.error("Use a finite nonnegative explanation cooldown")
    scorer = demo_score if args.demo_rules else None
    mode = "Demo rules" if args.demo_rules else "Unscored"
    if args.model:
        try:
            scorer = RiskFusionScorer(load_ciciot_bundle(args.model))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        mode = "CIC model + traffic rules"
    try:
        explainer = create_explainer(args.explainer, args.llama_model, args.llama_tokenizer, args.ollama_url)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    state = Dashboard(args.alerts_db, scorer, mode, explainer, args.explain_min_level,
                      explanation_cooldown=args.explain_cooldown)
    stop = threading.Event()
    try:
        with make_server(args.host, args.port, state) as server:
            state.recover_interrupted_explanations()
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
    finally:
        state.close()
    return int(state.status.startswith("Capture failed"))


if __name__ == "__main__":
    sys.exit(main())
