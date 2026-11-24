"""Measure the local CIC detector and optional explainer on PCAP or live input."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import threading
from time import perf_counter

import numpy as np
import psutil
from scapy.error import Scapy_Exception
from threadpoolctl import threadpool_limits

from dashboard import Dashboard, DEFAULT_EXPLANATION_COOLDOWN
from explain import create_explainer
from nf_flow_extractor import FlowEngine, iter_pcap_flows, stream_live_flows
from risk_fusion import RiskFusionScorer, load_ciciot_bundle


SAMPLE_LIMIT = 8192
HEALTH_INTERVAL = 0.25


class Measurements:
    """Keep exact counts and maxima, and bound the memory used for percentiles."""

    def __init__(self):
        self.values = []
        self.count = 0
        self.maximum = None
        self.random = random.Random(42)

    def add(self, value):
        if value is None:
            return
        self.count += 1
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        index = self.count - 1 if self.count <= SAMPLE_LIMIT else self.random.randrange(self.count)
        if index == len(self.values) and index < SAMPLE_LIMIT:
            self.values.append(value)
        elif index < SAMPLE_LIMIT:
            self.values[index] = value

    def summary(self):
        p50, p95 = map(float, np.percentile(self.values, [50, 95])) if self.values else (None, None)
        return dict(p50=p50, p95=p95, max=self.maximum, count=self.count, sampled=len(self.values))


class ExtractionTiming:
    def __init__(self):
        self.elapsed_ms = 0.0

    def rows(self, iterator):
        # Charge iterator work between outputs to the next flow, excluding consumer time.
        while True:
            start = perf_counter()
            row = next(iterator, None)
            self.elapsed_ms += (perf_counter() - start) * 1000
            if row is None:
                break
            yield row

    def take(self):
        elapsed = self.elapsed_ms
        self.elapsed_ms = 0.0
        return elapsed


def temperature_c():
    if platform.system() == "Linux":
        try:
            return int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000
        except (OSError, ValueError):
            pass
    return None


def throttling():
    program = shutil.which("vcgencmd") if platform.system() == "Linux" else None
    if not program:
        return None
    try:
        output = subprocess.check_output([program, "get_throttled"], timeout=3, text=True)
        return output.strip() if output.startswith("throttled=") else None
    except (OSError, subprocess.SubprocessError):
        return None


class Health:
    def __init__(self):
        self.process = psutil.Process()
        self.start_process_cpu = self.process_cpu()
        psutil.cpu_percent()
        self.start_ram = self.ram_mb()
        self.peak_ram = self.start_ram
        self.start_temperature = temperature_c()
        self.peak_temperature = self.start_temperature
        self.cpu_total = 0.0
        self.cpu_samples = 0
        self.peak_cpu = None
        self.start_throttling = throttling()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.sample, name="benchmark-health")

    def ram_mb(self):
        return self.process.memory_info().rss / 1_000_000

    def process_cpu(self):
        times = self.process.cpu_times()
        return times.user + times.system

    def sample(self):
        psutil.cpu_percent()
        while not self.stop.wait(HEALTH_INTERVAL):
            self.peak_ram = max(self.peak_ram, self.ram_mb())
            temp = temperature_c()
            if temp is not None:
                self.peak_temperature = temp if self.peak_temperature is None else max(self.peak_temperature, temp)
            cpu = psutil.cpu_percent()
            self.cpu_total += cpu
            self.cpu_samples += 1
            self.peak_cpu = cpu if self.peak_cpu is None else max(self.peak_cpu, cpu)

    def finish(self, elapsed):
        self.stop.set()
        self.thread.join()
        end_ram = self.ram_mb()
        end_temperature = temperature_c()
        temps = [value for value in (self.peak_temperature, end_temperature) if value is not None]
        cpu_avg, cpu_peak = self.cpu_total / self.cpu_samples if self.cpu_samples else None, self.peak_cpu
        if not self.cpu_samples:
            cpu_avg = cpu_peak = psutil.cpu_percent()
        return dict(start_ram_mb=self.start_ram, peak_ram_mb=max(self.peak_ram, end_ram), end_ram_mb=end_ram,
                    ram_delta_mb=end_ram - self.start_ram, cpu_avg_percent=cpu_avg,
                    cpu_peak_percent=cpu_peak, cpu_samples=self.cpu_samples or 1,
                    process_cpu_percent=100 * (self.process_cpu() - self.start_process_cpu) / elapsed,
                    start_temperature_c=self.start_temperature, peak_temperature_c=max(temps, default=None),
                    end_temperature_c=end_temperature, start_throttling=self.start_throttling,
                    end_throttling=throttling())


def cpu_model():
    for path in ("/proc/device-tree/model", "/proc/cpuinfo"):
        try:
            content = Path(path).read_text(encoding="utf-8").strip("\0\n ")
        except OSError:
            continue
        if path.endswith("/model"):
            return content
        for line in content.splitlines():
            name, _, value = line.partition(":")
            if name.strip().lower() in ("model name", "hardware") and value.strip():
                return value.strip()
    return platform.processor() or platform.machine()


def package_version(name):
    try:
        return version(name)
    except PackageNotFoundError:
        return "not installed"


def artifact_info(path):
    if not path:
        return None
    return dict(path=str(path), size_mb=Path(path).stat().st_size / 1_000_000)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def replay(state, path, stop, repeat, timing, on_flow):
    totals = dict(packets_seen=0, packets_skipped=0, packets_dropped=None, flows_emitted=0, passes=0)
    while not stop.is_set():
        state.engine = FlowEngine()
        state.scorer.reset()
        status = {}
        for row in timing.rows(iter_pcap_flows(path, state.engine, stop, stats=status)):
            on_flow(row)
        counts = state.engine.counters()
        for key in ("packets_seen", "packets_skipped", "flows_emitted"):
            totals[key] += counts[key]
        totals["passes"] += 1
        if not repeat or status.get("reason") == "interrupt":
            break
        if not counts["packets_seen"]:
            raise ValueError("Cannot repeat an empty capture for a sustained benchmark")
    return totals


def explanation_measurements(db_path):
    metrics = {name: Measurements() for name in ("ttft_ms", "tokens_per_sec", "total_latency_ms")}
    with closing(sqlite3.connect(db_path)) as db:
        for (raw,) in db.execute("""SELECT json_extract(flow, '$.explanation_timing') FROM alerts
                                  WHERE json_type(flow, '$.explanation_timing') = 'object'"""):
            timing = json.loads(raw)
            for name, samples in metrics.items():
                samples.add(timing.get(name))
    return {name: samples.summary() for name, samples in metrics.items()}


def benchmark(args):
    environment = dict(os=platform.platform(), architecture=platform.machine(), cpu_model=cpu_model(),
                       logical_cores=os.cpu_count(), physical_cores=psutil.cpu_count(logical=False),
                       python=platform.python_version(), scikit_learn=package_version("scikit-learn"),
                       executorch=package_version("executorch"))
    artifacts = dict(detector=artifact_info(args.model), llama_model=artifact_info(args.llama_model),
                     llama_tokenizer=artifact_info(args.llama_tokenizer))
    run = dict(utc=datetime.now(timezone.utc).isoformat(), pcap=str(args.pcap) if args.pcap else None,
               pcap_sha256=sha256(args.pcap) if args.pcap else None, interface=args.interface,
               requested_duration_sec=args.duration_sec, explain_min_level=args.explain_min_level,
               explanation_cooldown_sec=args.explain_cooldown, detector_threads=1)
    scorer = RiskFusionScorer(load_ciciot_bundle(args.model))
    explainer = create_explainer(args.explainer, args.llama_model, args.llama_tokenizer, args.ollama_url)
    extraction = ExtractionTiming()
    samples = {name: Measurements() for name in ("extraction_ms", "detector_ms", "combined_ms", "emit_delay_ms")}
    alert_count = 0
    stop = threading.Event()
    timer = threading.Timer(args.duration_sec, stop.set) if args.duration_sec is not None else None
    with TemporaryDirectory() as work, threadpool_limits(limits=1, user_api="openmp"):
        health = Health()
        state = Dashboard(Path(work) / "alerts.db", scorer, "CIC model + traffic rules", explainer,
                          args.explain_min_level, explanation_cooldown=args.explain_cooldown)

        def accept(row):
            nonlocal alert_count
            extract_ms = extraction.take()
            flow = state.accept(row)
            detector_ms = flow["detector_ms"]
            samples["extraction_ms"].add(extract_ms)
            samples["detector_ms"].add(detector_ms)
            samples["combined_ms"].add(extract_ms + detector_ms)
            samples["emit_delay_ms"].add(flow["metadata"]["emit_delay_ms"])
            alert_count += flow["verdict"] == "Flagged"

        health.thread.start()
        start = perf_counter()
        if timer:
            timer.start()
        try:
            if args.pcap:
                counts = replay(state, args.pcap, stop, timer is not None, extraction, accept)
            else:
                stream_live_flows(args.interface, accept, state.engine, stop, measure=extraction.rows)
                counts = state.engine.counters()
        finally:
            capture_end = perf_counter()
            if timer:
                timer.cancel()
                timer.join()
            state.close(drain=True)
            end = perf_counter()
            system = health.finish(end - start)
        slow = dict(state.explainer_stats)
        slow.update(explanation_measurements(state.db_path))

    elapsed = capture_end - start
    flows = counts["flows_emitted"]
    run.update(capture_elapsed_sec=elapsed, explanation_drain_sec=end - capture_end)
    fast = dict(total_packets=counts["packets_seen"], total_flows=flows, alert_count=alert_count,
                packet_drop_count=counts["packets_dropped"], packets_skipped=counts["packets_skipped"],
                packets_per_sec=counts["packets_seen"] / elapsed, flows_per_sec=flows / elapsed,
                replay_passes=counts.get("passes"))
    fast.update({name: measurements.summary() for name, measurements in samples.items()})
    slow["invocation_rate_percent"] = slow["invocation_count"] * 100 / flows if flows else None
    return dict(schema_version=1, run=run, environment=environment, artifacts=artifacts, detector=fast,
                explainer=slow, system_health=system)


def markdown(report):
    def entries(values, prefix=""):
        for key, value in values.items():
            label = prefix + key.replace("_", " ")
            if isinstance(value, dict):
                yield from entries(value, label + " / ")
            else:
                yield label, value

    lines = ["# Edge-Sec Guardian benchmark", "",
             "Throughput uses capture wall time, including alert persistence. Extraction latency measures "
             "iterator work per emitted flow, excluding idle wait. Combined latency sums extraction and "
             "detector work. Emit delay uses capture timestamps. Explanation drain is timed separately.", "",
             "RAM is dashboard process RSS, including queued work during drain. CPU averages and peaks are "
             "system-wide. Process CPU percent uses one core as 100%. "
             "Peak health values are sampled every 250 ms. An RSS delta is a stability indicator. "
             "Compare sustained runs to assess growth. Latency percentiles use at most 8,192 sampled "
             "observations per metric. Unavailable readings are reported explicitly.", ""]
    for section, values in report.items():
        if not isinstance(values, dict):
            continue
        lines.extend([f"## {section.replace('_', ' ').title()}", "", "| Metric | Value |", "|---|---|"])
        for label, value in entries(values):
            display = "Unavailable" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)
            display = display.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {label} | {display} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path, help="Capture file for unpaced replay")
    source.add_argument("--interface", help="Authorized live capture interface")
    parser.add_argument("--duration-sec", type=float, help="Live duration or time budget for repeated PCAP replay")
    parser.add_argument("--model", type=Path, default=Path("artifacts/ciciot_model.pkl"), help="Trusted detector bundle")
    parser.add_argument("--explainer", choices=("none", "ollama", "executorch"), default="none")
    parser.add_argument("--llama-model", type=Path)
    parser.add_argument("--llama-tokenizer", type=Path)
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--explain-min-level", choices=("high", "medium"), default="high")
    parser.add_argument("--explain-cooldown", type=float, default=DEFAULT_EXPLANATION_COOLDOWN)
    parser.add_argument("--output-json", type=Path, default=Path("artifacts/benchmark.json"))
    parser.add_argument("--output-md", type=Path, default=Path("artifacts/benchmark.md"))
    args = parser.parse_args(argv)
    if args.duration_sec is not None and (not math.isfinite(args.duration_sec) or args.duration_sec <= 0):
        parser.error("--duration-sec must be finite and positive")
    if args.interface and args.duration_sec is None:
        parser.error("--interface requires --duration-sec")
    if not math.isfinite(args.explain_cooldown) or args.explain_cooldown < 0:
        parser.error("--explain-cooldown must be finite and nonnegative")
    outputs = {args.output_json.resolve(), args.output_md.resolve()}
    inputs = {path.resolve() for path in (args.pcap, args.model, args.llama_model, args.llama_tokenizer) if path}
    if len(outputs) != 2 or outputs & inputs:
        parser.error("Report output paths must be distinct from each other and the input files")
    try:
        report = benchmark(args)
        for path, body in (
            (args.output_json, json.dumps(report, indent=2, allow_nan=False) + "\n"),
            (args.output_md, markdown(report)),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
    except (OSError, ValueError, RuntimeError, sqlite3.Error, Scapy_Exception) as exc:
        parser.exit(1, f"Benchmark failed: {exc}\n")
    print(f"Wrote {args.output_json} and {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
