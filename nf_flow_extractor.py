"""Bidirectional IPv4 flow extraction for capture files and local interfaces."""
import argparse
import csv
import json
import math
import statistics
import socket
import struct
import sys
import time
from collections import OrderedDict
from pathlib import Path

from scapy.all import IP, TCP, UDP, PcapReader, conf, sniff
from scapy.error import Scapy_Exception

DIRECTIONS = ("SRC_TO_DST", "DST_TO_SRC")
FEATURE_COLUMNS = ["IN_PKTS", "OUT_PKTS", "IN_BYTES", "OUT_BYTES", "FLOW_DURATION_MILLISECONDS"]
FEATURE_COLUMNS += [f"{direction}_IAT_{stat}" for direction in DIRECTIONS
                    for stat in ("MIN", "MAX", "AVG", "STDDEV")]
META_COLUMNS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "flow_start_ts", "flow_end_ts", "emit_reason", "emit_delay_ms"]


class Direction:
    """Merge batches of 64 gaps to keep exact-count population moments in bounded space."""
    def __init__(self):
        self.packets = self.size = self.count = 0
        self.last = None
        self.low, self.high = math.inf, -math.inf
        self.mean = self.m2 = 0.0
        self.batch = []

    def merge(self):
        gaps = self.batch
        if gaps:
            n = len(gaps)
            delta = statistics.mean(gaps) - self.mean
            total = self.count + n
            self.m2 += n * statistics.pstdev(gaps)**2 + delta**2 * self.count * n / total
            self.mean += delta * n / total
            self.count = total
            gaps.clear()

    def add(self, timestamp, size):
        if self.last is not None:
            gap = (timestamp - self.last) * 1000
            self.low, self.high = min(self.low, gap), max(self.high, gap)
            self.batch.append(gap)
            if len(self.batch) == 64:
                self.merge()
        self.last = timestamp
        self.packets += 1
        self.size += size

    def summary(self):
        self.merge()
        if not self.count:
            return [0.0] * 4
        return [self.low, self.high, self.mean, math.sqrt(self.m2 / self.count)]


class FlowEngine:
    """Single-writer engine. Creation and activity order make expiry cheap per packet."""
    def __init__(self, idle_timeout=15, active_timeout=60, max_open_flows=2000):
        if not all(math.isfinite(t) and t > 0 for t in (idle_timeout, active_timeout)):
            raise ValueError("timeouts must be finite and positive")
        if max_open_flows < 1:
            raise ValueError("max-open-flows must be positive")
        self.idle_timeout, self.active_timeout = idle_timeout, active_timeout
        self.cap = max_open_flows
        self.flows = {}
        self.activity = OrderedDict()
        self.seen = self.skipped = self.emitted = 0
        self.total_delay = self.clock = 0.0
        self.started = time.monotonic()
        self.finished = None
        self.dropped = None

    def counters(self):
        elapsed = (self.finished or time.monotonic()) - self.started
        return dict(packets_seen=self.seen, packets_skipped=self.skipped,
                    packets_dropped=self.dropped, flows_emitted=self.emitted,
                    open_flows=len(self.flows), packets_per_sec=round(self.seen / max(elapsed, 1e-6), 2),
                    avg_emit_delay_ms=round(self.total_delay / max(1, self.emitted), 3))

    def emit(self, key, reason):
        first, start, directions = self.flows.pop(key)
        end = self.activity.pop(key)
        forward, reverse = directions
        delay = round((self.clock - end) * 1000, 3)
        self.total_delay += delay
        self.emitted += 1
        values = [forward.packets, reverse.packets, forward.size, reverse.size,
                  (end - start) * 1000, *forward.summary(), *reverse.summary()]
        meta = [*first, start, end, reason, delay]
        return {"metadata": dict(zip(META_COLUMNS, meta)),
                "features": dict(zip(FEATURE_COLUMNS, (round(v, 3) for v in values)))}

    def expire(self, timestamp):
        self.clock = max(self.clock, timestamp)
        while self.flows:
            oldest = next(iter(self.flows))
            idle = next(iter(self.activity))
            active_at = self.flows[oldest][1] + self.active_timeout
            idle_at = self.activity[idle] + self.idle_timeout
            if self.clock < min(active_at, idle_at):
                break
            yield self.emit(oldest, "active_timeout") if active_at <= idle_at else self.emit(idle, "idle_timeout")

    def feed(self, packet):
        self.seen += 1
        yield from self.expire(float(packet.time))
        ip = packet.getlayer(IP)
        if ip is None or ip.frag or ip.flags.MF or not isinstance(ip.payload, (TCP, UDP)):
            self.skipped += 1
            return
        transport = ip.payload
        tcp = isinstance(transport, TCP)
        src, dst = (ip.src, transport.sport), (ip.dst, transport.dport)
        proto = "TCP" if tcp else "UDP"
        key = (*sorted((src, dst)), proto)
        endpoints = (src[0], dst[0], src[1], dst[1], proto)
        if key not in self.flows:
            if len(self.flows) == self.cap:
                yield self.emit(next(iter(self.flows)), "capacity")
            self.flows[key] = (endpoints, self.clock, (Direction(), Direction()))
        first, _, directions = self.flows[key]
        directions[int(first != endpoints)].add(self.clock, int(ip.len) if ip.len is not None else len(ip))
        self.activity[key] = self.clock
        self.activity.move_to_end(key)
        if tcp and int(transport.flags) & 5:
            yield self.emit(key, "rst" if int(transport.flags) & 4 else "fin")

    def flush(self, reason):
        while self.flows:
            yield self.emit(next(iter(self.flows)), reason)
        self.finished = time.monotonic()


def iter_pcap_flows(path, engine=None, stop=None):
    engine = engine or FlowEngine()
    reason = "eof"
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if stop is not None and stop.is_set():
                    reason = "interrupt"
                    break
                yield from engine.feed(packet)
    except KeyboardInterrupt:
        reason = "interrupt"
    yield from engine.flush(reason)


def stream_live_flows(interface, on_flow, engine=None, stop=None):
    engine = engine or FlowEngine()

    def deliver(rows):
        for row in rows:
            on_flow(row)

    sock = conf.L2listen(iface=interface)
    try:
        while stop is None or not stop.is_set():
            sniff(opened_socket=sock, store=False, timeout=0.5, chainCC=True,
                  prn=lambda packet: deliver(engine.feed(packet)))
            if sock.closed:
                raise OSError("Capture socket closed during sniffing")
            # Linux AF_PACKET returns (received, dropped) since the last read.
            raw = getattr(sock, "ins", None)
            if sys.platform.startswith("linux") and getattr(raw, "family", None) == socket.AF_PACKET:
                try:
                    stats = raw.getsockopt(263, 6, 8)  # SOL_PACKET, PACKET_STATISTICS
                except OSError:
                    engine.dropped = None
                else:
                    engine.dropped = (engine.dropped or 0) + struct.unpack("=II", stats)[1]
            deliver(engine.expire(time.time()))
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        deliver(engine.flush("interrupt"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap")
    group.add_argument("--interface")
    parser.add_argument("--output", help="CSV destination (stdout by default)")
    parser.add_argument("--idle-timeout", type=float, default=15)
    parser.add_argument("--active-timeout", type=float, default=60)
    parser.add_argument("--max-open-flows", type=int, default=2000)
    args = parser.parse_args()
    try:
        engine = FlowEngine(args.idle_timeout, args.active_timeout, args.max_open_flows)
        if args.pcap and args.output and Path(args.output).exists() and Path(args.pcap).samefile(args.output):
            raise ValueError("CSV output must differ from PCAP input")
        output = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        try:
            writer = csv.DictWriter(output, fieldnames=META_COLUMNS + FEATURE_COLUMNS)
            writer.writeheader()

            def write(row):
                writer.writerow({**row["metadata"], **row["features"]})

            if args.pcap:
                for row in iter_pcap_flows(args.pcap, engine):
                    write(row)
            else:
                stream_live_flows(args.interface, write, engine)
        finally:
            if args.output:
                output.close()
        print(json.dumps(engine.counters()), file=sys.stderr)
        return 0
    except (OSError, ValueError, RuntimeError, Scapy_Exception) as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
