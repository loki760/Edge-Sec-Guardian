"""Bidirectional IPv4 flow extraction for capture files and local interfaces."""
import argparse
import csv
import json
import math
import socket
import struct
import sys
import time
from collections import OrderedDict
from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP, UDP, PcapReader, RawPcapReader, conf, sniff
from scapy.error import Scapy_Exception

DIRECTIONS = ("SRC_TO_DST", "DST_TO_SRC")
MODEL_FEATURE_COLUMNS = [
    "PROTOCOL_NUM", "IN_PKTS", "OUT_PKTS", "IN_BYTES", "OUT_BYTES",
    "FLOW_DURATION_MILLISECONDS", "PKTS_PER_SEC", "BYTES_PER_SEC",
    "IN_OUT_PKT_RATIO", "IN_OUT_BYTE_RATIO", "PKT_LEN_MIN", "PKT_LEN_MAX",
    "PKT_LEN_MEAN", "PKT_LEN_STD", "TTL_MEAN", "SYN_RATIO", "ACK_RATIO",
    "FIN_RATIO", "RST_RATIO", "PSH_RATIO", "URG_RATIO",
]
MODEL_FEATURE_COLUMNS += [f"{direction}_IAT_{stat}" for direction in DIRECTIONS
                          for stat in ("MIN", "MAX", "AVG", "STDDEV")]
FEATURE_COLUMNS = MODEL_FEATURE_COLUMNS
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
FLAG_BITS = (2, 16, 1, 4, 8, 32)
META_COLUMNS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "flow_start_ts", "flow_end_ts", "emit_reason", "emit_delay_ms"]


class Moments:
    """Online population variance, without storing individual observations."""
    def __init__(self):
        self.count = 0
        self.low, self.high = math.inf, -math.inf
        self.mean = self.m2 = 0.0

    def add(self, value):
        self.count += 1
        self.low = min(self.low, value)
        self.high = max(self.high, value)
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    def summary(self):
        if not self.count:
            return [0.0] * 4
        return [self.low, self.high, self.mean, math.sqrt(self.m2 / self.count)]


class Direction:
    def __init__(self):
        self.packets = self.size = 0
        self.last = None
        self.gaps = Moments()

    def add(self, timestamp, size):
        if self.last is not None:
            self.gaps.add((timestamp - self.last) * 1000)
        self.last = timestamp
        self.packets += 1
        self.size += size


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
        first, start, directions, lengths, totals = self.flows.pop(key)
        end = self.activity.pop(key)
        forward, reverse = directions
        delay = round((self.clock - end) * 1000, 3)
        self.total_delay += delay
        self.emitted += 1
        duration = end - start
        count = lengths.count
        size = forward.size + reverse.size
        values = [key[-1], forward.packets, reverse.packets, forward.size, reverse.size,
                  duration * 1000, count / duration if duration else 0.0,
                  size / duration if duration else 0.0,
                  forward.packets / (reverse.packets + 1), forward.size / (reverse.size + 1),
                  *lengths.summary(), *(total / count for total in totals),
                  *forward.gaps.summary(), *reverse.gaps.summary()]
        meta = [*first, start, end, reason, delay]
        return {"metadata": dict(zip(META_COLUMNS, meta)),
                "features": dict(zip(MODEL_FEATURE_COLUMNS, values))}

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
        if isinstance(packet, Ether):
            yield from self.feed_fields(float(packet.time), ethernet_fields(bytes(packet)))
            return
        ip = packet.getlayer(IP)
        fields = None
        if ip is not None and not ip.frag and not ip.flags.MF:
            layer = ip.payload
            if isinstance(layer, (TCP, UDP, ICMP)):
                icmp = isinstance(layer, ICMP)
                fields = (ip.src, ip.dst, 0 if icmp else layer.sport, 0 if icmp else layer.dport,
                          int(ip.proto), int(ip.len) if ip.len is not None else len(ip), int(ip.ttl),
                          int(layer.flags) if isinstance(layer, TCP) else 0)
        yield from self.feed_fields(float(packet.time), fields)

    def feed_fields(self, timestamp, fields):
        self.seen += 1
        yield from self.expire(timestamp)
        if fields is None:
            self.skipped += 1
            return
        src_ip, dst_ip, sport, dport, number, size, ttl, flags = fields
        key = (*sorted(((src_ip, sport), (dst_ip, dport))), number)
        endpoints = (src_ip, dst_ip, sport, dport, PROTOCOL_NAMES[number])
        if key not in self.flows:
            if len(self.flows) == self.cap:
                yield self.emit(next(iter(self.flows)), "capacity")
            self.flows[key] = (endpoints, self.clock, (Direction(), Direction()), Moments(), [0] * 7)
        first, _, directions, lengths, totals = self.flows[key]
        directions[int(first != endpoints)].add(self.clock, size)
        lengths.add(size)
        totals[0] += ttl
        if flags:
            for index, bit in enumerate(FLAG_BITS, 1):
                totals[index] += bool(flags & bit)
        self.activity[key] = self.clock
        self.activity.move_to_end(key)
        if flags & 5:
            yield self.emit(key, "rst" if flags & 4 else "fin")

    def flush(self, reason):
        while self.flows:
            yield self.emit(next(iter(self.flows)), reason)
        self.finished = time.monotonic()


def ethernet_fields(frame):
    """Read just the outer IPv4 and transport headers in an Ethernet frame."""
    offset = 14
    if len(frame) < offset:
        return None
    kind = int.from_bytes(frame[12:14], "big")
    while kind in (0x8100, 0x88a8, 0x9100):
        if len(frame) < offset + 4:
            return None
        kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if kind != 0x800 or len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        return None
    header_size = (frame[offset] & 15) * 4
    size, _, fragment = struct.unpack_from("!HHH", frame, offset + 2)
    ttl, number = frame[offset + 8:offset + 10]
    minimum = {1: 8, 6: 20, 17: 8}.get(number)
    if minimum is None or fragment & 0x3fff or header_size < 20:
        return None
    transport = offset + header_size
    if size < header_size + minimum or len(frame) < transport + minimum:
        return None
    src = socket.inet_ntoa(frame[offset + 12:offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
    ports = (0, 0) if number == 1 else struct.unpack_from("!HH", frame, transport)
    flags = frame[transport + 13] if number == 6 else 0
    return src, dst, *ports, number, size, ttl, flags


def capture_events(path, engine):
    # Ethernet PCAPs need only a few header fields. Scapy handles other link
    # types and PCAPNG, including captures with multiple interfaces.
    with RawPcapReader(str(path)) as reader:
        if getattr(reader, "linktype", None) == 1 and hasattr(reader, "nano"):
            scale = 1e9 if reader.nano else 1e6
            for frame, meta in reader:
                yield engine.feed_fields(meta.sec + meta.usec / scale, ethernet_fields(frame))
            return
    with PcapReader(str(path)) as reader:
        for packet in reader:
            yield engine.feed(packet)


def iter_pcap_flows(path, engine=None, stop=None, max_packets=None, max_flows=None, stats=None):
    """Stop reading at either cap, finalize open state, and yield up to max_flows."""
    engine = engine or FlowEngine()
    if any(cap is not None and cap < 1 for cap in (max_packets, max_flows)):
        raise ValueError("capture limits must be positive")
    reason, written = "eof", 0
    events = capture_events(path, engine)
    try:
        while True:
            if stop is not None and stop.is_set():
                reason = "interrupt"
                break
            if max_flows is not None and written >= max_flows:
                reason = "flow_cap"
                break
            if max_packets is not None and engine.seen >= max_packets:
                reason = "packet_cap"
                break
            packet_rows = next(events, None)
            if packet_rows is None:
                break
            for row in packet_rows:
                if max_flows is None or written < max_flows:
                    written += 1
                    yield row
    except KeyboardInterrupt:
        reason = "interrupt"
    finally:
        events.close()
    for row in engine.flush(reason):
        if max_flows is None or written < max_flows:
            written += 1
            yield row
    if stats is not None:
        stats.update(reason=reason, packets_read=engine.seen, flows_written=written,
                     flows_over_cap=engine.emitted - written)


def stream_live_flows(interface, on_flow, engine=None, stop=None, measure=None):
    engine = engine or FlowEngine()

    def deliver(rows):
        for row in (measure(rows) if measure else rows):
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
