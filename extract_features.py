"""Read an offline PCAP and export one row per bidirectional IPv4 flow."""

import argparse
import csv
import math
import statistics
import sys
from pathlib import Path

from scapy.all import IP, TCP, UDP, PcapReader
from scapy.error import Scapy_Exception


FLOW_COLUMNS = ["source_ip", "destination_ip", "source_port", "destination_port", "protocol"]
FEATURE_COLUMNS = [
    "flow_duration", "total_fwd_pkts", "total_bwd_pkts",
    "total_fwd_bytes", "total_bwd_bytes", "pkt_rate", "byte_rate",
    "pkt_len_mean", "pkt_len_std", "pkt_len_max", "iat_mean", "iat_std",
    "syn_ratio", "rst_ratio", "ack_ratio", "unique_dst_ports_by_src",
]


def parse_packet(packet):
    """Return the fields we need, or None for unsupported/malformed packets."""
    if IP not in packet:
        return None

    ip = packet[IP]
    # Port-based flows require complete, unfragmented IPv4 transport headers.
    if ip.frag != 0 or ip.flags.MF:
        return None

    transport = ip.payload
    if ip.proto == 6 and isinstance(transport, TCP):
        protocol = "TCP"
    elif ip.proto == 17 and isinstance(transport, UDP):
        protocol = "UDP"
    else:
        return None

    try:
        if ip.ihl < 5 or ip.len < ip.ihl * 4 or ip.len > len(ip):
            return None
        if protocol == "TCP":
            if transport.dataofs < 5 or transport.dataofs * 4 > ip.len - ip.ihl * 4:
                return None
        elif transport.len < 8 or transport.len > ip.len - ip.ihl * 4:
            return None

        timestamp = float(packet.time)
        if not math.isfinite(timestamp):
            return None
        flags = 0
        if protocol == "TCP" and transport.flags is not None:
            flags = int(transport.flags)

        return {
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "source_port": int(transport.sport),
            "destination_port": int(transport.dport),
            "protocol": protocol,
            "length": len(packet),
            "timestamp": timestamp,
            "flags": flags,
        }
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def read_flows(input_path):
    """Keep all supported packets in flow lists; count ports across the PCAP."""
    flows = {}
    destination_ports = {}
    total_packets = 0
    skipped_packets = 0

    with PcapReader(str(input_path)) as reader:
        for packet in reader:
            total_packets += 1
            fields = parse_packet(packet)
            if fields is None:
                skipped_packets += 1
                continue

            source_ip = fields["source_ip"]
            destination_ip = fields["destination_ip"]
            source_port = fields["source_port"]
            destination_port = fields["destination_port"]
            protocol = fields["protocol"]
            key = (source_ip, destination_ip, source_port, destination_port, protocol)
            reverse_key = (destination_ip, source_ip, destination_port, source_port, protocol)

            # The key created by the first packet fixes the forward direction.
            if key in flows:
                flows[key].append(fields)
            elif reverse_key in flows:
                flows[reverse_key].append(fields)
            else:
                flows[key] = [fields]

            if source_ip not in destination_ports:
                destination_ports[source_ip] = set()
            destination_ports[source_ip].add(destination_port)

    return flows, destination_ports, total_packets, skipped_packets


def flow_to_row(packets, destination_ports):
    """Calculate the 16 features. README.md defines their units and edge cases."""
    first = packets[0]
    forward_packets = 0
    backward_packets = 0
    forward_bytes = 0
    backward_bytes = 0
    syn_count = 0
    rst_count = 0
    ack_count = 0
    lengths = []
    timestamps = []

    for packet in packets:
        # In this flow, matching the first source endpoint means forward.
        if (packet["source_ip"] == first["source_ip"]
                and packet["source_port"] == first["source_port"]):
            forward_packets += 1
            forward_bytes += packet["length"]
        else:
            backward_packets += 1
            backward_bytes += packet["length"]

        lengths.append(packet["length"])
        timestamps.append(packet["timestamp"])
        if packet["flags"] & 0x02:
            syn_count += 1
        if packet["flags"] & 0x04:
            rst_count += 1
        if packet["flags"] & 0x10:
            ack_count += 1

    # Capture records may be out of timestamp order. Use chronological gaps.
    timestamps.sort()
    duration = timestamps[-1] - timestamps[0]
    inter_arrival_times = []
    for index in range(1, len(timestamps)):
        inter_arrival_times.append(timestamps[index] - timestamps[index - 1])

    packet_count = len(packets)
    total_bytes = forward_bytes + backward_bytes
    packet_rate = 0.0
    byte_rate = 0.0
    if duration > 0:
        packet_rate = packet_count / duration
        byte_rate = total_bytes / duration

    iat_mean = 0.0
    iat_std = 0.0
    if inter_arrival_times:
        iat_mean = statistics.mean(inter_arrival_times)
        iat_std = statistics.pstdev(inter_arrival_times)

    return {
        "source_ip": first["source_ip"],
        "destination_ip": first["destination_ip"],
        "source_port": first["source_port"],
        "destination_port": first["destination_port"],
        "protocol": first["protocol"],
        "flow_duration": duration,
        "total_fwd_pkts": forward_packets,
        "total_bwd_pkts": backward_packets,
        "total_fwd_bytes": forward_bytes,
        "total_bwd_bytes": backward_bytes,
        "pkt_rate": packet_rate,
        "byte_rate": byte_rate,
        "pkt_len_mean": statistics.mean(lengths),
        "pkt_len_std": statistics.pstdev(lengths),
        "pkt_len_max": max(lengths),
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "syn_ratio": syn_count / packet_count,
        "rst_ratio": rst_count / packet_count,
        "ack_ratio": ack_count / packet_count,
        "unique_dst_ports_by_src": len(destination_ports[first["source_ip"]]),
    }


def write_csv(rows, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=FLOW_COLUMNS + FEATURE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Input PCAP file")
    parser.add_argument("--output", required=True, type=Path, help="Output flow CSV")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("input and output must be different files")

    try:
        flows, destination_ports, total_packets, skipped_packets = read_flows(args.input)
        print(f"Packets processed: {total_packets} (skipped: {skipped_packets})")
        print(f"Flows found: {len(flows)}")
        rows = []
        for packets in flows.values():
            rows.append(flow_to_row(packets, destination_ports))
        write_csv(rows, args.output)
    except (OSError, Scapy_Exception, ValueError, EOFError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Saved {len(rows)} rows to {args.output}")
    for row in rows[:3]:
        print(
            f"  {row['protocol']} {row['source_ip']}:{row['source_port']} -> "
            f"{row['destination_ip']}:{row['destination_port']}: "
            f"{row['total_fwd_pkts']} forward, {row['total_bwd_pkts']} backward, "
            f"{row['flow_duration']:.6f} seconds"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
