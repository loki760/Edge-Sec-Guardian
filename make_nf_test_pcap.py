"""Write the deterministic, synthetic flow-contract fixture (no capture device needed)."""
from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap


def sample_packets():
    packets = []
    for offset, proto, reverse, port, flags in [
        (0, TCP, False, 1000, "S"), (.125, TCP, True, 1000, "SA"),
        (.25, TCP, False, 1000, "A"), (.625, TCP, True, 1000, "A"),
        (1, TCP, False, 1000, "FA"), (2, UDP, False, 2000, ""),
        (2.25, UDP, False, 2000, ""), (18, UDP, False, 2000, ""),
        (19, ICMP, False, 0, ""), (19, ICMP, True, 0, ""),
    ]:
        a = ("02:00:00:00:00:01", "192.0.2.1", port)
        b = ("02:00:00:00:00:02", "192.0.2.2", 443)
        src, dst = (b, a) if reverse else (a, b)
        layer = (ICMP(type=0 if reverse else 8) if proto is ICMP
                 else proto(sport=src[2], dport=dst[2]))
        if proto is TCP:
            layer.flags = flags
        packet = Ether(src=src[0], dst=dst[0]) / IP(src=src[1], dst=dst[1]) / layer
        packet.time = 1700000000 + offset
        packets.append(packet)
    return packets


if __name__ == "__main__":
    path = Path(__file__).parent / "data" / "nf_test_sample.pcap"
    wrpcap(str(path), sample_packets())
