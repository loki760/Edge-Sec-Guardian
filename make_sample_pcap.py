"""Create six deterministic packets for checking the offline extractor."""

from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def make_sample_pcap(output_path):
    # Fixed Ethernet addresses avoid route/interface lookups when writing packets.
    ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    packets = [
        ethernet / IP(src="192.168.1.5", dst="192.168.1.10")
        / TCP(sport=5000, dport=80, flags="S"),
        ethernet / IP(src="192.168.1.10", dst="192.168.1.5")
        / TCP(sport=80, dport=5000, flags="SA"),
        ethernet / IP(src="192.168.1.5", dst="192.168.1.10")
        / TCP(sport=5000, dport=80, flags="RA") / Raw(b"test"),
        ethernet / IP(src="192.168.1.5", dst="192.168.1.20")
        / UDP(sport=6000, dport=53) / Raw(b"abcd"),
        ethernet / IP(src="192.168.1.20", dst="192.168.1.5")
        / UDP(sport=53, dport=6000) / Raw(b"abcdefgh"),
        ethernet / IP(src="192.168.1.5", dst="192.168.1.10")
        / TCP(sport=5001, dport=443, flags="S"),
    ]
    timestamps = [1000.0, 1000.5, 1002.0, 1003.0, 1004.0, 1005.0]
    for packet, timestamp in zip(packets, timestamps):
        packet.time = timestamp

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)


if __name__ == "__main__":
    make_sample_pcap("data/sample.pcap")
    print("Wrote 6 packets to data/sample.pcap")
