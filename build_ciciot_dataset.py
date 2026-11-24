"""Build a capture-labelled CIC-IoT-2023 flow CSV from local PCAP files."""
import argparse
import csv
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

from scapy.error import Scapy_Exception

from nf_flow_extractor import MODEL_FEATURE_COLUMNS, iter_pcap_flows

# Published attack names grouped into the CIC-IoT-2023 taxonomy.
ATTACKS = {
    "Benign": ["BenignTraffic", "Benign"],
    "DDoS": ["DDoS-" + name for name in (
        "ACK_Fragmentation", "UDP_Flood", "SlowLoris", "ICMP_Flood", "RSTFINFlood",
        "PSHACK_Flood", "HTTP_Flood", "UDP_Fragmentation", "ICMP_Fragmentation",
        "TCP_Flood", "SYN_Flood", "SynonymousIP_Flood")],
    "DoS": ["DoS-" + name for name in ("UDP_Flood", "SYN_Flood", "TCP_Flood", "HTTP_Flood")],
    "Mirai": ["Mirai-greeth_flood", "Mirai-greip_flood", "Mirai-udpplain"],
    "Recon": ["Recon-PingSweep", "Recon-OSScan", "Recon-PortScan", "Recon-HostDiscovery",
              "VulnerabilityScan"],
    "Spoofing": ["DNS_Spoofing", "MITM-ArpSpoofing"],
    "Web-based": ["BrowserHijacking", "Backdoor_Malware", "XSS", "Uploading_Attack",
                  "SqlInjection", "CommandInjection"],
    "BruteForce": ["DictionaryBruteForce"],
}
CSV_COLUMNS = ["source_pcap", "flow_start_ts", "attack_family", "label", *MODEL_FEATURE_COLUMNS]


def normalize(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


FAMILIES = {normalize(name): family for family, names in ATTACKS.items()
            for name in [family, *names]}


def capture_label(relative, mapping):
    if relative.as_posix() in mapping:
        entry = mapping[relative.as_posix()]
        if not isinstance(entry, dict) or not isinstance(entry.get("attack_family"), str):
            raise ValueError(f"Invalid label map entry for {relative}")
        family, label = entry["attack_family"], entry.get("label")
        if not family.strip() or type(label) is not int or label not in (0, 1):
            raise ValueError(f"Invalid family or binary label for {relative}")
        if family in ATTACKS and label != int(family != "Benign"):
            raise ValueError(f"Conflicting family and label for {relative}")
        return family, label
    matches = set()
    for part in [*relative.parts[:-1], relative.stem]:
        key = re.sub(r"[0-9]+$", "", normalize(part))
        if key in FAMILIES:
            matches.add(FAMILIES[key])
    if len(matches) != 1:
        raise ValueError(f"Unknown or ambiguous capture label for {relative}. Supply --label-map.")
    family = matches.pop()
    return family, int(family != "Benign")


def build_dataset(pcap_dir, output, max_flows_per_file=15000, max_packets_per_file=250000,
                  label_map=None):
    root, output = Path(pcap_dir), Path(output)
    paths = sorted(path for path in root.rglob("*")
                   if path.is_file() and path.suffix.lower() in (".pcap", ".pcapng"))
    if not paths:
        raise ValueError(f"No PCAP or PCAPNG files under {root}")
    if max_flows_per_file < 1 or max_packets_per_file < 1:
        raise ValueError("Caps must be positive")
    mapping = {} if label_map is None else json.loads(Path(label_map).read_text(encoding="utf-8-sig"))
    if not isinstance(mapping, dict):
        raise ValueError("Label map must be a JSON object keyed by relative capture path")
    relative_paths = [path.relative_to(root) for path in paths]
    labels = [capture_label(path, mapping) for path in relative_paths]
    if output.resolve() in {p.resolve() for p in paths}:
        raise ValueError("Output must differ from source captures")
    families, classes, captures = Counter(), Counter(), []
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = tempfile.NamedTemporaryFile(mode="w", newline="", encoding="utf-8",
                                       dir=output.parent, delete=False)
    try:
        with temp:
            writer = csv.writer(temp)
            writer.writerow(CSV_COLUMNS)
            for path, relative, (family, label) in zip(paths, relative_paths, labels):
                source = relative.as_posix()
                stats = dict(source_pcap=source, attack_family=family, label=label)
                for row in iter_pcap_flows(path, max_packets=max_packets_per_file,
                                           max_flows=max_flows_per_file, stats=stats):
                    writer.writerow([source, row["metadata"]["flow_start_ts"], family, label,
                                     *(row["features"][key] for key in MODEL_FEATURE_COLUMNS)])
                captures.append(stats)
                families[family] += stats["flows_written"]
                classes[label] += stats["flows_written"]
                print(json.dumps(stats), flush=True)
                if stats["reason"] == "interrupt":
                    raise KeyboardInterrupt
        os.replace(temp.name, output)
    finally:
        Path(temp.name).unlink(missing_ok=True)
    summary = dict(max_packets_per_file=max_packets_per_file, max_flows_per_file=max_flows_per_file,
                   families=dict(families), classes=dict(classes), captures=captures)
    output.with_suffix(".manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"families": families, "classes": classes}))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-flows-per-file", type=int, default=15000)
    parser.add_argument("--max-packets-per-file", type=int, default=250000)
    parser.add_argument("--label-map")
    args = parser.parse_args()
    try:
        build_dataset(args.pcap_dir, args.output, args.max_flows_per_file, args.max_packets_per_file,
                      args.label_map)
    except (OSError, ValueError, Scapy_Exception) as exc:
        print(f"Dataset build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
