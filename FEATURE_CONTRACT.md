# IPv4 flow feature contract

The first observed packet establishes the forward direction (IN or SRC_TO_DST). The flow key pairs the two IP/port endpoints in either order and includes the IP protocol. TCP and UDP use transport ports. ICMP uses zero for both ports and aggregates messages between the same two hosts. The engine skips fragmented IPv4 packets. Ethernet parsing supports VLAN tags and reads the outer IP header. The table gives the exact order of `MODEL_FEATURE_COLUMNS`.

| Feature(s), in order | Definition |
|---|---|
| PROTOCOL_NUM | 6 for TCP, 17 for UDP, 1 for ICMP |
| IN_PKTS, OUT_PKTS | Forward and reverse packet counts |
| IN_BYTES, OUT_BYTES | Forward and reverse sums of IPv4 total lengths, including IP/transport headers and payload, excluding Ethernet framing and padding |
| FLOW_DURATION_MILLISECONDS | 1,000 × elapsed seconds between first and last packets |
| PKTS_PER_SEC, BYTES_PER_SEC | Total packets and total IPv4 bytes divided by elapsed seconds. Both are zero for zero duration. |
| IN_OUT_PKT_RATIO, IN_OUT_BYTE_RATIO | Forward count or bytes divided by the corresponding reverse value plus one |
| PKT_LEN_MIN, PKT_LEN_MAX, PKT_LEN_MEAN, PKT_LEN_STD | Minimum, maximum, mean and population standard deviation of IPv4 lengths in both directions |
| TTL_MEAN | Arithmetic mean of all outer IPv4 TTLs |
| SYN_RATIO, ACK_RATIO, FIN_RATIO, RST_RATIO, PSH_RATIO, URG_RATIO | Fraction of all flow packets carrying the respective TCP flag. Each flag counts separately. UDP and ICMP have zero for each value. |
| SRC_TO_DST_IAT_MIN, SRC_TO_DST_IAT_MAX, SRC_TO_DST_IAT_AVG, SRC_TO_DST_IAT_STDDEV | Minimum, maximum, mean and population standard deviation of the gaps in milliseconds between successive forward packets |
| DST_TO_SRC_IAT_MIN, DST_TO_SRC_IAT_MAX, DST_TO_SRC_IAT_AVG, DST_TO_SRC_IAT_STDDEV | Same statistics for reverse packets |

With fewer than two packets in a direction, all four gap values are zero. A single gap has zero standard deviation. Online population moments keep constant memory per open flow. The capture clock uses Unix seconds, clamps backward arrivals to the latest seen timestamp, and retains floating-point precision for feature values.

## Flow lifecycle and interfaces

Before processing a packet the engine expires flows idle for at least 15 seconds or open for at least 60 seconds. The earlier deadline determines the reason, with active expiry winning ties. Live capture checks the clock during silence every half second. FIN or RST is counted and closes a TCP flow immediately. At 2,000 open flows a new key evicts the earliest-created flow. Reuse of a closed key starts a new flow. EOF and interruption flush open flows. The extractor CLI supports `--idle-timeout`, `--active-timeout` and `--max-open-flows`.

`iter_pcap_flows(path, engine=None, stop=None, max_packets=None, max_flows=None, stats=None)` yields dictionaries with separate `features` and `metadata` fields. `stream_live_flows(interface, on_flow, engine=None, stop=None)` calls the callback with the same structure. Metadata contains src_ip, dst_ip, src_port, dst_port, protocol, flow_start_ts, flow_end_ts, emit_reason and emit_delay_ms. Delay measures capture-clock milliseconds from the last packet until emission. The extractor CSV flattens metadata followed by the 29 features. Packet payload, IP addresses, ports, filenames, timestamps and capture labels never enter the predictor vector.

The engine reports packets_seen, packets_skipped, packets_dropped, flows_emitted, open_flows, packets_per_sec and avg_emit_delay_ms. Throughput averages all packets over elapsed processing time. Drops come from Linux AF_PACKET capture statistics when available. File replay and unsupported capture backends report null.

## Building capture-labelled data

`build_ciciot_dataset.py` recursively reads PCAP/PCAPNG files and writes source_pcap (path relative to the input root), flow_start_ts, attack_family, label and the ordered features. Known CIC-IoT-2023 names identify one of Benign, BruteForce, DDoS, DoS, Mirai, Recon, Spoofing and Web-based. A recognized filename and parent folder pointing to different families cause an error. For renamed or ambiguous files, supply a JSON object with exact relative paths using forward slashes, e.g. `{"lab/a.pcap":{"attack_family":"Recon","label":1}}`. Labels describe capture membership. Benign traffic inside attack captures can inherit an attack label.

The default prefix limits are 250,000 packets and 15,000 written flows per file. The reader stops before requesting another packet when either limit is reached. Open flows are finalized at the boundary. The flow limit also applies to flushed output. A neighboring `.manifest.json` records the limits, read and write counts, stop reason, and number of finalized flows beyond the write limit. Capture prefixes may underrepresent later traffic.

```powershell
.\.venv\Scripts\python.exe make_nf_test_pcap.py
.\.venv\Scripts\python.exe nf_flow_extractor.py --pcap data/nf_test_sample.pcap --output data/nf_test_features.csv
.\.venv\Scripts\python.exe build_ciciot_dataset.py --pcap-dir data/raw/ciciot2023 --output data/processed/ciciot_flows.csv --max-flows-per-file 15000 --max-packets-per-file 250000
```

The included ten-packet capture is synthetic. It exercises TCP, UDP and ICMP without a live capture device.
