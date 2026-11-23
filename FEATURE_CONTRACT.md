# IPv4 flow feature contract

The first observed packet defines forward (IN, SRC_TO_DST). A packet with swapped IPs and ports belongs to the reverse direction (OUT, DST_TO_SRC). The key includes the transport protocol. Only IPv4 with a directly decoded TCP or UDP header is eligible. IPv4 fragments are skipped.

For a direction, let G be successive arrival-time differences in milliseconds **within that direction**. With zero or one packet, all four IAT values are 0.0. One gap has population standard deviation 0.0. Packet lengths use the IPv4 total length, including IP and transport headers and payload, excluding Ethernet and padding. Scapy's serialized IP length is used for constructed packets without a populated length field.

| Column in scorer order | Formula | Unit |
|---|---|---|
| IN_PKTS | Count forward packets | packets |
| OUT_PKTS | Count reverse packets | packets |
| IN_BYTES | Sum forward IP lengths | bytes |
| OUT_BYTES | Sum reverse IP lengths | bytes |
| FLOW_DURATION_MILLISECONDS | 1000 × (last timestamp − first timestamp), both directions | ms |
| SRC_TO_DST_IAT_MIN | min(forward G) | ms |
| SRC_TO_DST_IAT_MAX | max(forward G) | ms |
| SRC_TO_DST_IAT_AVG | sum(forward G) / count(forward G) | ms |
| SRC_TO_DST_IAT_STDDEV | √mean((forward gap − forward mean)²) | ms |
| DST_TO_SRC_IAT_MIN | min(reverse G) | ms |
| DST_TO_SRC_IAT_MAX | max(reverse G) | ms |
| DST_TO_SRC_IAT_AVG | sum(reverse G) / count(reverse G) | ms |
| DST_TO_SRC_IAT_STDDEV | √mean((reverse gap − reverse mean)²) | ms |

Timestamps use Unix seconds. The capture clock advances in arrival order and clamps backward timestamps to the latest observed time. Output millisecond fields are rounded to three decimal places after aggregation. Directional moments use bounded batches and population standard deviation.

## Lifecycle and integration

Before processing each packet, expire flows whose idle time reaches 15 seconds or whose age reaches 60 seconds. The earlier deadline determines the reason, with active expiry winning ties. Live capture also checks the clock during silence, roughly every half second. Replay advances on capture timestamps. FIN or RST is counted and closes the flow immediately. At the 2,000-flow cap, a new key evicts the earliest-created open flow. The next packet after closure starts a fresh flow, even for the same key. EOF or interruption flushes outstanding flows. The extractor CLI accepts --idle-timeout and --active-timeout in seconds and --max-open-flows as a count.

Each row from `iter_pcap_flows(path, engine=None)` or callback to `stream_live_flows(interface, on_flow, engine=None, stop=None)` has separate `features` and `metadata` dictionaries. Metadata contains src_ip, dst_ip, src_port, dst_port, protocol, flow_start_ts, flow_end_ts, emit_reason, and emit_delay_ms (capture-clock milliseconds since the last packet at emission). The CSV flattens metadata first, then the ordered features. The scorer gets only the numeric dictionary. No packet payload is retained.

Pass a FlowEngine instance to read its counters. Packets/sec is average throughput since capture or replay-pass start, including configured replay pauses. Skipped counts unsupported packets delivered to the engine. Dropped counts kernel-reported capture socket drops on Linux AF_PACKET when available. PCAP replay and unsupported backends report null (N/A). Offline mode means local capture, storage, and scoring with no external service. It does not measure internet connectivity.

`Dashboard(db_path, scorer=callable, scoring="Model name")` accepts a scorer returning a dictionary with verdict. Use "Flagged" to persist an alert and supply severity, signals (list of strings), and explanation (string). Supply a descriptive scoring label for display. The default verdict is "Unscored". With --demo-rules, three forward packets or 100 forward bytes triggers a demonstration alert. The existing 42-feature classifier has a separate input contract.

## To Confirm Against `expt/nf-ton-iot-v3`

- IP total length versus link-layer or captured length, including truncation and fragments.
- First-observed direction versus initiator/exporter alignment for IN and OUT.
- Millisecond precision, intermediate rounding, and out-of-order handling.
- Population versus sample deviation, per-direction gap definition, and missing-gap values.
- Idle/active limits, equality at deadlines, and FIN/RST closure semantics.

## Run from the repository root

Windows PowerShell, using the project virtual environment:

```powershell
.\.venv\Scripts\python.exe nf_flow_extractor.py --pcap data/nf_test_sample.pcap --output data/nf_flows.csv
.\.venv\Scripts\python.exe dashboard.py --replay-pcap data/nf_test_sample.pcap --interval 1 --loop --demo-rules
```

Linux, using a Python environment with Scapy:

```sh
python3 nf_flow_extractor.py --pcap data/nf_test_sample.pcap --output data/nf_flows.csv
python3 dashboard.py --replay-pcap data/nf_test_sample.pcap --interval 1 --demo-rules
```

Raspberry Pi 5, using the interface that carries the traffic and an interpreter with Scapy installed:

```sh
sudo "$(command -v python3)" nf_flow_extractor.py --interface wlan0
sudo "$(command -v python3)" dashboard.py --interface wlan0 --host 0.0.0.0 --port 8080 --demo-rules
```

Open `http://localhost:8080` on the host or `http://<host-ip>:8080` on the same trusted LAN. The host firewall must permit the latter connection. Anyone with access can read endpoints and submit feedback. The dashboard keeps the latest 50 completed flows in memory and displays the latest 50 persisted alerts. Confirm/Dismiss updates survive restarts in artifacts/alerts.db. Omit --loop to finish after one pass and leave the results available. Ctrl+C stops the server. The included capture is a deterministic synthetic fixture. Regenerate it with `python make_nf_test_pcap.py`.
