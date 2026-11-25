# Edge-Sec-Guardian engineering report

Bharat AI-SoC Challenge, Phase 1 · Problem Statement 3, Option C

## 1. Problem statement and system overview

Option C asks for local intrusion detection for a home or small-office network. Edge-Sec-Guardian runs on a Raspberry Pi 5 at a network point that can observe the traffic, such as the LAN-facing interface of a gateway. It extracts flow statistics from TCP, UDP and ICMP over IPv4, scores the completed flows, and presents alerts in a local web dashboard. After installation, detection and explanation need no internet connection or remote inference service. The live browser workload used internet access to generate traffic through the gateway.

The detector combines a binary ML score with deterministic network rules. It decides whether to raise an alert before the optional Llama worker runs. Llama summarizes selected evidence and suggests review steps. Its output cannot change the detector decision or trigger blocking, deletion or a system command.

## 2. Hardware mapping and runtime stack

| Item | Submission configuration and evidence |
| --- | --- |
| Board and CPU | Raspberry Pi 5 Model B Rev 1.0, four physical cores, AArch64. The project configuration specifies the 8 GB board. |
| Operating system | The project configuration specifies Debian 13. The benchmark exports identify Linux kernel `6.18.34+rpt-rpi-2712` and glibc 2.41. |
| Python and detector | Python 3.13.5 and scikit-learn 1.9.1 in the physical-board benchmarks. The serialized detector is 729,676 bytes (0.73 MB). |
| Explanation runtime | ExecuTorch 1.6.0 using the local CPU-only `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte` and `tokenizer.model`. XNNPACK is the stated deployment backend. The saved benchmark JSON records the runtime version and model paths. |
| Capture and scoring | Linux `AF_PACKET` on `eth0`, with a 16 MiB `SO_RCVBUF` request and an effective 8 MiB buffer reported in the final live run. A separate worker consumes a bounded queue of 4,096 completed flows. |

The detector bundle and the persistent ExecuTorch `TextLLMRunner` are created once at application startup. The adapter calls the runtime load method when exposed, and resets generation state between requests. Each benchmark records runtime versions, input source, artifact sizes and the replay capture hash where applicable. [Physical Pi logs](reports/benchmarks/) · [Live-run evidence](reports/benchmarks/inline_stress_comparison.md)

## 3. Detection pipeline and ML iterations

The [flow extractor](nf_flow_extractor.py) uses one 29-feature contract for PCAP replay, offline dataset generation and live capture. It keeps at most 2,000 open flows and computes packet counts, byte counts, rates, directional timing, lengths, TTL and TCP flag ratios without buffering payloads in flow state. Initial TCP flags and endpoints are separate metadata. The ML input excludes endpoints, timestamps, capture names and labels. [Feature contract](FEATURE_CONTRACT.md)

- **UNSW-NB15 baseline.** The historical `main` README recorded 0.893497 attack F1 and 26.98% FPR on the official held-out split. The Random Forest used 42 CSV features. Its dataset and features differ from the final model’s, so this is a historical reference across different workloads. [Baseline README](https://github.com/loki760/Edge-Sec-Guardian/blob/449c66a4a40d9ece34811eeb1331ca3ae7e7b54f/README.md)
- **NF-ToN-IoT-v3 exploration.** The project explored distribution shift with a separate NetFlow experiment described as `expt/nf-ton-iot-v3`. That branch and its measurement files were absent from the audited checkout. This report uses no numerical result from that experiment.
- **Offline multiclass XGBoost exploration.** The team explored an eight-class Pattern-Aware XGBoost model in Colab. The audit found no saved notebook, evaluation output or Pi latency measurement for that model. The deployed HGB uses the same 29 features that the live collector produces, and its local artifact size, target FPR and Pi latency have recorded measurements.
- **CIC-IoT-2023 raw-PCAP detector.** The deployed `HistGradientBoostingClassifier` fits training flows, ranks candidate operating points on validation, and evaluates the held-out test flows after selection. The selection manifest binds the CSV and each split to SHA-256 hashes. It pins all 1,806 local `BenignTraffic4.pcap` flows to training. Separate whole benign captures supply validation and test. Attack families with too few captures use chronological blocks with an embargo at the boundaries. These blocks share capture conditions, which limits claims about generalization to independent recordings. [Split report](reports/FEATURE_SELECTION.md) · [Model comparison](reports/MODEL_COMPARISON.md)

The training, validation and test sets contain 71,434, 25,403 and 25,364 flows. The validation FPR target was 2.0%, and the measured validation FPR was 1.9997%. The deployed High threshold is `0.9658762205636321`. The Medium threshold is `0.48293811028181605`, a review band that does not independently raise an alert.

| Held-out ML metric | Value |
| --- | ---: |
| Accuracy | 75.2326% |
| Precision | 99.6575% |
| Recall | 48.1708% |
| F1 | 0.649481 |
| FPR | 0.1506% |
| ROC-AUC | 0.919957 |
| PR-AUC | 0.929682 |

| Actual class | Predicted benign | Predicted attack |
| --- | ---: | ---: |
| Benign | 13,262 | 20 |
| Attack | 6,262 | 5,820 |

| Attack family | Held-out recall |
| --- | ---: |
| BruteForce | 3.7333% |
| DDoS | 52.2936% |
| DoS | 99.6889% |
| Mirai | 0.0000% |
| Recon | 73.6000% |
| Spoofing | 2.0000% |
| Web-based | 11.3019% |

Source for all tables: [CIC metrics JSON](artifacts/ciciot_metrics.json). These are classifier-only test metrics. The deployed `RiskFusionScorer` also detects bursts of distinct destination ports per source IP, destination IP and protocol. For TCP, it requires an opening SYN without ACK. TCP flood and packet-rate rules use SYN-heavy or asymmetric low-ACK traffic. UDP and ICMP flood rules require high forward volume and few or no replies. Bidirectional UDP/443 is excluded from the UDP flood rule. [Rule definitions](CIC_IOT_PIPELINE.md#reading-a-dashboard-result)

## 4. On-device ExecuTorch explainer

A single background worker handles up to 16 waiting jobs. High flagged flows qualify by default. A pending job is shared across matches, and a completed result is reused for 30 seconds for the same source IP, risk level and sorted signals. Capture and alert creation continue while the Llama worker runs.

The prompt receives allowlisted detector signals, the risk level and score, protocol and selected numeric counters. It receives no payload, endpoint address, hostname, filename or ground-truth label. The runtime caps generation at 100 tokens. The parser extracts JSON from a short preamble when needed, requires two text fields, and checks length, verdict overrides, certainty claims and unsafe advice. SQLite retains explanation status and measured timing.

In a recorded physical Pi test, 80 offline SYN flow records produced 72 High port-burst alerts. The real ExecuTorch worker saved this explanation and action:

> The device tried multiple network services in quick succession, indicating a potential attack.
>
> Review the device's configuration and network services to identify potential vulnerabilities.

The fixture emitted no network packets. The execution log is local evidence, summarized in the [inline and offline comparison](reports/benchmarks/inline_stress_comparison.md).

## 5. Physical Raspberry Pi 5 benchmarks

The first two captures replayed the same `Recon-PortScan.pcap` file for different time budgets. The sustained run used live `eth0` traffic with offline inference. Each run used one detector worker thread. The table uses decimal MB for process RSS. Invocation rate is the share of emitted flows that caused a model call, and reuse counts are saved alert explanations served from a shared result.

| Measurement | [Fast path only](reports/benchmarks/benchmark_pi5_fast.json) | [Full ExecuTorch](reports/benchmarks/benchmark_pi5_executorch.json) | [15-minute live capture](reports/benchmarks/benchmark_pi5_sustained_15m.json) |
| --- | ---: | ---: | ---: |
| Capture elapsed (s) | 30.55 | 27.39 | 900.43 |
| Packets / flows | 23,183 / 7,373 | 5,825 / 2,690 | 2,190 / 318 |
| Packets/s / flows/s | 758.82 / 241.33 | 212.69 / 98.22 | 2.43 / 0.35 |
| Detector p50 / p95 (ms) | 3.77 / 3.86 | 4.90 / 27.29 | 10.07 / 27.68 |
| Llama invocations / invocation rate | 0 / 0.000% | 20 / 0.743% | 11 / 3.459% |
| Reused explanations | 0 | 2,180 | 292 |
| TTFT p50 / p95 (s) | — | 1.96 / 2.79 | 2.14 / 3.38 |
| Decode p50 / p95 (tokens/s) | — | 12.23 / 12.33 | 12.01 / 12.11 |
| Explanation latency p50 / p95 (s) | — | 6.54 / 8.21 | 6.56 / 8.04 |
| Explanation drain after capture (s) | 0.00 | 106.35 | <0.01 |
| Start / peak / end RSS (MB) | 220.18 / 226.16 / 226.15 | 948.73 / 2,355.31 / 2,223.75 | 1,212.83 / 2,651.52 / 2,468.07 |
| Peak CPU temperature (°C) | 52.35 | 68.30 | 61.15 |
| Throttling at start and end | `0x0` | `0x0` | `0x0` |

The 15-minute RSS rose during the run and ended below its measured peak. The benchmark records summary readings, so it cannot establish a flat memory curve. The short replay also left a substantial explanation backlog after capture ended. These benchmark logs predate the final inline capture changes and recorded a 729,892-byte detector artifact. The present detector file is 729,676 bytes.

### Real inline Chrome and YouTube workload

| Measurement | Before fixes | After fixes |
| --- | ---: | ---: |
| Packets read | 118,819 | 202,258 |
| Kernel packet drops | 124,293 | 0 |
| Scoring queue drops | Unmeasured | 0 |
| Emitted flows | 3,766 | 5,492 |
| Scored flows recovered by polling | 3,691 | 4,727 |
| New High alerts | 464 | 13 |
| High alerts involving a rule | 424 | 0 |
| Chrome HTTP/3 responses | 1,005 | 1,015 |

The fixes were to count TCP opening SYNs per source, destination and protocol, require TCP rate corroboration and exclude isolated web replies, and read raw Ethernet frames with a larger receive buffer and a separate scoring queue. The new run recorded zero rule-driven High alerts. The 13 ML-only High alerts are **0.275% of 4,727 observed scored flows**. This is a live alert share. Test-site ground truth was unavailable for those endpoints, so it cannot establish a live FPR. API polling recovered 5,016 of 5,492 emitted flows. [Redacted audit and original evidence references](reports/benchmarks/inline_stress_comparison.md)

## 6. Limitations

- CIC-IoT-2023 labels identify the capture scenario. Normal HTTPS or other background sessions within an attack-labelled PCAP inherit the capture label. This can create conflicting benign and attack examples. Low measured recall for BruteForce, Spoofing, Web-based and Mirai limits coverage claims.
- Ten of the 13 remaining live High alerts had only an opening SYN and a SYN-ACK before the idle timeout. This shape is consistent with speculative browser preconnects or abandoned handshakes. The logs did not associate those endpoints with a test site, so no browser cause is confirmed.
- A single interface sees the traffic that actually reaches it. To inspect other devices on a switched LAN, place the sensor on their forwarding path or use a router or switch mirror. This release extracts IPv4 flows.
- The High threshold favors a low false-positive rate at the measured validation operating point. The separate benign local Pi capture is used for training, so the held-out test does not independently estimate Pi traffic FPR.

## 7. Privacy, security and offline-safe updates

Flow extraction reads headers and counts, and the dashboard stores flow metadata, alert details, explanations and Confirm/Dismiss feedback in local SQLite. It does not save raw packet payloads. Endpoints and timestamps are retained for review and may be identifying, so treat the database and packet captures as private data. The Llama evidence omits endpoints. Keep the dashboard bound to loopback or a restricted management interface.

The proposed offline update procedure is manual. Temporarily connect the Pi to a trusted update network, such as Wi-Fi, and download the approved release bundle, including the wheel for rule changes, the trusted `.pkl`, and the matching `.pte` and tokenizer as applicable. Verify a signed SHA-256 manifest with a release key already trusted by the Pi, then verify each artifact hash against that manifest. Stage the files, confirm the scikit-learn and model contracts, install locally and run a smoke test. Disconnect the update network and resume offline capture. The repository does not implement a signed-release updater. A checksum alone verifies bytes against the manifest, while the signature authenticates its publisher. Load pickles only from trusted releases.

## 8. Extensibility

Option A could use a local SMS scam detector with bounded, redacted features. Option B could use a local phishing URL detector and redact sensitive URL components before explanations. Each would supply its own detector evidence and risk decision. An adapter can connect those signals to the common alert fields, SQLite feedback, dashboard views and asynchronous ExecuTorch worker. The current evidence validator is network-specific, so either option needs its own allowlist and tests. The shared worker and UI can stay in place.
