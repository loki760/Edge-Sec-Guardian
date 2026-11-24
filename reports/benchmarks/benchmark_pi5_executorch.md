# Edge-Sec Guardian benchmark

Throughput uses capture wall time, including alert persistence. Extraction latency measures iterator work per emitted flow, excluding idle wait. Combined latency sums extraction and detector work. Emit delay uses capture timestamps. Explanation drain is timed separately.

RAM is dashboard process RSS, including queued work during drain. CPU averages and peaks are system-wide. Process CPU percent uses one core as 100%. Peak health values are sampled every 250 ms. An RSS delta is a stability indicator. Compare sustained runs to assess growth. Latency percentiles use at most 8,192 sampled observations per metric. Unavailable readings are reported explicitly.

## Run

| Metric | Value |
|---|---|
| utc | 2026-11-24T19:58:30.539489+00:00 |
| pcap | data/Recon-PortScan.pcap |
| pcap sha256 | e13368bdc571a6ec53f8dd9e5491137dd0656c9d997bd62b323e957722bd4fc1 |
| interface | Unavailable |
| requested duration sec | 15.0000 |
| explain min level | high |
| explanation cooldown sec | 30.0000 |
| detector threads | 1 |
| capture elapsed sec | 27.3866 |
| explanation drain sec | 106.3495 |

## Environment

| Metric | Value |
|---|---|
| os | Linux-6.18.34+rpt-rpi-2712-aarch64-with-glibc2.41 |
| architecture | aarch64 |
| cpu model | Raspberry Pi 5 Model B Rev 1.0 |
| logical cores | 4 |
| physical cores | 4 |
| python | 3.13.5 |
| scikit learn | 1.9.1 |
| executorch | 1.6.0 |

## Artifacts

| Metric | Value |
|---|---|
| detector / path | artifacts/ciciot_model.pkl |
| detector / size mb | 0.7299 |
| llama model / path | models/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte |
| llama model / size mb | 1135.9515 |
| llama tokenizer / path | models/tokenizer.model |
| llama tokenizer / size mb | 2.1840 |

## Detector

| Metric | Value |
|---|---|
| total packets | 5825 |
| total flows | 2690 |
| alert count | 2200 |
| packet drop count | Unavailable |
| packets skipped | 243 |
| packets per sec | 212.6949 |
| flows per sec | 98.2231 |
| replay passes | 1 |
| extraction ms / p50 | 0.0689 |
| extraction ms / p95 | 0.2531 |
| extraction ms / max | 6.2285 |
| extraction ms / count | 2690 |
| extraction ms / sampled | 2690 |
| detector ms / p50 | 4.9045 |
| detector ms / p95 | 27.2892 |
| detector ms / max | 34.7944 |
| detector ms / count | 2690 |
| detector ms / sampled | 2690 |
| combined ms / p50 | 4.9997 |
| combined ms / p95 | 27.4687 |
| combined ms / max | 34.8521 |
| combined ms / count | 2690 |
| combined ms / sampled | 2690 |
| emit delay ms / p50 | 14891.2770 |
| emit delay ms / p95 | 15108.5379 |
| emit delay ms / max | 15421.4710 |
| emit delay ms / count | 2690 |
| emit delay ms / sampled | 2690 |

## Explainer

| Metric | Value |
|---|---|
| mode | executorch |
| invocation count | 20 |
| skipped count | 0 |
| error count | 0 |
| reused count | 2180 |
| last latency ms | 6759.1584 |
| avg latency ms | 6682.9477 |
| ttft ms / p50 | 1957.5938 |
| ttft ms / p95 | 2787.0166 |
| ttft ms / max | 5271.5199 |
| ttft ms / count | 20 |
| ttft ms / sampled | 20 |
| tokens per sec / p50 | 12.2273 |
| tokens per sec / p95 | 12.3314 |
| tokens per sec / max | 12.4207 |
| tokens per sec / count | 20 |
| tokens per sec / sampled | 20 |
| total latency ms / p50 | 6535.8174 |
| total latency ms / p95 | 8214.2625 |
| total latency ms / max | 9925.8925 |
| total latency ms / count | 20 |
| total latency ms / sampled | 20 |
| invocation rate percent | 0.7435 |

## System Health

| Metric | Value |
|---|---|
| start ram mb | 948.7319 |
| peak ram mb | 2355.3147 |
| end ram mb | 2223.7512 |
| ram delta mb | 1275.0193 |
| cpu avg percent | 92.8300 |
| cpu peak percent | 97.1000 |
| cpu samples | 530 |
| process cpu percent | 368.2026 |
| start temperature c | 50.7000 |
| peak temperature c | 68.3000 |
| end temperature c | 65.0000 |
| start throttling | throttled=0x0 |
| end throttling | throttled=0x0 |

