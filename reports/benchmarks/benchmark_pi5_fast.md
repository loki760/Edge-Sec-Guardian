# Edge-Sec Guardian benchmark

Throughput uses capture wall time, including alert persistence. Extraction latency measures iterator work per emitted flow, excluding idle wait. Combined latency sums extraction and detector work. Emit delay uses capture timestamps. Explanation drain is timed separately.

RAM is dashboard process RSS, including queued work during drain. CPU averages and peaks are system-wide. Process CPU percent uses one core as 100%. Peak health values are sampled every 250 ms. An RSS delta is a stability indicator. Compare sustained runs to assess growth. Latency percentiles use at most 8,192 sampled observations per metric. Unavailable readings are reported explicitly.

## Run

| Metric | Value |
|---|---|
| utc | 2026-11-24T17:40:57.861226+00:00 |
| pcap | data/Recon-PortScan.pcap |
| pcap sha256 | e13368bdc571a6ec53f8dd9e5491137dd0656c9d997bd62b323e957722bd4fc1 |
| interface | Unavailable |
| requested duration sec | 30.0000 |
| explain min level | high |
| explanation cooldown sec | 30.0000 |
| detector threads | 1 |
| capture elapsed sec | 30.5515 |
| explanation drain sec | 0.0000 |

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
| executorch | not installed |

## Artifacts

| Metric | Value |
|---|---|
| detector / path | artifacts/ciciot_model.pkl |
| detector / size mb | 0.7299 |
| llama model | Unavailable |
| llama tokenizer | Unavailable |

## Detector

| Metric | Value |
|---|---|
| total packets | 23183 |
| total flows | 7373 |
| alert count | 5300 |
| packet drop count | Unavailable |
| packets skipped | 1101 |
| packets per sec | 758.8176 |
| flows per sec | 241.3304 |
| replay passes | 1 |
| extraction ms / p50 | 0.0708 |
| extraction ms / p95 | 0.2327 |
| extraction ms / max | 5.3414 |
| extraction ms / count | 7373 |
| extraction ms / sampled | 7373 |
| detector ms / p50 | 3.7702 |
| detector ms / p95 | 3.8619 |
| detector ms / max | 16.5822 |
| detector ms / count | 7373 |
| detector ms / sampled | 7373 |
| combined ms / p50 | 3.8500 |
| combined ms / p95 | 4.0591 |
| combined ms / max | 16.9283 |
| combined ms / count | 7373 |
| combined ms / sampled | 7373 |
| emit delay ms / p50 | 15000.0360 |
| emit delay ms / p95 | 255250.7822 |
| emit delay ms / max | 255655.9610 |
| emit delay ms / count | 7373 |
| emit delay ms / sampled | 7373 |

## Explainer

| Metric | Value |
|---|---|
| mode | none |
| invocation count | 0 |
| skipped count | 0 |
| error count | 0 |
| reused count | 0 |
| last latency ms | Unavailable |
| avg latency ms | Unavailable |
| ttft ms / p50 | Unavailable |
| ttft ms / p95 | Unavailable |
| ttft ms / max | Unavailable |
| ttft ms / count | 0 |
| ttft ms / sampled | 0 |
| tokens per sec / p50 | Unavailable |
| tokens per sec / p95 | Unavailable |
| tokens per sec / max | Unavailable |
| tokens per sec / count | 0 |
| tokens per sec / sampled | 0 |
| total latency ms / p50 | Unavailable |
| total latency ms / p95 | Unavailable |
| total latency ms / max | Unavailable |
| total latency ms / count | 0 |
| total latency ms / sampled | 0 |
| invocation rate percent | 0.0000 |

## System Health

| Metric | Value |
|---|---|
| start ram mb | 220.1846 |
| peak ram mb | 226.1647 |
| end ram mb | 226.1484 |
| ram delta mb | 5.9638 |
| cpu avg percent | 25.0372 |
| cpu peak percent | 25.7000 |
| cpu samples | 121 |
| process cpu percent | 100.0605 |
| start temperature c | 47.9500 |
| peak temperature c | 52.3500 |
| end temperature c | 50.7000 |
| start throttling | throttled=0x0 |
| end throttling | throttled=0x0 |

