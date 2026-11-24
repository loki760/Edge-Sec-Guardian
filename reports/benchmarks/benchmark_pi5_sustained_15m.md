# Edge-Sec Guardian benchmark

Throughput uses capture wall time, including alert persistence. Extraction latency measures iterator work per emitted flow, excluding idle wait. Combined latency sums extraction and detector work. Emit delay uses capture timestamps. Explanation drain is timed separately.

RAM is dashboard process RSS, including queued work during drain. CPU averages and peaks are system-wide. Process CPU percent uses one core as 100%. Peak health values are sampled every 250 ms. An RSS delta is a stability indicator. Compare sustained runs to assess growth. Latency percentiles use at most 8,192 sampled observations per metric. Unavailable readings are reported explicitly.

## Run

| Metric | Value |
|---|---|
| utc | 2026-11-24T20:58:04.628487+00:00 |
| pcap | Unavailable |
| pcap sha256 | Unavailable |
| interface | eth0 |
| requested duration sec | 900.0000 |
| explain min level | high |
| explanation cooldown sec | 30.0000 |
| detector threads | 1 |
| capture elapsed sec | 900.4262 |
| explanation drain sec | 0.0002 |

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
| total packets | 2190 |
| total flows | 318 |
| alert count | 303 |
| packet drop count | 0 |
| packets skipped | 12 |
| packets per sec | 2.4322 |
| flows per sec | 0.3532 |
| replay passes | Unavailable |
| extraction ms / p50 | 0.3039 |
| extraction ms / p95 | 4.1825 |
| extraction ms / max | 42.6802 |
| extraction ms / count | 318 |
| extraction ms / sampled | 318 |
| detector ms / p50 | 10.0683 |
| detector ms / p95 | 27.6770 |
| detector ms / max | 36.3334 |
| detector ms / count | 318 |
| detector ms / sampled | 318 |
| combined ms / p50 | 11.0096 |
| combined ms / p95 | 30.4564 |
| combined ms / max | 59.3031 |
| combined ms / count | 318 |
| combined ms / sampled | 318 |
| emit delay ms / p50 | 0.0000 |
| emit delay ms / p95 | 0.0000 |
| emit delay ms / max | 15476.9240 |
| emit delay ms / count | 318 |
| emit delay ms / sampled | 318 |

## Explainer

| Metric | Value |
|---|---|
| mode | executorch |
| invocation count | 11 |
| skipped count | 0 |
| error count | 0 |
| reused count | 292 |
| last latency ms | 6543.3421 |
| avg latency ms | 6767.8454 |
| ttft ms / p50 | 2143.0775 |
| ttft ms / p95 | 3378.3097 |
| ttft ms / max | 4586.5335 |
| ttft ms / count | 11 |
| ttft ms / sampled | 11 |
| tokens per sec / p50 | 12.0061 |
| tokens per sec / p95 | 12.1056 |
| tokens per sec / max | 12.1252 |
| tokens per sec / count | 11 |
| tokens per sec / sampled | 11 |
| total latency ms / p50 | 6555.6491 |
| total latency ms / p95 | 8042.9999 |
| total latency ms / max | 9258.9211 |
| total latency ms / count | 11 |
| total latency ms / sampled | 11 |
| invocation rate percent | 3.4591 |

## System Health

| Metric | Value |
|---|---|
| start ram mb | 1212.8256 |
| peak ram mb | 2651.5210 |
| end ram mb | 2468.0694 |
| ram delta mb | 1255.2438 |
| cpu avg percent | 7.3806 |
| cpu peak percent | 97.0000 |
| cpu samples | 3595 |
| process cpu percent | 29.3861 |
| start temperature c | 50.7000 |
| peak temperature c | 61.1500 |
| end temperature c | 46.3000 |
| start throttling | throttled=0x0 |
| end throttling | throttled=0x0 |

