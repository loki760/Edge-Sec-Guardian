# Edge-Sec-Guardian

Edge-Sec-Guardian is the Phase 1 submission for Bharat AI-SoC Challenge Problem Statement 3, Option C. It detects suspicious IPv4 flows on a Raspberry Pi 5 and shows alerts in a local dashboard. A 29-feature Histogram Gradient Boosting model and network rules make the detection decision. An optional local ExecuTorch Llama worker explains High alerts for review. The installed system can run without internet access.

- [Engineering report](ENGINEERING_REPORT.md)
- [Architecture](ARCHITECTURE.md) and [feature contract](FEATURE_CONTRACT.md)
- [Physical Pi benchmarks and inline stress test](reports/benchmarks/)
- [Dataset, training and evaluation guide](CIC_IOT_PIPELINE.md)

## Install on Raspberry Pi 5

The recorded configuration uses 64-bit ARM Linux, Python 3.13.5, scikit-learn 1.9.1, and ExecuTorch 1.6.0. Run `bash scripts/setup_pi5.sh` from a source checkout to provision core dependencies. For a wheel-only installation, prepare the virtual environment and its dependencies separately. Stage the following files inside your project directory:

- `edge_sec_guardian-0.1.0-py3-none-any.whl`
- `artifacts/ciciot_model.pkl`, a trusted bundle trained with scikit-learn 1.9.1
- For explanations, `models/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte` and its matching `models/tokenizer.model`, plus an ARM64 ExecuTorch installation with the LLM runner bindings

Build a wheel from the repository with `python -m pip wheel --no-deps --wheel-dir artifacts/wheels .`. With dependencies and model files staged, install the wheel on the Pi from the local directory:

```sh
.venv/bin/python -m pip install --no-index --no-deps ./edge_sec_guardian-0.1.0-py3-none-any.whl
```

## Run offline

Start with a local capture file. Open `http://127.0.0.1:8080` on the Pi or use SSH port forwarding.

```sh
.venv/bin/edge-sec-dashboard --replay-pcap data/nf_test_sample.pcap \
  --model artifacts/ciciot_model.pkl --host 127.0.0.1 --interval 0
```

For live capture on an authorized gateway or mirror interface, use its LAN-facing interface name. Raw capture requires elevated network permissions. In this example the interface is `eth0`.

```sh
sudo .venv/bin/edge-sec-dashboard --interface eth0 --host 127.0.0.1 \
  --alerts-db artifacts/alerts.db --model artifacts/ciciot_model.pkl \
  --explainer executorch \
  --llama-model models/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte \
  --llama-tokenizer models/tokenizer.model
```

Use `--explainer none` for detection alone. See `edge-sec-benchmark --help` for PCAP replay and timed live measurements. The dashboard stores alerts and Confirm/Dismiss feedback in local SQLite. Network endpoints are retained in that database, so keep it private.

## Verified results

| Physical Pi benchmark | Packets/s | Detector p95 | Llama p50 TTFT | Llama p50 decode | Peak RSS | Peak CPU temperature |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [Fast path PCAP replay](reports/benchmarks/benchmark_pi5_fast.md) | 758.82 | 3.86 ms | — | — | 226.16 MB | 52.35 °C |
| [ExecuTorch PCAP replay](reports/benchmarks/benchmark_pi5_executorch.md) | 212.69 | 27.29 ms | 1.96 s | 12.23 tokens/s | 2,355.31 MB | 68.30 °C |
| [15-minute live capture](reports/benchmarks/benchmark_pi5_sustained_15m.md) | 2.43 | 27.68 ms | 2.14 s | 12.01 tokens/s | 2,651.52 MB | 61.15 °C |

The 15-minute run used live Ethernet and local inference. All three runs reported `throttled=0x0` at the start and end. The separate inline Chrome and YouTube rerun reported zero kernel packet drops, zero scoring-queue drops and 13 ML-only High alerts among 4,727 observed scored flows. Site attribution for those 13 records was unavailable. [Inline comparison](reports/benchmarks/inline_stress_comparison.md)

The deployed classifier measured 99.6575% precision, 48.1708% recall and 0.1506% FPR on its labeled holdout. The [Engineering Report](ENGINEERING_REPORT.md) gives split membership, threshold selection, per-family recall and limitations.

Run the repository tests on Windows with `.\.venv\Scripts\python.exe -m unittest -v` or on Linux with `.venv/bin/python -m unittest -v`. Tests use offline packet fixtures and mocked explanation backends.
