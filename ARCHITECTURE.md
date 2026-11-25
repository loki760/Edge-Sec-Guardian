# Edge-Sec-Guardian architecture

The active system is the Phase 1 Option C deployment on Raspberry Pi 5. It runs flow extraction, ML, rules, optional CPU-only Llama explanations and a local dashboard. The historical UNSW-NB15 CSV classifier and Mac Docker setup live in the `main` branch history.

## Capture and alert path

```text
PCAP replay or IPv4 packets on eth0
  → FlowEngine and the ordered 29-feature vector
  → RiskFusionScorer using the versioned detector bundle and flow rules
  → dashboard traffic view and SQLite alert record
  → optional gated explanation queue and local ExecuTorch runner
  → validated explanation and timing saved to that alert record
```

Linux Ethernet capture reads raw frames using `AF_PACKET`. It requests a 16 MiB receive buffer and reports the effective socket value, which was 8 MiB on the Pi. The dashboard separates capture and extraction from scoring and SQLite writes with a bounded 4,096-flow queue. Kernel packet loss and completed-flow queue overflow have separate counters. Replay uses the same extractor and scorer with a local capture file.

[FEATURE_CONTRACT.md](FEATURE_CONTRACT.md) defines the classifier input and metadata fields. The detector bundle includes the ordered feature names, scikit-learn version, and High and Medium thresholds. Scope checks exclude locally addressed management traffic on configured ports, multicast or limited broadcast, and isolated web reply fragments. The [pipeline guide](CIC_IOT_PIPELINE.md#reading-a-dashboard-result) defines the rules. A flagged verdict is decided before explanation generation.

## Explanation and dashboard boundaries

The dashboard serves bundled HTML and JSON from the Pi. SQLite keeps alerts and review feedback. It includes endpoint metadata, so the database is private. The explainer uses a separate allowlist of detector evidence and never receives endpoint addresses or payloads. Its single worker has a bounded 16-slot queue and a 30-second reuse window. The default policy explains High flagged flows. Structured output passes length and safety checks before it is saved, and explanation errors are recorded separately from detection.

ExecuTorch runs the local Llama 3.2 1B Instruct model on the Pi CPU. Ollama is an optional local development backend. Detection can run with explanations disabled. After installation, the runtime needs no remote inference connection.

## Training and evaluation

`build_ciciot_dataset.py` derives labels from capture scenarios and emits the shared 29 features. Feature selection binds the input and split positions to hashes. Benign captures are assigned as whole files, with the local Pi capture pinned to training. Scarce attack families use chronological blocks and a boundary embargo. The trainer fits on training rows, calibrates at the specified validation FPR target and evaluates the untouched test partition. See the [split evidence](reports/FEATURE_SELECTION.md) and [metrics](artifacts/ciciot_metrics.json).

The wheel includes the dashboard asset and exposes `edge-sec-dashboard` and `edge-sec-benchmark`. See the [README](README.md) for installation and [Engineering Report](ENGINEERING_REPORT.md) for measured results and deployment limits.
