# CIC-IoT-2023 flow classification on Windows

From PowerShell in this checkout, use the project virtual environment. Place the original packet captures under `data\raw\ciciot2023`. Folder and file names identify capture scenarios. Keep benign recordings from independent sessions in separate files. Capture-level labels can include background traffic.

```powershell
Set-Location D:\AISOC
$python = '.\.venv\Scripts\python.exe'
& $python build_ciciot_dataset.py --pcap-dir data/raw/ciciot2023 --output data/processed/ciciot_flows.csv --max-flows-per-file 15000 --max-packets-per-file 250000
& $python eda_ciciot.py --input data/processed/ciciot_flows.csv --report reports/CIC_IOT_2023_EDA.md --plot-dir reports/eda
& $python select_ciciot_features.py --input data/processed/ciciot_flows.csv --output artifacts/ciciot_selected_features.json --report reports/FEATURE_SELECTION.md
& $python train_ciciot_model.py --input data/processed/ciciot_flows.csv --features artifacts/ciciot_selected_features.json --model artifacts/ciciot_model.pkl --metrics artifacts/ciciot_metrics.json --report reports/MODEL_COMPARISON.md --target-fpr 0.015 --target-fpr 0.020 --target-fpr 0.025
& $python -m unittest -v
& $python dashboard.py --replay-pcap data/raw/ciciot2023/Recon-PortScan.pcap --model artifacts/ciciot_model.pkl --host 127.0.0.1 --interval 0
```

Run the commands in sequence and inspect any nonzero exit before continuing. Open `http://127.0.0.1:8080/` during replay. The packet and flow limits apply separately to each input capture during dataset construction. Counts and model quality depend on which portions of the captures were sampled. See the generated EDA, feature-selection and model-comparison reports for this run. Model evaluation covers ML-only predictions at the saved high threshold. The synthetic integration test uses small temporary captures for wiring checks.

### Retraining with the local Pi capture

After changing the flow CSV, rerun feature selection to bind the manifest to its new SHA256.
For the dataset containing `BenignTraffic4.pcap`, the following commands keep that file
entirely in training and retain all 29 features. Validation and test each use a different
whole benign capture. The trainer reconstructs this split from the manifest and checks its hashes.

```powershell
& $python select_ciciot_features.py --input data/processed/ciciot_flows.csv --train-capture BenignTraffic4.pcap --all-features
& $python train_ciciot_model.py --input data/processed/ciciot_flows.csv --target-fpr 0.020
```

## Reading a dashboard result

The dashboard loads a trusted project-generated pickle once at startup. Each completed flow receives the fitted model’s attack probability from its saved ordered numeric feature columns. Endpoints and timestamps go only to the dashboard and rule logic. A probability at or above the stored high threshold contributes an ML signal. A probability between the stored medium and high thresholds gives Medium risk without an alert.

Any of the following heuristic rule signals also raises an alert.

| Rule | Condition |
| --- | --- |
| Destination port burst | At least 8 distinct destination ports within a 10-second window per source IP, destination IP and protocol. TCP flows must begin with SYN without ACK. The detector retains up to 2,000 groups and 64 ports per group. |
| SYN-heavy TCP | At least 10 forward TCP packets, SYN ratio at least 0.8 and ACK ratio at most 0.1. |
| Extreme packet rate | At least 10 forward TCP packets and 1,000 packets per second, plus a SYN-heavy pattern or the asymmetric opening-SYN condition below. |
| UDP or ICMP flood pattern | At least 100 forward packets, positive duration, and at most one reverse packet per ten forward packets. Flag at 1,000 forward packets per second, or at 100 forward packets per second when the flow spans at least one second. Bidirectional UDP/443 is excluded from this rule. |

For the asymmetric TCP rate condition, reverse packets must be at most 10% of forward packets, and ACK flags must appear on at most 10% of all packets. The UDP and ICMP rules evaluate individual completed flows. Scope checks leave local SSH and dashboard traffic, multicast and limited broadcast, and isolated web reply fragments unscored.

`signals` identifies each ML or rule trigger. `prediction` is the fused binary verdict, with 1 meaning Flagged. `ml_probability` is the model output. `risk_score` equals that probability unless a rule triggers, which sets it to 1. A fused risk score is a detection policy value. Rule state follows completed flows, and resets on each replay pass. Late flows ending outside the current 10-second window cannot contribute to a port burst. Flow batching and source eviction can affect alert timing.

The existing `--demo-rules` option still runs the separate demonstration thresholds. Omitting both scoring options gives an unscored replay. The scorer also supports programmatic ML-only operation with `enable_rules=False` and rules-only operation with `bundle=None`. Historical alerts and feedback persist in the local SQLite database. The traffic view keeps the latest 50 flows.

The physical Pi 5 runs and their measured limits are documented in the [benchmark directory](reports/benchmarks/) and [Engineering Report](ENGINEERING_REPORT.md).
