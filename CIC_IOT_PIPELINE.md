# CIC-IoT-2023 flow classification on Windows

From PowerShell in this checkout, use the project virtual environment. Place the original packet captures under `data\raw\ciciot2023`. Folder and file names identify capture scenarios. Keep benign recordings from independent sessions in separate files. Capture-level labels can include background traffic.

```powershell
Set-Location D:\AISOC
$python = '.\.venv\Scripts\python.exe'
& $python build_ciciot_dataset.py --pcap-dir data/raw/ciciot2023 --output data/processed/ciciot_flows.csv --max-flows-per-file 15000 --max-packets-per-file 250000
& $python eda_ciciot.py --input data/processed/ciciot_flows.csv --report reports/CIC_IOT_2023_EDA.md --plot-dir reports/eda
& $python select_ciciot_features.py --input data/processed/ciciot_flows.csv --output artifacts/ciciot_selected_features.json --report reports/FEATURE_SELECTION.md
& $python train_ciciot_model.py --input data/processed/ciciot_flows.csv --features artifacts/ciciot_selected_features.json --model artifacts/ciciot_model.pkl --metrics artifacts/ciciot_metrics.json --report reports/MODEL_COMPARISON.md
& $python -m unittest -v
& $python dashboard.py --replay-pcap data/raw/ciciot2023/Recon-PortScan.pcap --model artifacts/ciciot_model.pkl --host 127.0.0.1 --interval 0
```

Run the commands in sequence and inspect any nonzero exit before continuing. Open `http://127.0.0.1:8080/` during replay. The packet and flow limits apply separately to each input capture during dataset construction. Counts and model quality depend on which portions of the captures were sampled. See the generated EDA, feature-selection and model-comparison reports for this run. Model evaluation covers ML-only predictions at the saved high threshold. The synthetic integration test uses small temporary captures for wiring checks.

## Reading a dashboard result

The dashboard loads a trusted project-generated pickle once at startup. Each completed flow receives the fitted model’s attack probability from its saved ordered numeric feature columns. Endpoints and timestamps go only to the dashboard and rule logic. A probability at or above the stored high threshold contributes an ML signal. A probability between the stored medium and high thresholds gives Medium risk without an alert.

Any of the following heuristic rule signals also raises an alert.

| Rule | Condition |
| --- | --- |
| Destination port burst | At least 8 distinct destination ports in completed TCP or UDP flows from one source across a 10-second window of flow-end times. The detector retains up to 2,000 recently observed sources and 64 ports per source. |
| SYN-heavy TCP | At least 10 forward TCP packets, SYN ratio at least 0.8 and ACK ratio at most 0.1. |
| Extreme packet rate | At least 10 packets in both directions combined and at least 1,000 packets per second. |

`signals` identifies each ML or rule trigger. `prediction` is the fused binary verdict, with 1 meaning Flagged. `ml_probability` is the model output. `risk_score` equals that probability unless a rule triggers, which sets it to 1. A fused risk score is a detection policy value. Rule state follows completed flows, and resets on each replay pass. Late flows ending outside the current 10-second window cannot contribute to a port burst. Flow batching and source eviction can affect alert timing.

The existing `--demo-rules` option still runs the separate demonstration thresholds. Omitting both scoring options gives an unscored replay. The scorer also supports programmatic ML-only operation with `enable_rules=False` and rules-only operation with `bundle=None`. Historical alerts and feedback persist in the local SQLite database. The traffic view keeps the latest 50 flows.

Raspberry Pi 5 capture, device inference benchmarks and an ExecuTorch conversion or native runtime require separate implementation and device testing.
