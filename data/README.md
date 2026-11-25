# Data for the CIC-IoT-2023 detector

The active pipeline reads labeled PCAP and PCAPNG captures under `data/raw/ciciot2023/`. It writes the shared 29-feature flow CSV and its capture manifest under `data/processed/`. Keep raw captures and generated flow CSVs out of Git. The repository includes a small synthetic fixture at `data/nf_test_sample.pcap` for testing.

The reported dataset includes a local capture, `BenignTraffic4.pcap`, pinned wholly to training. The [pipeline guide](../CIC_IOT_PIPELINE.md) gives build commands and the [feature selection report](../reports/FEATURE_SELECTION.md) records the CSV hash and split membership. The [Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/iotdataset-2023.html) gives CIC-IoT-2023 provenance and citation details.

The historical UNSW-NB15 CSV baseline and its data documentation are available in `main`. The Pi detector uses the CIC flow feature contract.
