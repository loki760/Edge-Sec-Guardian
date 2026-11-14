# UNSW-NB15 data preparation

Use the original named training and testing CSV splits from the
[UNSW dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
Its **HERE** link leads to the
[official SharePoint collection](https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS).
Do not use third-party mirrors, the four larger raw CSV parts, or a new split.

## Acquisition status (14 November 2026)

Automatic acquisition was blocked. The linked collection redirected the web
fetcher to Microsoft sign-in. An independent `curl -I -L --max-time 30` request
returned SharePoint access denied (`x-msdavext_error: 917656`) after redirects.
No official CSV bytes were obtained. No substitute data was downloaded.

| Required local file | Expected records | Measured records | SHA-256 |
| --- | ---: | --- | --- |
| `data/raw/UNSW_NB15_training-set.csv` | 175,341 | Pending download | Unavailable |
| `data/raw/UNSW_NB15_testing-set.csv` | 82,332 | Pending download | Unavailable |

Both official files must contain 45 columns: `id`, the 42 features in
`preprocess.FEATURE_COLUMNS`, `attack_cat`, and `label`. The expected record
counts above are from UNSW, not measurements made in this worktree. Retrieval
dates, bytes, checksums, and real label counts remain pending. No official
publisher SHA-256 was available on the dataset page; locally computed hashes
fingerprint the acquired bytes and do not independently establish authenticity.

## Manual download procedure

1. Open the UNSW dataset page above in a browser and follow **HERE** to the
   official collection. Sign in if required and if you have authorized access.
   If access is denied, request access from the dataset owner using the contact
   information on the UNSW page. Do not substitute another source.
2. In that collection, locate the Training and Testing Sets files and download
   exactly `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`. If the
   browser downloads a ZIP, extract those two members without editing them.
   Do not open and re-save the CSVs in spreadsheet software.
3. From the repository root run `mkdir -p data/raw`, then place the files at the
   exact paths in the table. Keep original names and bytes. Record the actual
   retrieval date and official per-file source URLs here when available.
4. Run `python download_data.py`. Existing files are verified in place, never
   overwritten. Success requires all schema/value checks, both binary labels,
   and the exact row count for each split. Success prints SHA-256 values and
   appends local measurements to the managed verification section below.
5. Review the resulting provenance section, add the manual retrieval date/source
   confirmation, and hand the verified paths to the ML Engineer before training.

If the browser provides direct official HTTPS CSV download URLs usable without
authentication, the same script can acquire missing files:

```sh
python download_data.py --training-url 'OFFICIAL_TRAINING_FILE_URL' --testing-url 'OFFICIAL_TESTING_FILE_URL'
```

These are explicit URL placeholders. The collection link is a folder, not a
CSV endpoint, so the script does not guess a per-file URL or download the whole
collection. Direct URLs must be on UNSW hosts or `unsw-my.sharepoint.com`;
sign-in pages, invalid data, and redirects away from those hosts fail visibly.
Validated temporary bytes are published without replacing existing files. If
one split fails, the script exits 1; any successfully acquired split is retained
for the next run. An invalid existing file is reported, never silently replaced.
The script requires pandas and scikit-learn because it uses the shared loader.

<!-- verification:start -->
No successful local official-split verification yet.
<!-- verification:end -->

## Loader and preprocessing

`load_csv(path, require_label=False)` returns `(X, y)` with 42 ordered raw feature
columns, preserving row order. Training/evaluation use `require_label=True` and
receive integer binary labels. Prediction ignores optional `id`, `attack_cat`,
and `label` metadata, and returns `y=None`. Those columns never enter features.
Numeric features must be finite; category strings are stripped while preserving
case, `None`, and `-`. Invalid input raises clear errors, with zero-based data
row indices where applicable. The legacy `data/features.csv` is incompatible.

`build_preprocessor()` creates an unfitted `ColumnTransformer` with numeric
passthrough and sparse `OneHotEncoder(handle_unknown="ignore")` encoding.
The ML pipeline alone fits it, using training data only. Keep the official
split membership intact; do not combine, resample, or export encoded CSVs.

Run the synthetic unit tests (no network or real benchmark data required):

```sh
python -m unittest test_preprocess -v
```

Development verification used Python 3.14.3, pandas 3.1.1 and scikit-learn 1.9.1
in `/tmp/edge-data-venv`, without changing global dependency files. These are
observed test versions, not shared dependency pins. CLI/DevOps owns final pins
and Linux ARM64 compatibility verification.

Observed result: all 13 synthetic unit tests passed. Running `download_data.py`
without the missing official files returned exit 1 and clear placement errors.
Real-data verification and full ML/LLM integration have not run.

Keep downloaded CSVs and generated artifacts out of commits. This task leaves
the shared `.gitignore` under CLI/DevOps ownership; that owner must add
`data/raw/` before broad staging or integration. Stage only explicit owned source
and documentation paths in the meantime. Existing `data/sample.pcap` and
`data/features.csv` belong to the separate legacy PCAP demonstration.

## Attribution and use

The dataset page grants academic research use, requires agreement with the
authors for commercial use, and requests citation of the following five works.
Consult that page for the source terms and linked publications.

1. Nour Moustafa and Jill Slay. *UNSW-NB15: a comprehensive data set for network
   intrusion detection systems (UNSW-NB15 network data set).* MilCIS, IEEE, 2015.
2. Nour Moustafa and Jill Slay. *The evaluation of Network Anomaly Detection
   Systems: Statistical analysis of the UNSW-NB15 data set and the comparison
   with the KDD99 data set.* Information Security Journal: A Global Perspective,
   2016, pp. 1–14.
3. Nour Moustafa et al. *Novel geometric area analysis technique for anomaly
   detection using trapezoidal area estimation on large-scale networks.*
   IEEE Transactions on Big Data, 2017.
4. Nour Moustafa et al. *Big data analytics for intrusion detection system:
   statistical decision-making using finite dirichlet mixture models.*
   Data Analytics and Decision Support for Cybersecurity, Springer, 2017,
   pp. 127–156.
5. Mohanad Sarhan, Siamak Layeghy, Nour Moustafa, and Marius Portmann.
   *NetFlow Datasets for Machine Learning-Based Network Intrusion Detection
   Systems.* Big Data Technologies and Applications, BDTA/WiCON 2020
   proceedings, Springer Nature, p. 117.
