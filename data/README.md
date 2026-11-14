# UNSW-NB15 data preparation

Use the original named training and testing CSV splits from the
[UNSW dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
Its **HERE** link leads to the
[official SharePoint collection](https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS).
Do not use third-party mirrors, the four larger raw CSV parts, or a new split.

## Acquisition status (14 November 2026)

Both named CSV files are present in `data/raw/` and passed schema, row-count,
label, and hash verification. They were used for the completed training and
held-out evaluation. The measured counts and hashes are preserved below.

The known acquisition path is the official UNSW-NB15 dataset page → its linked
SharePoint collection → CSV Files → Training and Testing Sets. Earlier automated
access encountered sign-in/access-denied responses; the verifier subsequently
found files already placed locally.

**User confirmation still required:** the actual retrieval date, exact per-file
source URLs (or folder/archive details if direct URLs are unavailable), and how
the files were downloaded and placed locally. The verification timestamp below
is not a download timestamp. Local hashes fingerprint the bytes; they do not
independently establish official origin, and no publisher hash is recorded.

Both files contain 45 columns: `id`, the 42 features in
`preprocess.FEATURE_COLUMNS`, `attack_cat`, and `label`.

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
   paths `data/raw/UNSW_NB15_training-set.csv` and
   `data/raw/UNSW_NB15_testing-set.csv`. Keep original names and bytes. Record
   the actual retrieval date and official per-file source URLs here when available.
4. Run `python download_data.py`. Existing files are verified in place, never
   overwritten. Success requires all schema/value checks, both binary labels,
   and the exact row count for each split. Success prints SHA-256 values and
   appends local measurements to the managed verification section below.
5. Review the resulting provenance section, add the manual retrieval date/source
   confirmation before using newly acquired files for training.

If the browser provides direct official HTTPS CSV download URLs usable without
authentication, the same script can acquire missing files:

```sh
python download_data.py --training-url 'OFFICIAL_TRAINING_FILE_URL' --testing-url 'OFFICIAL_TESTING_FILE_URL'
```

These are explicit URL placeholders. The collection link is a folder, not a
CSV endpoint, so the script does not guess a per-file URL or download the whole
collection. The script checks the initial and final URLs for official HTTPS
hosts; it does not validate intermediate redirects before following them.
Sign-in pages, invalid data, and a final URL outside the allowed hosts fail visibly.
Validated temporary bytes are published without replacing existing files. If
one split fails, the script exits 1; any successfully acquired split is retained
for the next run. An invalid existing file is reported, never silently replaced.
The script requires pandas and scikit-learn because it uses the shared loader.

<!-- verification:start -->

Successful local verification: 2026-11-14T16:58:44.210696+00:00

- `UNSW_NB15_training-set.csv`: 175,341 rows, 45 columns, 32293018 bytes; labels {1: 119341, 0: 56000}.
  SHA-256: `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`.
  Acquisition: Existing file; manual placement/source must be confirmed by the operator.
- `UNSW_NB15_testing-set.csv`: 82,332 rows, 45 columns, 15380800 bytes; labels {1: 45332, 0: 37000}.
  SHA-256: `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`.
  Acquisition: Existing file; manual placement/source must be confirmed by the operator.
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

All 14 preprocessing tests passed within the 58-test ARM64 Docker suite using
Python 3.13.18, pandas 3.1.1 and scikit-learn 1.9.1. Final review independently
verified both files against the measurements above and reproduced the saved
held-out metrics. Real classifier-to-Llama integration also passed; see
[the project README](../README.md).

The existing `.gitignore` excludes `data/raw/` and `artifacts/`. Keep downloaded
CSVs and generated models out of commits. Tracked `data/sample.pcap` and
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
