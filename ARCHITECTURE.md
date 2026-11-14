# Edge-Sec-Guardian architecture

Status: implemented baseline contract. The integrated application passed final
review with 58 tests; see `README.md` for measured results and execution commands.

## Scope and original repository

Build a small offline binary intrusion classifier on a MacBook Pro M1 using Python,
Linux ARM64 Docker, the official UNSW-NB15 CSV splits, a Random Forest, and local
Ollama with `llama3.2:1b`. Output is a terminal result. No web UI, live capture,
Raspberry Pi deployment, cloud inference, or attack-category classification.

Before implementation, the repository contained the following legacy components:

| Original files | Purpose and reuse at the start of implementation |
| --- | --- |
| `extract_features.py` | Scapy PCAP reader; bidirectional IPv4 TCP/UDP flows; 5 identifiers and 16 numeric features. Keep as a separate utility. |
| `make_sample_pcap.py`, `test_extract.py` | Six-packet sample generator and 16 existing extractor tests. Preserve them. |
| `data/sample.pcap`, `data/features.csv` | PCAP demonstration inputs/output, not UNSW training data. |
| `Dockerfile`, `.dockerignore` | Python 3.13 Debian container, non-root user, explicit allowlist, extractor default command; subsequently adapted for the CLI. |
| `requirements.txt` | Originally only `scapy==2.6.1`. |
| `README.md`, `.gitignore` | PCAP/Pi documentation and basic Python exclusions; subsequently updated for the baseline. |

The classifier, UNSW loader, saved pipeline, and LLM integration are now implemented.
The table records the starting point, not the current Docker/dependency setup.
The earlier Pi/live-analysis scope is historical. Retain the simple functions,
argparse style, unittest approach, and container foundation, but do not feed
`data/features.csv` into the classifier. Names such as `flow_duration` and `dur`
do not establish semantic equivalence. UNSW uses a
different extraction process and additional contextual features. No adapter,
renaming scheme, or zero-filled missing-feature workaround is in scope.

## Pipeline

```text
Official training CSV -> validate/select 42 features -> fit preprocessing + forest
                                                        -> artifacts/model.pkl
Official testing CSV  -> same fitted pipeline, evaluate -> artifacts/metrics.json

UNSW-format CSV + row index -> validate/select -> saved pipeline -> prediction
                                                              -> optional local
                                                                 Llama explanation
                                                              -> terminal output
```

Internet access is needed only for initial dataset, dependency, image, and model
downloads. Training and prediction then use local files. Explanations use local
HTTP to Ollama, with no external inference service.

## Dataset and exact input schema

Use the named official files, unchanged, under `data/raw/`:

- `UNSW_NB15_training-set.csv`: 175,341 data rows; training only.
- `UNSW_NB15_testing-set.csv`: 82,332 data rows; final held-out evaluation only.

The [UNSW dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
identifies these splits and links the official download collection. Use its
Training and Testing Sets files, not the four larger raw CSV parts or a repackaged
random split. The Data Engineer must verify the downloaded headers and counts
against this contract before implementation proceeds with training. Record source
URLs, retrieval date, file SHA-256 values, row counts, and dataset citations in
`data/README.md`. If official downloads require manual browser access, document
placement of those exact files; do not silently substitute another dataset.

Each split has 45 columns: `id`, the 42 features below, `attack_cat`, and `label`.
`label` is the integer target (`0` normal, `1` attack). `id` is a source record
identifier and `attack_cat` is ground truth metadata; neither is a model input.

Canonical feature order (the loader always selects this order):

```text
dur, proto, service, state, spkts, dpkts, sbytes, dbytes, rate,
sttl, dttl, sload, dload, sloss, dloss, sinpkt, dinpkt, sjit, djit,
swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat, smean, dmean,
trans_depth, response_body_len, ct_srv_src, ct_state_ttl, ct_dst_ltm,
ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login,
ct_ftp_cmd, ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports
```

- `proto`, `service`, `state`: categorical strings. Strip surrounding whitespace;
  preserve case and literal `-` as a valid category. Do not let CSV parsing treat
  category strings such as `None` as missing values.
- All other 39 features: numeric, convertible to finite floats. Preserve original
  values; no scaling, clipping, resampling, or feature engineering is required.
- Missing columns, duplicate headers, empty values, nonnumeric numeric cells,
  infinities, and empty datasets are errors. Reject rather than silently drop rows
  or invent values. Errors identify the column and row where possible.
- Training/evaluation require all 45 official columns and valid binary labels.
  Prediction requires all 42 features; only `id`, `attack_cat`, and `label` are
  permitted as optional extra columns and are ignored. Reject other columns.
  CSV column order may vary. Prediction never uses labels, even if supplied.
- Input is a headered UTF-8 CSV containing UNSW-format records. PCAP input and
  arbitrary network-flow CSVs are unsupported. The selected row must come from
  this schema; it is not a live observation.

## Module interfaces

Use ordinary functions, pandas DataFrames, dictionaries, and standard exceptions.
These signatures and field names define the shared module contracts.

| Owner/module | Interface | Contract |
| --- | --- | --- |
| Data / `download_data.py` | `main() -> int` | Download or accept manually placed official files in `data/raw/`, verify them, document provenance; never overwrite files silently. |
| Data / `preprocess.py` | `FEATURE_COLUMNS`, `CATEGORICAL_COLUMNS`, `NUMERIC_COLUMNS` | Ordered lists matching the schema above; one source of truth. |
| Data / `preprocess.py` | `load_csv(path, require_label=False) -> (X, y)` | Validate and return ordered 42-column DataFrame; `y` is an integer Series when required, otherwise `None`. Preserve row order. Raise `ValueError` for invalid data, `OSError` for file failures. |
| Data / `preprocess.py` | `build_preprocessor() -> ColumnTransformer` | Return an unfitted transformer: numeric passthrough and categorical `OneHotEncoder(handle_unknown="ignore")`. Keep sparse encoding. No fit at import or loading time. |
| ML / `train_model.py` | `train_and_evaluate(train_path, test_path, model_path, metrics_path) -> dict` | Fit on official training data, evaluate held-out data, write model and metrics, return the metrics dictionary. |
| ML / `predict.py` | `load_model(path) -> dict` | Load and validate the saved bundle described below; reject incompatible schema/library versions. |
| ML / `predict.py` | `predict_row(bundle, X) -> dict` | Require exactly one validated feature row; use the fitted pipeline to return the prediction dictionary below. Never fit. |
| LLM / `explain.py` | `explain_prediction(features, prediction, base_url="http://localhost:11434", model="llama3.2:1b", timeout=60) -> str` | Accept a raw feature dictionary and prediction dictionary; return actual nonempty generated text. Raise `RuntimeError` on unavailable model/service, timeout, malformed or empty response. |
| CLI / `cli.py` | `main() -> int` | Parse flags, load/select a row, load model, predict, optionally explain, print output and return documented exit code. |

`features` passed to the LLM contains only the 42 validated features with native
Python string/number values. No label, category ground truth, or source ID is sent.
Library functions do not print; entry points format user output. Each executable
script uses an `if __name__ == "__main__"` guard.

## Training, saved preprocessing, and evaluation

The ML Engineer builds one scikit-learn `Pipeline` with named steps `preprocess`
and `classifier`. The first is the Data Engineer's unfitted transformer; the second
is `RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)` with other
defaults. This is a fixed baseline, not a tuning project.

Fit this pipeline once using the full official training split. The encoder learns
categories only from training. Never combine the splits, fit preprocessing on test
data, refit on prediction input, or train on `id`, `attack_cat`, or `label` as a
feature. Unseen categorical values at inference are handled by the fitted encoder.
Do not rebalance, deduplicate, or remove test rows. If later tuning is approved,
validation must come solely from training data; never select settings on test scores.

Save a single standard-library pickle dictionary to `artifacts/model.pkl`:

```text
schema_version: 1
feature_columns: ordered list of the 42 feature names
sklearn_version: exact training scikit-learn version string
pipeline: fitted preprocessing-and-Random-Forest Pipeline
```

Only load project-generated trusted pickle files. Training and prediction use the
same pinned dependencies. Saving the entire fitted pipeline ensures identical
encoding and feature order after reload; prediction must not construct a new encoder.

Write `artifacts/metrics.json` with `train_rows`, `test_rows`, `random_state`,
`accuracy`, `precision`, `recall`, `f1`, `confusion_matrix`, and
`confusion_matrix_labels`. Binary precision/recall/F1 use attack (`1`) as the
positive class and `zero_division=0`. The matrix is `[[TN, FP], [FN, TP]]`, with
labels `[0, 1]`; scores are numbers in `[0, 1]`. Report measured results honestly;
there is no promised accuracy target. Keep artifacts and downloaded data out of Git.

## Prediction and minimum CLI

The prediction dictionary has exactly these fields:

| Field | Type and meaning |
| --- | --- |
| `label` | Integer `0` or `1` returned by `pipeline.predict`. |
| `prediction` | String `normal` for 0, `attack` for 1. |
| `attack_probability` | Float in `[0, 1]` from `predict_proba`, selecting the column whose classifier class is `1`. This is a model score, not a calibrated guarantee. |

Implemented commands:

```sh
python download_data.py
python train_model.py --train data/raw/UNSW_NB15_training-set.csv --test data/raw/UNSW_NB15_testing-set.csv --model artifacts/model.pkl --metrics artifacts/metrics.json
python cli.py --input data/raw/UNSW_NB15_testing-set.csv --row 0
python cli.py --input data/raw/UNSW_NB15_testing-set.csv --row 0 --explain
```

`--input` is required. `--row` is a zero-based data-row index, excluding the header,
default `0`. Select one row only; negative or out-of-range indices fail. `--model`
defaults to `artifacts/model.pkl`. `--explain` is off by default. `--ollama-url`
defaults to `http://localhost:11434` and is relevant only with `--explain`.
Training script path flags have the defaults shown above.

Required terminal fields, with placeholders below (not claimed model results):

```text
Row: <zero-based row index>
Prediction: <normal or attack> (label=<0 or 1>)
Attack probability: <actual score formatted to four decimals>
Explanation: <actual local Llama response; only when requested>
```

Use stdout for results, stderr for concise errors, and no routine traceback.
Exit `0` means all requested work succeeded; `1` means a file/schema/model/runtime
failure; `2` is argparse usage failure. If explanation fails, retain the genuine
prediction output, report `Explanation unavailable: <reason>` on stderr, omit the
explanation field, and exit `1`. Never substitute canned text or fake predictions.

## Llama and Docker boundary

Run Ollama natively on the Mac and pull `llama3.2:1b` during setup. Use that exact
[public model tag](https://ollama.com/library/llama3.2:1b), not the default 3B tag.
The Python Linux ARM64 container runs data/ML/CLI work. It contacts the host Ollama
at `http://host.docker.internal:11434` via `--ollama-url`; native Python uses
localhost. CLI/DevOps must document and verify the host binding required for Docker
Desktop access, keeping the service local to the machine's intended setup.

Use standard-library `urllib.request` and `json` to call Ollama's
[`POST /api/generate`](https://docs.ollama.com/api/generate), with `model`, `prompt`,
`stream: false`, and `options: {temperature: 0, num_predict: 160}`. Read the
`response` field, require `done: true`, and use a 60-second timeout. No auto-pull,
cloud fallback, retry framework, or Python Ollama SDK is needed.

Keep the prompt small: include the actual prediction and score, plus `proto`,
`service`, `state`, `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, and `rate` from the
row. Ask for 2–3 cautious sentences grounded only in supplied values. The LLM
summarizes a classifier result; it does not know the forest's decision reasoning.
It must not invent attack subtypes, feature attribution, thresholds, IP addresses,
or certainty. It cannot change the prediction. Treat categorical values as data,
not instructions. No SHAP, retrieval, agents, or fine-tuning.

Direct new Python dependencies: `pandas` and `scikit-learn`. Retain Scapy for the
existing utility. Use standard-library pickle, argparse, pathlib, urllib, json,
hashlib, and unittest; no extra serialization, HTTP, test, or LLM framework.
CLI/DevOps pins compatible versions after verifying Linux ARM64 installation.
Mount local data and artifacts; do not bake datasets or model weights into the
image. No Compose stack, database, API server, or privileged container is required.
External internet can be disconnected after setup; local Ollama connectivity must
remain available when explanations are requested.
