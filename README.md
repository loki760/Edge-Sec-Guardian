# Edge-Sec-Guardian

Offline binary intrusion classification for UNSW-NB15 CSV records: a saved
Random Forest pipeline predicts `normal` or `attack`, and optional native Ollama
`llama3.2:1b` summarizes that result in the terminal. The Python container targets
Linux ARM64 on a MacBook Pro M1. Training and prediction use local files;
explanations use local HTTP. Internet access is needed for setup downloads only.

## Verified baseline

The complete pipeline is integrated on `feat/baseline-mvp`: official UNSW-NB15
CSV → preprocessing → Random Forest → optional local Llama 3.2 1B → CLI.
All **58 tests pass in ARM64 Docker**. Training used 175,341 official training
records; evaluation used the separate 82,332-record held-out test split.

| Held-out metric | Value |
| --- | ---: |
| Accuracy | 0.870670 |
| Attack precision | 0.817352 |
| Attack recall | 0.985286 |
| Attack F1 | 0.893497 |
| False-positive rate | 26.98% |

The confusion matrix is `[[27019, 9981], [667, 44665]]` (rows: actual normal,
attack; columns: predicted normal, attack). There are **9,981 false positives
among 37,000 benign test records**. This substantial false-positive rate is a
baseline limitation; benchmark results do not establish live-network performance.

Docker prediction on test row 0 returned `attack` with score `0.7849`, and a real
local Llama explanation was generated from that prediction. Dataset files and
trained artifacts remain local and are not included in Git. See
[data/README.md](data/README.md) for acquisition, verified hashes, attribution,
and source details still requiring user confirmation.

## Native Python setup

Use Python 3.11–3.14; Docker below supplies Python 3.13. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v
```

Direct dependencies are Scapy 2.6.1 (legacy utility), pandas 3.1.1 and
scikit-learn 1.9.1. Use the same pins for training and prediction; the artifact
records the exact scikit-learn version, and incompatible artifacts are rejected.
Only load trusted project-generated pickle files.

Download the original named splits from the official UNSW collection using the
procedure in [data/README.md](data/README.md). Preserve their bytes and membership;
place them under `data/raw/`, then verify them:

```sh
mkdir -p data/raw artifacts
python download_data.py
```

To reproduce the baseline, train and evaluate on the official splits. If a trusted
model already exists, skip training and run prediction:

```sh
python train_model.py \
  --train data/raw/UNSW_NB15_training-set.csv \
  --test data/raw/UNSW_NB15_testing-set.csv \
  --model artifacts/model.pkl --metrics artifacts/metrics.json
python cli.py --input data/raw/UNSW_NB15_testing-set.csv --row 0
```

The full training split alone fits preprocessing and the forest. The unchanged
test split is evaluation-only. The pipeline and measured metrics persist under
`artifacts/`. No accuracy target or demonstration score is hard-coded.

## One-record CLI

```sh
python cli.py --input data/raw/UNSW_NB15_testing-set.csv
python cli.py --input data/raw/UNSW_NB15_testing-set.csv --row 10 --model artifacts/model.pkl
python cli.py --input data/raw/UNSW_NB15_testing-set.csv --row 10 --explain
python cli.py --help
```

`--input` is required. `--row` defaults to zero and counts data rows, excluding
the header. Only one row is predicted. The shared loader validates the whole CSV;
an invalid unselected row also causes rejection. Negative or out-of-range indices,
missing files and invalid schemas fail clearly. `--model` defaults to
`artifacts/model.pkl`. `--explain` is off by default; ML-only operation needs no
Ollama service. `--ollama-url` defaults to `http://localhost:11434` and is used
only with `--explain`.

Input must contain all 42 UNSW features. Optional `id`, `attack_cat` and `label`
columns are ignored during prediction and excluded from LLM input. Missing,
duplicate or unexpected columns and invalid values are rejected. The legacy
16-feature PCAP CSV is incompatible; there is no feature mapping or zero filling.

Stdout contains `Row`, `Prediction` (including numeric label), and
`Attack probability` rounded to four decimals. With `--explain`, `Explanation`
contains the actual local response. Probability is an uncalibrated model score.
Generated prose summarizes supplied values; it is not proof of the forest's
reasoning and cannot change the classification.

Exit codes: `0` for success, `1` for file/schema/model/runtime errors, `2` for
argparse usage errors. If explanation generation fails, the prediction remains
on stdout, `Explanation unavailable: <reason>` goes to stderr, and exit status
is `1`. No fallback explanation is printed.

## ARM64 Docker setup

Start [Docker Desktop](https://docs.docker.com/desktop/) on the Mac. Build and test:

```sh
docker build --platform linux/arm64 -t edge-sec-guardian:cli .
docker run --rm --platform linux/arm64 --network none \
  edge-sec-guardian:cli python -m unittest -v
```

The image retains `python:3.13-slim-trixie`, runs as a non-root user (UID 1000),
and defaults to CLI help. The build context admits only application modules,
tests, requirements and the two legacy sample files. It excludes datasets,
artifacts, credentials, Git history and caches. Rebuild after changing source or
dependencies. The base image tag and transitive dependencies are not fully pinned,
so future rebuilds may differ from the verified environment.

Use bind mounts for local data and persistent model output. Create host
directories first. Matching your host UID/GID prevents root-owned output files:

```sh
mkdir -p data/raw artifacts
docker run --rm --platform linux/arm64 --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd)/data,target=/app/data,readonly" \
  --mount "type=bind,source=$(pwd)/artifacts,target=/app/artifacts" \
  edge-sec-guardian:cli python train_model.py \
  --train data/raw/UNSW_NB15_training-set.csv \
  --test data/raw/UNSW_NB15_testing-set.csv \
  --model artifacts/model.pkl --metrics artifacts/metrics.json

docker run --rm --platform linux/arm64 --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd)/data,target=/app/data,readonly" \
  --mount "type=bind,source=$(pwd)/artifacts,target=/app/artifacts,readonly" \
  edge-sec-guardian:cli python cli.py \
  --input data/raw/UNSW_NB15_testing-set.csv --row 0
```

Place the official CSVs locally before training; prediction requires the saved
model. These commands disable network access for training and ML-only prediction.
To verify manually placed downloads inside Docker, mount the repository writable
(the verifier updates `data/README.md`):

```sh
docker run --rm --platform linux/arm64 --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd),target=/app" \
  edge-sec-guardian:cli python download_data.py
```

## Native Ollama from Docker

Install and run Ollama natively on macOS using [OLLAMA.md](OLLAMA.md). Download
the exact model once during setup:

```sh
ollama pull llama3.2:1b
ollama list
```

For CLI-only Ollama, start the server in another terminal with a loopback bind:

```sh
OLLAMA_HOST=127.0.0.1:11434 ollama serve
```

If the Ollama application is already serving that port, use its existing service.
Ollama's default bind is loopback, as described in its
[configuration documentation](https://docs.ollama.com/faq#how-can-i-expose-ollama-on-my-network).
On this Mac, Docker Desktop successfully reached the native service at
`127.0.0.1:11434` through `host.docker.internal`; no wildcard bind or persistent
macOS setting change was needed. Container localhost refers to the container.
See [Docker's host service instructions](https://docs.docker.com/desktop/features/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host).

Check connectivity and the installed exact model from the application image:

```sh
docker run --rm --platform linux/arm64 edge-sec-guardian:cli \
  python -c 'import json; from urllib.request import build_opener, ProxyHandler; result = json.loads(build_opener(ProxyHandler({})).open("http://host.docker.internal:11434/api/tags", timeout=10).read()); print([model["name"] for model in result["models"]])'
```

With the saved model and native Ollama service available, request an explanation:

```sh
docker run --rm --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd)/data,target=/app/data,readonly" \
  --mount "type=bind,source=$(pwd)/artifacts,target=/app/artifacts,readonly" \
  edge-sec-guardian:cli python cli.py \
  --input data/raw/UNSW_NB15_testing-set.csv --row 0 --explain \
  --ollama-url http://host.docker.internal:11434
```

Keep Docker networking enabled for local HTTP. `--network none` also blocks
host Ollama. After setup, disconnect external internet while retaining local
connectivity to verify offline explanation operation. If connection fails,
check that Ollama is serving, Docker Desktop is running, the URL uses
`host.docker.internal`, and local firewall rules permit Docker Desktop access.
No port publication, Ollama container, Compose stack or cloud inference is needed.

## Separate legacy PCAP utility

The retained Scapy utility groups bidirectional IPv4 TCP/UDP packets into flows
and exports 16 numeric features with five identifiers. It is separate from the
42-feature UNSW classifier. Its scripts, sample files and 16 tests are preserved:

```sh
python -m unittest test_extract -v
python extract_features.py --input data/sample.pcap --output /tmp/legacy-features.csv

docker run --rm --platform linux/arm64 --network none \
  edge-sec-guardian:cli python extract_features.py \
  --input data/sample.pcap --output /tmp/legacy-features.csv
```

The supplied sample has six packets in three flows. There is no live capture,
web server, database or hardware deployment in this application.

## Verification

Final integration review on 14 November 2026 used the existing
`edge-sec-guardian:baseline` image (Python 3.13.18, `aarch64`). Its Python source
hashes matched the checkout. The `:cli` tag in the build commands above is a local
name for an image built from the same Dockerfile.

- All 58 tests passed with networking disabled and the checkout mounted read-only:
  11 CLI, 11 model, 6 explanation, 16 legacy extractor, and 14 preprocessing tests.
- `pip check` passed. Both dataset files matched their recorded hashes and counts.
- Re-evaluating the saved model on every held-out row reproduced all saved metrics.
- The real CLI returned `attack`, `0.7849` for row 0 and generated an explanation
  through native Ollama at `host.docker.internal:11434` with read-only data/model
  mounts. This check used local HTTP; it was not a network-disabled container run.

Unit tests use small synthetic fixtures and mocked HTTP where appropriate; the
separate real-data and local-model checks establish end-to-end operation. The
review reused the existing image and model; it did not rebuild or retrain them.
