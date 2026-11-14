# Developer work allocation

Status: the four components are implemented and merged into `feat/baseline-mvp`.
Final integration review passed with 58 tests. This document retains the original
ownership, dependencies, and acceptance criteria; it does not authorize new work.
`ARCHITECTURE.md` is the shared interface contract. Dataset acquisition details
still requiring user confirmation are listed in `data/README.md`.

## Exclusive file ownership

| Developer | Source/document files owned | Generated outputs owned |
| --- | --- | --- |
| Data Engineer | `download_data.py`, `preprocess.py`, `test_preprocess.py`, `data/README.md` | `data/raw/UNSW_NB15_training-set.csv`, `data/raw/UNSW_NB15_testing-set.csv` |
| ML Engineer | `train_model.py`, `predict.py`, `test_model.py` | `artifacts/model.pkl`, `artifacts/metrics.json` |
| LLM Engineer | `explain.py`, `test_explain.py`, `OLLAMA.md` | None; Ollama manages model storage outside the repository. |
| CLI/DevOps Engineer | `cli.py`, `test_cli.py`, `Dockerfile`, `.dockerignore`, `requirements.txt`, `.gitignore`, `README.md` | Docker image; temporary integration outputs only. |
| Tech Lead | `ARCHITECTURE.md`, `TASKS.md`, `AGENTS.md` | None. |

Leave `extract_features.py`, `make_sample_pcap.py`, `test_extract.py`,
`data/sample.pcap`, and `data/features.csv` unchanged. Other developers request
dependency/documentation edits from CLI/DevOps rather than editing shared files.
Request contract changes from the Tech Lead before changing interfaces; do not
introduce compatibility wrappers to work around disagreements.

## 1. Data Engineer

Responsibilities:

- Retrieve the official named CSV splits, retain their original bytes, and record
  provenance, SHA-256 hashes, row counts, and required dataset attribution.
- Implement schema constants, shared validation/loading, and the unfitted
  preprocessing factory specified in `ARCHITECTURE.md`.
- Validate official labels and metadata without exposing them as features.
  Do not create a newly randomized split or export separately encoded CSVs.

Dependencies: no implementation dependency on another module. Coordinate pandas
and scikit-learn installation with CLI/DevOps.

Acceptance criteria:

- Official files contain 175,341 training and 82,332 testing rows and the expected
  45 columns. Download failures are visible; manual official-file placement is
  documented if necessary. Files remain unchanged after loading/training.
- Loader returns exactly the 42 ordered features and optional binary target.
  Tests cover column reordering, missing/duplicate/unexpected columns, invalid
  numeric/missing values, preserved categorical tokens, and leakage exclusions.
- Transformer remains unfitted until the ML pipeline fits it. A meaningful test
  fits on training-like categories and transforms an unseen category successfully
  without learning it from held-out input.
- `data/features.csv` fails with a clear schema mismatch.

Handoff: validated local split paths, provenance document, loader/factory functions,
and passing `python -m unittest test_preprocess -v`.

## 2. ML Engineer

Responsibilities:

- Consume `preprocess.py`; implement the fixed Random Forest pipeline, training
  entry point, metrics, trusted model saving/loading, and single-row prediction.
- Fit exclusively on the official training split. Evaluate the entire official
  held-out split with no fitting, resampling, or tuning against it.
- Save preprocessing and classifier together; make prediction use that artifact.

Dependencies: Data Engineer's schema/loader/factory and verified official files;
CLI/DevOps dependency pins.

Acceptance criteria:

- Full official training and evaluation complete on the target environment and
  write a real model and metrics with the exact fields in `ARCHITECTURE.md`.
- Report accuracy, attack precision/recall/F1, and ordered confusion matrix from
  actual test predictions. Matrix counts sum to 82,332. No score is fabricated
  and no minimum accuracy is assumed.
- Save/reload preserves predictions and probabilities on the same rows. Tests
  cover target/metadata exclusion, class-1 probability selection, unseen
  categories after reload, and malformed/incompatible artifacts.
- Prediction performs no fitting and requires one validated row. Record the real
  training/evaluation command and measured results in the handoff to CLI/DevOps.

Handoff: genuine artifacts, measured results, and passing
`python -m unittest test_model -v`. Small test fixtures may train a real tiny forest
for unit tests; they must never be presented as the official benchmark model.

## 3. LLM Engineer

Responsibilities:

- Document native Mac Ollama setup and the one-time `ollama pull llama3.2:1b` in
  `OLLAMA.md`; coordinate Docker-to-host connectivity with CLI/DevOps.
- Implement `explain_prediction` with standard-library HTTP and the exact
  interface, prompt constraints, timeout, and error semantics in the architecture.
- Keep explanations separate from classifier decisions and ground-truth labels.

Dependencies: prediction dictionary contract; actual end-to-end demonstration
requires the ML Engineer's model and a running local Ollama installation. Prompt
and error-handling work can proceed before the classifier exists.

Acceptance criteria:

- A real call to the installed `llama3.2:1b` returns a short explanation using an
  actual model prediction. Record how to reproduce it; do not commit canned output
  as a fallback.
- Prompt excludes `label` ground truth and `attack_cat`; it uses the classifier's
  predicted label and does not claim causal feature attribution or attack subtype.
- Unavailable service, missing model, timeout, invalid JSON, incomplete response,
  and empty response raise clear errors. No network call happens on import.
- Unit tests may mock transport to test parsing/errors, clearly marked as unit
  fixtures. Such mocks are not evidence that local Llama integration works.

Handoff: callable explanation module, `OLLAMA.md`, passing
`python -m unittest test_explain -v`, and evidence of a real local generation.

## 4. CLI/DevOps Engineer

Responsibilities:

- Integrate the shared modules without duplicating schema validation, encoding,
  forest logic, or prompts. Implement the one-row CLI and exit behavior.
- Own all shared setup files. Add only pandas/scikit-learn to existing dependencies
  and pin versions tested with the retained Python base on Linux ARM64.
- Adapt the existing Dockerfile and `.dockerignore` allowlist for new modules and
  tests; retain non-root execution and the ability to run the legacy extractor.
- Document setup, download, training, prediction, optional explanation, local
  mounts, and Docker-to-host Ollama configuration in README; link `OLLAMA.md`.
  Replace Pi deployment directions with the current project scope while retaining
  a short, clearly separate PCAP utility section.
- Exclude downloaded datasets, model/metrics artifacts, virtual environments, and
  credentials from Git/build context. Do not ignore the tracked PCAP sample files.

Dependencies: interface contract first; completed Data/ML modules for inference;
LLM module and local model for explanation verification.

Acceptance criteria:

- A Linux ARM64 image builds on the M1; data and artifact mounts persist output
  without requiring a privileged container or root-owned host files.
- Documented commands train on official splits and print a genuine one-row
  prediction from a reloaded model; `--explain` prints an actual local response.
- Test default/explicit row selection, out-of-range index, bad CSV, missing model,
  CLI usage errors, ML-only operation without Ollama, and truthful LLM failure
  behavior with prediction retained and nonzero exit status.
- Full `python -m unittest -v` passes, including the unchanged legacy tests.
  Unit mocks never replace the real integration demonstration.
- After initial downloads, demonstrate training/prediction with external internet
  disconnected, and explanation through local HTTP. Do not confuse container
  `--network none` with allowing access to host Ollama.

Handoff: reproducible README commands, passing checks, actual integration results,
and any observed limitations. No publishing, pushing, or deployment is implied.

## Original integration sequence (historical)

1. Tech Lead obtains review of the planning files before implementation.
2. After implementation authorization, Data Engineer establishes schema and files;
   CLI/DevOps prepares minimal dependencies. LLM Engineer works against the written
   interface and documents local setup.
3. ML Engineer consumes the Data interface, trains, evaluates, and saves artifacts.
4. CLI/DevOps integrates real modules and verifies Docker and native commands with
   LLM Engineer support for local HTTP connectivity.
5. Tech Lead reviews split preservation, module contracts, measured results, and
   simplicity. Developers report changed owned files, checks run, and limitations.

No developer edits another developer's files to unblock integration. Communicate
the needed change to its owner. No commits, pushes, subagent spawning, or further
application work are authorized by this planning document alone.
