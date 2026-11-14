# Common developer instructions

## Current authorization

This task is planning only: create/review `ARCHITECTURE.md`, `TASKS.md`, and this
file, then stop. Do not implement the application, modify existing functional code,
spawn subagents, commit, or push unless a later user instruction authorizes it.
The allocation in `TASKS.md` describes future work, not permission to start it.

## Scope and contracts

- Read `ARCHITECTURE.md` and `TASKS.md` before work. Follow their exact schemas,
  interfaces, artifact fields, CLI semantics, dependencies, and file ownership.
- Build only the offline UNSW-NB15 binary Random Forest classifier, optional local
  Llama 3.2 1B explanation, and CLI/Docker setup for the M1 Mac and Linux ARM64.
- No UI, API server, live monitoring, Raspberry Pi work, cloud LLM, database,
  orchestration framework, agent framework, or unnecessary infrastructure.
- Existing README Pi instructions describe the previous project scope. The new
  architecture governs this work; CLI/DevOps updates README during implementation.
- Edit only your assigned files. Ask the owner for shared-file changes. Bring
  schema/interface changes to the Tech Lead before implementation.

## Keep the Python simple

- Use short, readable functions, descriptive names, ordinary dictionaries/lists,
  and undergraduate-level Python. Explain non-obvious decisions briefly.
- No custom classes, abstraction layers, plugin systems, or generic frameworks
  unless a concrete requirement warrants them. Standard scikit-learn Pipeline and
  ColumnTransformer objects and unittest test classes are appropriate.
- Reuse existing code/style where suitable. Preserve the legacy PCAP scripts,
  sample files, and tests. Their 16-feature format is not compatible with the 42
  UNSW features. Never create a pretend mapping or fill absent features with zeros.
- Keep dependencies to existing Scapy plus pandas and scikit-learn. Use standard
  library HTTP, serialization, CLI parsing, and tests. Only CLI/DevOps edits pins.
- Use main guards. Do not download, train, generate text, or print at import time.
  Report expected errors clearly; do not hide failures behind broad exceptions.

## Data and ML integrity

- Download the official named training/testing CSVs and record provenance. Keep
  their bytes, rows, and split membership intact. Never combine and re-split them.
- Fit preprocessing and the forest on training data only. The held-out test split
  is evaluation-only. Any future validation/tuning must use training data only.
- Exclude `id`, `attack_cat`, and target `label` from all features and LLM input.
  A predicted label is allowed in the explanation request; ground truth is not.
- Use the shared loader and save the fitted preprocessor with the classifier.
  Prediction loads and transforms with that artifact; it never fits preprocessing.
- Report actual measured metrics and actual predictions. No invented benchmark
  numbers, random prediction placeholders, or hard-coded demonstration answers.
- Load only trusted project-generated pickle artifacts. Keep generated artifacts
  and downloaded datasets out of Git; retain dataset attribution in documentation.

## LLM and integration integrity

- Use exactly local Ollama `llama3.2:1b`; no silent model substitution, automatic
  runtime download, external inference call, or canned fallback explanation.
- Explanations summarize the provided classifier result and selected raw values.
  They are not proven explanations of tree decisions and cannot alter predictions.
- If Ollama fails, preserve the real ML result and report explanation unavailability
  with the defined nonzero exit code. Do not present error text as generated prose.
- Keep setup downloads distinct from offline runtime. Docker-to-host local HTTP
  is expected for explanations; external internet is not.

## Verification and handoff

- Test meaningful boundaries: schema rejection, leakage prevention, unseen
  categories, save/reload consistency, real predictions, and clear failure paths.
- Use unittest and temporary files. Small synthetic fixtures and mocked HTTP are
  permitted only in isolated, clearly identified unit tests. They are never the
  application model, benchmark dataset, or evidence of successful Llama generation.
- Verify the full pipeline with real official CSV data and a real local model.
  Retain the existing extractor tests. State exactly which checks actually ran;
  distinguish pending checks and failures from successes.
- Hand off changed owned files, interface compliance, measured results, and known
  limitations. Do not commit/push or expand scope without user authorization.
