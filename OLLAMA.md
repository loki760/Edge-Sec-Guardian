# Local Llama explanations

Run Ollama natively on the Mac; the Linux ARM64 Python container calls
that host service. No Python SDK or extra dependency is required.

## One-time setup

On macOS 14 or newer with Apple silicon, install Ollama from
https://ollama.com/download/mac (mount the DMG and move the application into
Applications), then launch it. Official setup details:
https://docs.ollama.com/macos . If the native CLI is already installed, use it;
this project does not require reinstalling it. With a CLI-only installation,
start the service in a separate terminal:

```sh
ollama serve
```

Download the exact public model during setup, then verify its presence:

```sh
ollama pull llama3.2:1b
ollama list
ollama run llama3.2:1b 'Explain what a network packet is in one sentence.'
```

Model reference: https://ollama.com/library/llama3.2:1b . Ollama manages weights
outside Git, normally in `~/.ollama/models`. Setup requires internet; runtime
uses local weights and local HTTP. The application never pulls models or uses a
cloud fallback. Keep the native service running while explanations are requested.

## Python interface

```python
from explain import explain_prediction

# X is one validated UNSW feature row from the shared loader.
# result is the actual dictionary returned by predict_row(bundle, X).
text = explain_prediction(X.iloc[0].to_dict(), result)
print(text)
```

The exact signature is
`explain_prediction(features, prediction, base_url="http://localhost:11434", model="llama3.2:1b", timeout=60) -> str`.
Only `llama3.2:1b` is accepted. The selected raw fields are `proto`, `service`,
`state`, `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, and `rate`. Source ID, ground
truth label, and attack category are never serialized. Only predicted label,
decision, and attack probability are sent from the prediction dictionary.
Inputs are expected to have passed shared schema validation; invalid prediction
values or a nonlocal URL raise `ValueError`, and missing required keys raise
`KeyError`.

The request uses standard-library HTTP, bypasses environment proxies, and refuses
redirects. Allowed HTTP hostnames are localhost, 127.0.0.1, ::1, and
host.docker.internal. It posts to `/api/generate` with `stream: false`,
`temperature: 0`, and `num_predict: 160`. See the official API:
https://docs.ollama.com/api/generate . Service/model errors, timeouts, invalid JSON,
incomplete generation, and empty prose raise `RuntimeError`; nothing is printed
or generated at import. No fallback text is returned.

The prompt requests 2–3 cautious sentences and a proportionate recommended
action. Generated prose is an unverified summary, not causal feature attribution
or proof of an attack. A small model can still disregard prompt instructions.
The caller must keep it separate from the actual Random Forest decision. Neither
input dictionary is changed. If generation fails, the CLI preserves its prediction
output, reports `Explanation unavailable: <reason>` on stderr, omits the
explanation field, and returns exit code 1. Generated wording may still imply
confidence that the uncalibrated score does not establish; treat it as unverified.

## Docker execution

Pass `--ollama-url http://host.docker.internal:11434`; container localhost points
to the container itself. Docker Desktop access to the native loopback-bound
service was verified on this Mac without a wildcard bind. Keep local HTTP
reachable: `--network none` blocks host Ollama as well as external services.
Ollama and its weights remain outside the Python image. See the
[README Docker commands](README.md#native-ollama-from-docker) for read-only data
and model mounts and the complete CLI invocation.

## Tests and integration status

```sh
python3 -m unittest test_explain -v
```

These six unit tests use clearly identified mocked responses. They check request
fields, metadata exclusion, unchanged input dictionaries, custom host/timeout,
response failures, transport failures, and local-only model/URL behavior. They
are not evidence of real Llama generation.

With the local CSVs, trusted trained artifact, and Ollama service available,
reproduce native Python integration using the shared prediction result:

```python
from preprocess import load_csv
from predict import load_model, predict_row
from explain import explain_prediction

X, _ = load_csv('data/raw/UNSW_NB15_testing-set.csv')
row = X.iloc[[0]]
result = predict_row(load_model('artifacts/model.pkl'), row)
print(result)
print(explain_prediction(row.iloc[0].to_dict(), result))
```

Verified on 14 November 2026 on the Apple M1 Pro:

- Native Ollama 0.35.1 served `llama3.2:1b`; setup recorded model ID
  `baf6a787fdff` and size 1.3 GB.
- The Docker CLI loaded the real classifier, predicted test row 0 as `attack`
  with score `0.7849`, and received a real local Llama summary recommending review.
- All six explanation tests passed within the complete 58-test Docker suite.

No generated response is installed as an application fallback.
