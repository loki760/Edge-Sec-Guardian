# Local Llama explanations

Run Ollama natively on the Mac; the future Linux ARM64 Python container calls
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
input dictionary is changed. If generation fails, the future CLI must preserve
its prediction output, report `Explanation unavailable: <reason>` on stderr,
omit the explanation field, and return exit code 1.

## Docker handoff

The future CLI must pass `--ollama-url http://host.docker.internal:11434`.
The container's localhost points to the container itself. Binding and Docker
Desktop verification belong to CLI/DevOps. The service started for this work
listens on loopback only; Docker access has not been verified. If the Docker
Desktop setup needs another host binding, CLI/DevOps should configure and test
it deliberately; a wildcard bind can expose Ollama to other machines. The
Python application and model runtime stay separate; do not install Ollama or
bake its weights into the Python image. External internet can be disconnected
after downloads, while local HTTP must remain reachable.

## Tests and integration status

```sh
python3 -m unittest test_explain -v
```

These six unit tests use clearly identified mocked responses. They check request
fields, metadata exclusion, unchanged input dictionaries, custom host/timeout,
response failures, transport failures, and local-only model/URL behavior. They
are not evidence of real Llama generation.

After the Data/ML modules and trusted trained artifact are available, reproduce
full integration using the shared prediction result:

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

No ML modules, official dataset, or model artifact were present in this checkout
at implementation time. An explanation based on an actual classifier prediction
and Docker-to-host integration therefore remain pending with their owners.

Verified on 14 November 2026 on this Mac (Apple M1 Pro, native ARM64):

- Existing Ollama CLI version 0.35.1 was used; no reinstall was needed.
- Started `ollama serve` on `127.0.0.1:11434`; Metal detected Apple M1 Pro.
- `ollama pull llama3.2:1b` completed with digest verification. `ollama list`
  reported model ID `baf6a787fdff`, size 1.3 GB.
- The `ollama run` command above returned a real sentence describing packets.
- A separate standard-library POST to `http://localhost:11434/api/generate`,
  with the same packet question, `stream: false`, `temperature: 0`,
  `num_predict: 160`, and timeout 60 returned `model: llama3.2:1b`, `done: true`,
  nonempty generated prose, and `eval_count: 55`.
- `python3 -m unittest test_explain -v`: all six tests passed.

These were real native generation checks with a general networking question,
not an ML prediction demonstration. The actual classifier integration above is
still pending. No generated response is installed as an application fallback.
