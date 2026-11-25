# Local Ollama development backend

The Raspberry Pi submission uses ExecuTorch. For development, the dashboard also supports a local Ollama server with `llama3.2:1b`. Acquire the model during setup using `ollama pull llama3.2:1b`, then run Ollama on a local address.

```sh
edge-sec-dashboard --replay-pcap data/nf_test_sample.pcap --host 127.0.0.1 \
  --model artifacts/ciciot_model.pkl --explainer ollama \
  --ollama-url http://127.0.0.1:11434
```

The client bypasses environment proxies, refuses redirects and validates generated JSON before displaying it. It sends selected detector evidence and leaves alert decisions to the detector. See the [README](README.md) for the primary Pi setup and [Engineering Report](ENGINEERING_REPORT.md) for physical-board measurements.
