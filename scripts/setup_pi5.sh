#!/usr/bin/env bash
set -euo pipefail

# Run from any directory. Reuse the same virtual environment on subsequent runs.
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ "$(uname -s)" != Linux || "$(uname -m)" != aarch64 ]]; then
    echo "This setup requires 64-bit Raspberry Pi OS or Ubuntu ARM64 (aarch64)." >&2
    exit 1
fi

# Override PYTHON_BIN to select a side-by-side Python installation.
python_bin="${PYTHON_BIN:-python3}"
if ! command -v "$python_bin" >/dev/null; then
    echo "Install Python 3.10 or newer and its venv package, or set PYTHON_BIN." >&2
    exit 1
fi
if [[ ! -x .venv/bin/python ]]; then
    "$python_bin" -c 'import sys; sys.exit("Python 3.10 or newer is required" if sys.version_info < (3, 10) else 0)'
    "$python_bin" -m venv .venv
fi
.venv/bin/python -c '
import struct
import sys
if sys.version_info < (3, 10) or struct.calcsize("P") != 8:
    sys.exit("The virtual environment needs 64-bit Python 3.10 or newer.")
if sys.version_info[:2] not in ((3, 10), (3, 11), (3, 12), (3, 13)):
    print("Check ARM64 wheel availability for your Python version. ExecuTorch 1.6.0 was verified on Pi 5 with Python 3.13.5.")
'

# pyproject.toml declares scikit-learn, pandas, NumPy, Scapy, psutil and threadpoolctl.
.venv/bin/python -m pip install -e .

cat <<'NEXT_STEPS'
Setup complete. Run these commands from the project directory.

  .venv/bin/python -m unittest -v

For local ExecuTorch, install an ARM64 build compatible with your Python version
that includes the LLM runner bindings. Install CPU-only PyTorch first:

  .venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
  .venv/bin/python -m pip install --only-binary=:all: executorch
  .venv/bin/python -c 'from executorch.extension.llm.runner import TextLLMRunner'

Use a trusted CIC model bundle built with the same scikit-learn version installed
on the Pi. If needed, retrain on that version using the original split manifest.
Provide your local .pte and matching tokenizer for ExecuTorch:

  sudo .venv/bin/python dashboard.py --interface wlan0 --host 127.0.0.1 --model artifacts/ciciot_model.pkl --explainer executorch --llama-model model.pte --llama-tokenizer tokenizer.model

Use --explainer none for an ML and rules baseline. For benchmarks, see
.venv/bin/edge-sec-benchmark --help. Use --pcap for reproducible replay or
--interface wlan0 --duration-sec 300 for a timed live run.
NEXT_STEPS
