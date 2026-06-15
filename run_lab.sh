#!/bin/bash
# Run the Track 3 lab wizard with the project virtual environment.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi

echo "[*] Starting lab wizard (sudo required for Wi-Fi capture)..."
exec sudo .venv/bin/python lab_cli.py "$@"
