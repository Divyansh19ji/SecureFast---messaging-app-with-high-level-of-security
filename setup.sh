#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "  SecureFast v2.0 - First-Time Setup (Python + C11 Engine)"
echo "============================================================"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] python3 (3.11+) not found."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "[1/4] Creating .venv..."
  "$PYTHON_BIN" -m venv .venv
fi

echo "[2/4] Installing dependencies..."
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements.txt

echo "[3/4] Installing SecureFast CLI package..."
.venv/bin/python -m pip install -e . --no-build-isolation --no-deps

echo "[4/4] Compiling C11 Native Core..."
.venv/bin/python build_native.py --bench

echo ""
echo "Setup complete! Run:"
echo "  .venv/bin/securefast start    (Host Relay + Local App)"
echo "  .venv/bin/securefast client   (Friend Client)"
echo "  .venv/bin/securefast demo     (Alice + Bob 2-User Demo)"
