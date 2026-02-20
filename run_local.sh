#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8000}"
"$SCRIPT_DIR/venv/bin/python" -m uvicorn main:app --reload --port "$PORT"
