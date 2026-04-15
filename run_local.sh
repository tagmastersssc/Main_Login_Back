#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8000}"

if command -v func >/dev/null 2>&1; then
  cd "$SCRIPT_DIR"
  AzureWebJobsStorage="${AzureWebJobsStorage:-UseDevelopmentStorage=true}" \
  FUNCTIONS_WORKER_RUNTIME="${FUNCTIONS_WORKER_RUNTIME:-python}" \
  func start --port "$PORT"
else
  echo "Azure Functions Core Tools no está instalado; usando uvicorn como fallback local."
  "$SCRIPT_DIR/venv/bin/python" -m uvicorn main:app --reload --port "$PORT"
fi
