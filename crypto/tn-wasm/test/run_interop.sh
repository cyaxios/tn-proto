#!/usr/bin/env bash
# Phase A interop driver. Runs the Node WASM smoke test, then diffs
# against tn_core.admin.reduce output from Python.
#
# From repo root:
#   bash tn-protocol/crypto/tn-wasm/test/run_interop.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_DIR="$(cd "${HERE}/.." && pwd)"
REPO_ROOT="$(cd "${WASM_DIR}/../../.." && pwd)"

PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"
if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python"
fi

echo "== Node WASM smoke =="
node "${HERE}/node_smoke.mjs"

echo ""
echo "== Python cross-check =="
"${PYTHON}" "${HERE}/py_cross_check.py"
