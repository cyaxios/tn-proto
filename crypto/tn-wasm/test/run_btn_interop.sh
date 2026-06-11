#!/usr/bin/env bash
# btn interop driver. Two-pass ping-pong:
#   1. JS produces kits + ciphertexts, writes btn_fixture.json
#   2. Python decrypts JS stuff, re-derives its own ciphertexts, adds
#      them to the fixture
#   3. JS decrypts Python's ciphertexts via --verify-py
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../../.." && pwd)"

PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"
if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python"
fi

echo "== Node produce =="
node "${HERE}/btn_interop.mjs"

echo ""
echo "== Python decrypt + mirror =="
"${PYTHON}" "${HERE}/btn_py_check.py"

echo ""
echo "== Node verify Python =="
node "${HERE}/btn_interop.mjs" --verify-py
