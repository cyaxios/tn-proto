#!/usr/bin/env bash
# Wrapper that resolves python via the project venv, then invokes the
# Node driver. See interop_driver.mjs for the actual logic.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "${HERE}/.." && pwd)"
REPO_ROOT="$(cd "${SDK_DIR}/../.." && pwd)"

PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"
if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python"
fi
export TN_PYTHON="${PYTHON}"

echo "== ts-sdk unit tests =="
(cd "${SDK_DIR}" && node --import tsx --test test/sdk_smoke.test.ts test/node_runtime.test.ts)

echo ""
echo "== wasm admin + crypto interop =="
node "${REPO_ROOT}/tn-protocol/crypto/tn-wasm/test/node_smoke.mjs"
"${PYTHON}" "${REPO_ROOT}/tn-protocol/crypto/tn-wasm/test/py_cross_check.py"

echo ""
echo "== btn interop =="
bash "${REPO_ROOT}/tn-protocol/crypto/tn-wasm/test/run_btn_interop.sh"

echo ""
echo "== public-only CLI interop =="
node "${HERE}/interop_driver.mjs"

echo ""
echo "== full-runtime (yaml + btn) interop =="
node "${HERE}/full_runtime_interop.mjs"

echo ""
echo "== admin verbs interop =="
node "${HERE}/admin_interop.mjs"
