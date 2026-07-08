#!/bin/bash
# HIBE Python<->wasm interop: python seals -> wasm opens (incl. a
# wasm-delegated key), wasm seals -> python opens. Mirrors
# run_btn_interop.sh. Needs: pkg/ built (wasm-pack build --target nodejs)
# and a Python env with the tn-proto wheel (or maturin develop) active.
set -e
cd "$(dirname "$0")"
python hibe_py_check.py --emit
node hibe_interop.mjs
python hibe_py_check.py --verify
rm -f hibe_fixture.json hibe_js_out.json
echo "hibe interop: ALL OK"
