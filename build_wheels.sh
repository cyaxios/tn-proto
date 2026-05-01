#!/usr/bin/env bash
# Rebuild every wheel and stage it in dist-wheelhouse/ so a downstream
# `pip install --find-links dist-wheelhouse tn-protocol` picks up the
# latest Rust + Python source. Run this after any change to:
#
#   - crypto/tn-core/src/      (Rust runtime)
#   - crypto/tn-btn/src/       (Rust btn primitive)
#   - crypto/tn-core-py/src/   (PyO3 bindings)
#   - crypto/tn-btn-py/src/    (PyO3 bindings)
#   - python/tn/               (Python SDK)
#
# Without this step, students/operators installing from the wheelhouse
# get stale Rust binaries that don't reflect source-tree fixes — see
# the FINDINGS S0.4 stale-wheel root cause.
#
# Usage:
#   ./build_wheels.sh              # build all three wheels into dist-wheelhouse/
#   ./build_wheels.sh tn_core      # build a subset
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$SCRIPT_DIR/../.venv/Scripts/python.exe"
DIST="$SCRIPT_DIR/dist-wheelhouse"
WHEELS_OUT="$SCRIPT_DIR/target/wheels"
mkdir -p "$DIST"
mkdir -p "$WHEELS_OUT"

build_tn_core() {
    echo "==> Building tn_core (Rust + PyO3)"
    cd "$SCRIPT_DIR/crypto/tn-core-py"
    "$VENV_PY" -m maturin build --release
    cp "$WHEELS_OUT/tn_core-"*.whl "$DIST/"
}

build_tn_btn() {
    echo "==> Building tn_btn (Rust + PyO3)"
    cd "$SCRIPT_DIR/crypto/tn-btn-py"
    "$VENV_PY" -m maturin build --release
    cp "$WHEELS_OUT/tn_btn-"*.whl "$DIST/"
}

build_tn_protocol() {
    echo "==> Building tn_protocol (pure Python)"
    cd "$SCRIPT_DIR/python"
    "$VENV_PY" -m build --wheel --outdir "$WHEELS_OUT"
    cp "$WHEELS_OUT/tn_protocol-"*.whl "$DIST/"
}

if [ $# -eq 0 ]; then
    build_tn_btn
    build_tn_core
    build_tn_protocol
else
    for arg in "$@"; do
        case "$arg" in
            tn_core|core)       build_tn_core ;;
            tn_btn|btn)         build_tn_btn ;;
            tn_protocol|python) build_tn_protocol ;;
            *) echo "unknown target: $arg (try tn_core / tn_btn / tn_protocol)"; exit 2 ;;
        esac
    done
fi

echo
echo "==> Wheels in $DIST:"
ls -la "$DIST" | awk 'NR>1 {print "    " $NF}'
echo
echo "Install locally with:"
echo "    pip install --find-links $DIST tn-protocol"
