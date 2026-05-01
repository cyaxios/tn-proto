#!/usr/bin/env bash
# Rebuild the TN PyO3 extensions (tn-core, tn-btn) and gracefully handle
# the Windows file-lock that strikes when a Python interpreter has the
# .pyd loaded.
#
# Why this script exists:
#   On Windows, `maturin develop --release` will compile cleanly but fail
#   to copy the resulting .dll over the live .pyd if any Python process
#   has imported it. The error reads:
#     "The process cannot access the file because it is being used by
#      another process. (os error 32)"
#   This blocks rebuilds during active dev (a pytest session, an open
#   REPL, even a Pyright language-server interpreter can hold the file).
#
# Usage:
#   tools/rebuild_pyo3.sh                   # rebuild both crates
#   tools/rebuild_pyo3.sh tn-core           # rebuild only tn-core
#   tools/rebuild_pyo3.sh tn-btn            # rebuild only tn-btn
#   tools/rebuild_pyo3.sh --no-kill         # skip the auto-kill step
#                                            (use if you have important
#                                             unsaved work in a Python REPL)
#
# Notes:
# - This script is Windows-aware; on Linux/macOS the file lock doesn't
#   happen, so the kill step is a no-op.
# - Always uses --release. Debug builds are 5-10x slower at runtime and
#   we want fast iteration when running the full suite.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"
if [[ ! -f "$VENV_PYTHON" ]]; then
    # Linux/macOS layout
    VENV_PYTHON="${REPO_ROOT}/.venv/bin/python"
fi
if [[ ! -f "$VENV_PYTHON" ]]; then
    echo "FAIL: no python found at .venv/Scripts/python.exe or .venv/bin/python"
    echo "      activate the venv first or fix REPO_ROOT detection"
    exit 1
fi

TARGETS=()
KILL_LOADERS=1
for arg in "$@"; do
    case "$arg" in
        --no-kill) KILL_LOADERS=0 ;;
        tn-core)   TARGETS+=("tn-core-py") ;;
        tn-btn)    TARGETS+=("tn-btn-py") ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("tn-core-py" "tn-btn-py")
fi

# ---------------------------------------------------------------------
# Step 1: kill any Python interpreter holding the .pyd files we're about
# to overwrite. Windows-only; harmless on other OSes (no `tasklist`).
# ---------------------------------------------------------------------
if [[ "$KILL_LOADERS" -eq 1 ]] && command -v cmd.exe >/dev/null 2>&1; then
    echo "==> Looking for Python processes holding _core.pyd ..."
    for crate in "${TARGETS[@]}"; do
        # tasklist /M output shape:
        #   Image Name                     PID Modules
        #   ========================= ======== ============
        #   python.exe                  724804 _core.pyd, _core.pyd
        holders=$(cmd.exe //c "tasklist /M _core.pyd" 2>/dev/null \
                    | grep -i "^python" \
                    | awk '{print $2}' \
                    | tr -d '\r')
        if [[ -z "$holders" ]]; then continue; fi
        echo "    Found PIDs: $holders"
        for pid in $holders; do
            echo "    Killing PID $pid"
            cmd.exe //c "taskkill /F /PID $pid" 2>/dev/null || true
        done
    done
    # Brief settle time for the OS to release the file handles.
    sleep 1
fi

# ---------------------------------------------------------------------
# Step 2: rebuild each crate via `maturin develop --release`.
# ---------------------------------------------------------------------
overall_ok=1
for crate in "${TARGETS[@]}"; do
    crate_dir="${REPO_ROOT}/tn-protocol/crypto/${crate}"
    if [[ ! -d "$crate_dir" ]]; then
        echo "SKIP: ${crate_dir} does not exist"
        continue
    fi
    echo "==> Building ${crate} via maturin develop --release"
    if ( cd "$crate_dir" && "$VENV_PYTHON" -m maturin develop --release 2>&1 | tail -5 ); then
        echo "    OK: ${crate}"
    else
        echo "    FAIL: ${crate}"
        overall_ok=0
    fi
done

if [[ "$overall_ok" -eq 1 ]]; then
    echo ""
    echo "All requested crates rebuilt successfully."
    echo "Tip: re-run pytest now to pick up the new .pyd."
    exit 0
else
    echo ""
    echo "One or more crates failed to rebuild. See output above."
    exit 1
fi
