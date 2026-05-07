#!/usr/bin/env bash
# Compatibility shim — delegates to the Makefile's standard targets.
#
# The real build orchestration lives in ./Makefile. Standard tooling
# (maturin / build / twine), standard output dir (./dist/), standard
# wheel layout. See ``make help`` for the full target list.
#
# Kept around so existing muscle memory and any external scripts that
# call ``./build_wheels.sh`` continue to work without surprise.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -eq 0 ]; then
    exec make build
fi

# Map legacy positional args to make targets.
TARGETS=()
for arg in "$@"; do
    case "$arg" in
        tn_core|core)        TARGETS+=("build-core") ;;
        tn_btn|btn)          TARGETS+=("build-btn") ;;
        tn_protocol|python)  TARGETS+=("build-protocol") ;;
        clean)               TARGETS+=("clean") ;;
        check)               TARGETS+=("check") ;;
        publish-test)        TARGETS+=("publish-test") ;;
        publish)             TARGETS+=("publish") ;;
        *)
            echo "build_wheels.sh: unknown target '$arg'"
            echo ""
            make help
            exit 2
            ;;
    esac
done

exec make "${TARGETS[@]}"
