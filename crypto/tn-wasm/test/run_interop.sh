#!/usr/bin/env bash
# Run the retained WASM conformance vectors.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "${HERE}/conformance_golden.mjs"
