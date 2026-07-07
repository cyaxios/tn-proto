#!/bin/bash
# hibe cross-impl at the CEREMONY level (modeled on
# crypto/tn-wasm/test/run_hibe_interop.sh, which proves the primitive layer):
#
#   1. Python mints a hibe ceremony, seals a log, grants a reader kit.
#   2. ts-sdk absorbs the kit and reads/verifies the python log.
#   3. ts-sdk mints its own hibe ceremony, seals a log, grants a kit.
#   4. Python absorbs the TS kit and reads/verifies the TS log.
#
# Needs: node (nvm) + a Python env with the tn-proto wheel active before
# invocation (e.g. `source ~/venv-tnhibe/bin/activate`), and ts-sdk
# node_modules installed for this platform.
set -e
cd "$(dirname "$0")/.."   # ts-sdk/

WS="$(mktemp -d /tmp/hibe-ximpl-XXXXXX)"
trap 'rm -rf "$WS"' EXIT

TN_NO_STDOUT=1 python test/hibe_cross_impl_py.py --emit "$WS"
node --import tsx test/hibe_cross_impl_ts.ts "$WS"
TN_NO_STDOUT=1 python test/hibe_cross_impl_py.py --verify "$WS"
echo "hibe cross-impl (ceremony level): ALL OK"
