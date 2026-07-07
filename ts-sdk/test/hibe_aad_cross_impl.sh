#!/bin/bash
# hibe AAD cross-impl at the CEREMONY level (modeled on hibe_cross_impl.sh):
#
#   1. Python mints a hibe ceremony, seals an entry bound to an aad dict, and
#      grants a reader kit.
#   2. ts-sdk absorbs the kit, reconstructs the aad from the public tn_aad,
#      reads/verifies the python log, and proves a tampered tn_aad fails to
#      decrypt. Then ts-sdk mints its own hibe ceremony, seals an aad-bound
#      entry, and grants a kit.
#   3. Python absorbs the TS kit, reconstructs the aad, reads/verifies the TS
#      log, and proves a tampered tn_aad fails to decrypt.
#
# Both sides bind the same aad dict via the same canonical-bytes routine and
# echo it into the public tn_aad block; the reader reconstructs it to open.
#
# Needs: node (nvm) + a Python env with the tn-proto wheel active before
# invocation (e.g. `source ~/venv-tnhibe/bin/activate`), and ts-sdk
# node_modules installed for this platform.
set -e
cd "$(dirname "$0")/.."   # ts-sdk/

WS="$(mktemp -d /tmp/hibe-aad-ximpl-XXXXXX)"
trap 'rm -rf "$WS"' EXIT

TN_NO_STDOUT=1 python test/hibe_aad_cross_impl_py.py --emit "$WS"
node --import tsx test/hibe_aad_cross_impl_ts.ts "$WS"
TN_NO_STDOUT=1 python test/hibe_aad_cross_impl_py.py --verify "$WS"
echo "hibe AAD cross-impl (ceremony level): ALL OK"
