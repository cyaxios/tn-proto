#!/usr/bin/env bash
# Quick local runner: executes every test file in this directory and
# prints a one-line pass/fail summary per test.
set -u
cd "$(dirname "$0")/.."
PY=${PY:-python3}
fails=0
for t in tests/test_native_roundtrip.py \
         tests/test_tnlog_roundtrip.py \
         tests/test_admin_and_log.py \
         tests/test_handlers.py \
         tests/test_kafka_pds_stubs.py \
         tests/test_examples.py; do
    echo "=== $t ==="
    if $PY "$t" > /tmp/_tn_test_out 2>&1; then
        tail -3 /tmp/_tn_test_out
        echo "  PASS"
    else
        tail -20 /tmp/_tn_test_out
        echo "  FAIL"
        fails=$((fails + 1))
    fi
done
echo
echo "failing suites: $fails"
exit $fails
