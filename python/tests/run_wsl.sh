#!/bin/bash
# Run the core (JWE-default) test suite. BGW is a legacy alternative
# and its tests live in the optional list below; set WITH_BGW=1 to
# include them. Live-cloud tests (S3 / Databricks / Kafka / Confluent)
# are always skipped.
set -u
cd "$(dirname "$0")/.."
export TNCRYPTO_LIB="$(pwd)/../crypto/build/libtncrypto.so"
PY=/usr/bin/python
fails=0

CORE_TESTS=(
    tests/test_indexing.py
    tests/test_multi_curve_verify.py
    tests/test_cipher_jwe.py
    tests/test_jwe_roundtrip.py
    tests/test_revoke_recipient.py
    tests/test_handlers.py
    tests/test_kafka_stubs.py
)

# BGW-path tests. Opt-in via WITH_BGW=1 for anyone specifically
# validating the broadcast-encryption alternative. Default runs skip.
BGW_TESTS=(
    tests/test_cipher_bgw.py
    tests/test_native_roundtrip.py
    tests/test_tnlog_roundtrip.py
    tests/test_admin_and_log.py
)

if [ "${WITH_BGW:-0}" = "1" ]; then
    TESTS=("${CORE_TESTS[@]}" "${BGW_TESTS[@]}" tests/test_examples.py)
else
    TESTS=("${CORE_TESTS[@]}" tests/test_examples.py)
fi

for f in "${TESTS[@]}"; do
  echo "=== $f ==="
  if "$PY" "$f"; then
    echo "PASS $f"
  else
    echo "FAIL $f"
    fails=$((fails+1))
  fi
done
echo
echo "failures: $fails"
exit $fails
