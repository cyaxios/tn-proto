#!/usr/bin/env bash
# Cross-language proof that add_recipient (jwe) and grant_reader (hibe) produce a
# recipient who can read the sealed log, for every publisher x reader language
# pair, repeated a few times with fresh keys.
#
#   TN_PY=/path/to/venv/bin/python bash run_proof.sh [jwe|hibe|both]
#
# TN_PY must point at a Python with the `tn` package installed. The TS side runs
# from the ts-sdk root via tsx.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="$(cd "$HERE/../.." && pwd)"          # ts-sdk root
PY="${TN_PY:-python3}"
WHICH="${1:-both}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

ts()  { ( cd "$SDK" && node --import tsx --import ./test/_setup_wasm.mjs "test/cross_impl/$1" "${@:2}" ); }
pym() { "$PY" "$HERE/$1" "${@:2}"; }

prove_jwe() {
  local pass=0 fail=0
  for pub in py ts; do for rd in py ts; do for run in 1 2 3; do
    local W="$TMP/jwe_${pub}_${rd}_${run}"; mkdir -p "$W/pub" "$W/bkeys"
    pym jwe_proof.py genkey "$W"
    local sec="hello-${pub}-${rd}-${run}"
    if [ "$pub" = py ]; then pym jwe_proof.py pub "$W/pub/tn.yaml" "$W" "$sec"; else ts jwe_proof.mts pub "$W/pub/tn.yaml" "$W" "$sec"; fi >/dev/null 2>"$W/pub.err" \
      || { echo "FAIL(pub) jwe pub=$pub read=$rd run=$run"; tail -2 "$W/pub.err"; fail=$((fail+1)); continue; }
    cp "$W/b_priv.bin" "$W/bkeys/default.jwe.mykey"
    local LOG="$W/pub/.tn/tn/logs/tn.ndjson"
    if { [ "$rd" = py ] && pym jwe_proof.py read "$LOG" "$W/bkeys" "$sec" || [ "$rd" = ts ] && ts jwe_proof.mts read "$LOG" "$W/bkeys" "$sec"; } 2>"$W/read.err" | grep -q OK; then
      echo "PASS jwe pub=$pub read=$rd run=$run"; pass=$((pass+1))
    else echo "FAIL(read) jwe pub=$pub read=$rd run=$run"; tail -2 "$W/read.err"; fail=$((fail+1)); fi
  done; done; done
  echo "=== JWE add_recipient cross-lang: $pass passed / $fail failed (of 12) ==="
}

prove_hibe() {
  local pass=0 fail=0
  for auth in py ts; do for rd in py ts; do for run in 1 2 3; do
    local W="$TMP/hibe_${auth}_${rd}_${run}"; mkdir -p "$W/auth" "$W/reader"
    local sec="hello-${auth}-${rd}-${run}"
    # 1. Reader mints its own ceremony first and prints its real DID. The grant
    #    kit is sealed to the reader's device key, so the authority must know
    #    the reader's actual DID before granting (an intercepted kit is useless
    #    to anyone else). Grabbing a fake DID here would fail the unseal below.
    local RDID
    if [ "$rd" = py ]; then RDID="$(pym hibe_proof.py readerinit "$W/reader/tn.yaml" 2>"$W/ri.err")"; else RDID="$(ts hibe_proof.mts readerinit "$W/reader/tn.yaml" 2>"$W/ri.err")"; fi
    RDID="$(printf '%s' "$RDID" | tr -d '\r' | tail -1)"
    if [ -z "$RDID" ]; then echo "FAIL(readerinit) hibe auth=$auth read=$rd run=$run"; tail -3 "$W/ri.err"; fail=$((fail+1)); continue; fi
    # 2. Authority grants to the reader's real DID and emits.
    if [ "$auth" = py ]; then pym hibe_proof.py auth "$W/auth/tn.yaml" "$W/kit.tnpkg" "$sec" "$RDID"; else ts hibe_proof.mts auth "$W/auth/tn.yaml" "$W/kit.tnpkg" "$sec" "$RDID"; fi >/dev/null 2>"$W/auth.err" \
      || { echo "FAIL(auth) hibe auth=$auth read=$rd run=$run"; tail -2 "$W/auth.err"; fail=$((fail+1)); continue; }
    # 3. Reader absorbs (unseals the kit with its device key).
    if [ "$rd" = py ]; then pym hibe_proof.py absorb "$W/reader/tn.yaml" "$W/kit.tnpkg"; else ts hibe_proof.mts absorb "$W/reader/tn.yaml" "$W/kit.tnpkg"; fi >/dev/null 2>"$W/abs.err" \
      || { echo "FAIL(absorb) hibe auth=$auth read=$rd run=$run"; tail -2 "$W/abs.err"; fail=$((fail+1)); continue; }
    local LOG="$W/auth/.tn/tn/logs/tn.ndjson"
    if { [ "$rd" = py ] && pym hibe_proof.py read "$LOG" "$W/reader/.tn/tn/keys" "$sec" || [ "$rd" = ts ] && ts hibe_proof.mts read "$LOG" "$W/reader/.tn/tn/keys" "$sec"; } 2>"$W/read.err" | grep -q OK; then
      echo "PASS hibe auth=$auth read=$rd run=$run"; pass=$((pass+1))
    else echo "FAIL(read) hibe auth=$auth read=$rd run=$run"; tail -2 "$W/read.err"; fail=$((fail+1)); fi
  done; done; done
  echo "=== HIBE grant_reader cross-lang: $pass passed / $fail failed (of 12) ==="
}

[ "$WHICH" = jwe ] || [ "$WHICH" = both ] && prove_jwe
[ "$WHICH" = hibe ] || [ "$WHICH" = both ] && prove_hibe
