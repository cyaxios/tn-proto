#!/usr/bin/env bash
# Local release rehearsal — run the entire real release pipeline EXCEPT the
# irreversible steps (real PyPI upload, `npm publish`, pushing a `v*` tag).
#
# Run it as many times as you like; it never publishes for real. The goal is a
# clean, deterministic dry-run before any actual release. "For real" is the
# same pipeline with publishing switched on, driven by the tagged GitHub
# workflows (release-python.yml / release-typescript.yml).
#
# Usage (from repo root, in WSL `codex`):
#   bash tools/release.sh                 # full rehearsal
#   bash tools/release.sh --ts-repeat 3   # run the TS suite 3x to check determinism
#   bash tools/release.sh --reuse-venv    # reuse the previous python venv (faster reruns)
#   bash tools/release.sh --skip rust,pkg # skip named stages (gate,rust,wasm,py,ts,pkg)
#
# Every stage's full output is written to .release-rehearsal/<stage>.log; the
# console shows a PASS/FAIL summary at the end.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$ROOT/.release-rehearsal"
VENV="$WORK/venv"
LOGS="$WORK/logs"
TS_REPEAT=1
REUSE_VENV=0
SKIP=""

while [ $# -gt 0 ]; do
  case "$1" in
    --ts-repeat) TS_REPEAT="$2"; shift 2 ;;
    --reuse-venv) REUSE_VENV=1; shift ;;
    --skip) SKIP="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$LOGS"
declare -a NAMES=() RESULTS=() TIMES=()

skipped() { case ",$SKIP," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# run <stage-key> <human label> <command...>
run() {
  local key="$1" label="$2"; shift 2
  if skipped "$key"; then
    NAMES+=("$label"); RESULTS+=("SKIP"); TIMES+=("-")
    printf '  [SKIP] %s\n' "$label"; return 0
  fi
  printf '\n=== %s ===\n' "$label"
  local log="$LOGS/$key.log" start end
  start=$SECONDS
  if "$@" >"$log" 2>&1; then
    end=$SECONDS
    NAMES+=("$label"); RESULTS+=("PASS"); TIMES+=("$((end-start))s")
    printf '  [PASS] %s (%ss) — %s\n' "$label" "$((end-start))" "$log"
  else
    end=$SECONDS
    NAMES+=("$label"); RESULTS+=("FAIL"); TIMES+=("$((end-start))s")
    printf '  [FAIL] %s (%ss) — see %s\n' "$label" "$((end-start))" "$log"
    printf '  ---- tail ----\n'; tail -n 15 "$log" | sed 's/^/  | /'
  fi
}

# ---- Stage commands ---------------------------------------------------------

stage_gate_version() { python3 tools/bump.py --check; }

stage_rust() {
  cargo check --workspace --manifest-path Cargo.toml && \
  cargo test --workspace --manifest-path Cargo.toml
}

stage_wasm() {
  ( cd crypto/tn-wasm && \
    wasm-pack build --target nodejs --release && \
    wasm-pack build --target web --release --out-dir pkg-web )
}

stage_py() {
  if [ "$REUSE_VENV" = 0 ] || [ ! -x "$VENV/bin/python" ]; then
    rm -rf "$VENV" && python3 -m venv "$VENV"
  fi
  "$VENV/bin/python" -m pip install --upgrade pip maturin >/dev/null && \
  ( cd python && "$VENV/bin/python" -m pip install -e . && \
    "$VENV/bin/python" -m pip install pytest pytest-asyncio cryptography fastapi httpx ) && \
  ( cd python && "$VENV/bin/python" -m pytest tests/ --ignore=tests/integration --tb=short -q )
}

stage_ts() {
  ( cd ts-sdk && (npm ci || npm install) && npm run typecheck && npm run lint ) || return $?
  # Run all N repeats and tally — never bail on the first failure, so
  # --ts-repeat can actually characterize flakiness (how many of N pass).
  local i fails=0
  for i in $(seq 1 "$TS_REPEAT"); do
    echo "----- npm test run $i/$TS_REPEAT -----"
    ( cd ts-sdk && npm test ) || fails=$((fails+1))
  done
  if [ "$fails" -ne 0 ]; then
    echo "TS suite failed $fails of $TS_REPEAT runs (flaky or broken)"
    return 1
  fi
}

stage_pkg() {
  # Python wheel: build host wheel, twine check, fresh-venv install + import.
  rm -rf "$WORK/dist" && mkdir -p "$WORK/dist"
  "$VENV/bin/python" -m pip install --upgrade build twine >/dev/null
  ( cd python && "$VENV/bin/python" -m maturin build --release --out "$WORK/dist" ) && \
  "$VENV/bin/python" -m twine check "$WORK/dist"/*.whl && \
  rm -rf "$WORK/smoke-venv" && python3 -m venv "$WORK/smoke-venv" && \
  "$WORK/smoke-venv/bin/python" -m pip install "$WORK/dist"/*.whl >/dev/null && \
  "$WORK/smoke-venv/bin/python" -c "import tn; print('python wheel import OK', tn.__version__)" && \
  # npm tarball: pack (runs prepack->build->gen:version), then install + import.
  ( cd ts-sdk && npm pack --pack-destination "$WORK/dist" ) && \
  rm -rf "$WORK/ts-smoke" && mkdir -p "$WORK/ts-smoke" && \
  ( cd "$WORK/ts-smoke" && npm init -y >/dev/null && \
    npm install "$WORK/dist"/cyaxios-tn-proto-*.tgz >/dev/null && \
    node --input-type=module -e "import * as tn from '@cyaxios/tn-proto'; console.log('npm tarball import OK', tn.SDK_VERSION ?? '(no SDK_VERSION export)')" )
}

stage_publish_dry() {
  echo "DRY RUN — nothing is published. For real, a v* tag triggers:"
  echo "  - release-python.yml  (target=pypi)  -> PyPI"
  echo "  - release-typescript.yml (publish=true) -> npm @cyaxios/tn-proto"
  echo
  echo "npm publish --dry-run (shows the file manifest that WOULD ship):"
  ( cd ts-sdk && npm publish --dry-run ) || true
}

# ---- Run --------------------------------------------------------------------

echo "Release rehearsal — VERSION=$(cat VERSION 2>/dev/null || echo '?')   (dry-run, nothing published)"
run gate "Version consistency (bump.py --check)" stage_gate_version
run rust "Rust: cargo check + cargo test"        stage_rust
run wasm "Build tn-wasm (node + web)"            stage_wasm
run py   "Python: build + full pytest"           stage_py
run ts   "TypeScript: typecheck + lint + full suite (x$TS_REPEAT)" stage_ts
run pkg  "Package smoke (wheel + npm tarball install)" stage_pkg
run pub  "Publish (dry-run)"                     stage_publish_dry

# ---- Summary ----------------------------------------------------------------

echo
echo "================ REHEARSAL SUMMARY ================"
fail=0
for i in "${!NAMES[@]}"; do
  printf '  %-5s %-6s %s\n' "${RESULTS[$i]}" "${TIMES[$i]}" "${NAMES[$i]}"
  [ "${RESULTS[$i]}" = "FAIL" ] && fail=1
done
echo "==================================================="
if [ "$fail" = 0 ]; then
  echo "All stages green. Ready to consider a real release (push a v* tag)."
else
  echo "Some stages failed — see .release-rehearsal/logs/*.log. Fix and re-run."
fi
exit "$fail"
