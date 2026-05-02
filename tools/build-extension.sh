#!/usr/bin/env bash
# tools/build-extension.sh — make extensions/tn-decrypt/ self-contained.
#
# Builds the TS SDK and copies the browser-safe Layer-1 modules the
# extension needs into extensions/tn-decrypt/vendor/sdk-core/. After
# this runs, the extension directory has no out-of-tree imports — you
# can zip it (or pass the path to "Load unpacked" in chrome://extensions)
# from anywhere and it works.
#
# Run this any time you change ts-sdk/src/core/encoding.ts or
# ts-sdk/src/core/emk.ts (or anything they transitively pull in). The
# script is idempotent — running twice is a no-op when nothing changed.
#
# Usage:
#   bash tools/build-extension.sh
#
# What it does NOT do:
#   - Build the wasm crate. The wasm artefacts under
#     extensions/tn-decrypt/wasm/ are produced by the tn-wasm Rust crate
#     and have their own pipeline (crypto/tn-wasm/build.sh).
#   - Bump manifest.json version. Do that by hand when shipping.
#   - Sign or zip for Chrome Web Store. Use chrome://extensions
#     "Pack extension" or `web-ext` for that.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="$REPO/ts-sdk"
EXT_DIR="$REPO/extensions/tn-decrypt"
VENDOR_DIR="$EXT_DIR/vendor/sdk-core"

echo "[ext-build] repo: $REPO"

# 1. Build the SDK (compiles src/ to dist/).
echo "[ext-build] npm run build"
(cd "$SDK_DIR" && npm run build)

# 2. Mirror the Layer-1 modules the extension actually imports. The list
#    matches unlock.js's re-export surface — keep it minimal so the
#    extension stays small. If unlock.js grows new re-exports, add the
#    backing module here.
mkdir -p "$VENDOR_DIR"
SDK_MODULES=(
  "encoding.js"
  "emk.js"
)

for mod in "${SDK_MODULES[@]}"; do
  src="$SDK_DIR/dist/core/$mod"
  if [[ ! -f "$src" ]]; then
    echo "[ext-build] MISSING: $src — did the build fail?" >&2
    exit 1
  fi
  cp "$src" "$VENDOR_DIR/$mod"
  echo "[ext-build]   vendored $mod ($(wc -c < "$src") bytes)"
done

# 3. Sanity-check: no extension file should import from outside the
#    extension dir. Catches accidental "../" path regressions in
#    unlock.js or any future helper.
echo "[ext-build] verifying self-containment"
bad="$(grep -RnE 'from\s+["'\'']\.\./\.\.' "$EXT_DIR" --include='*.js' \
       --exclude-dir=vendor --exclude-dir=wasm --exclude-dir=test || true)"
if [[ -n "$bad" ]]; then
  echo "[ext-build] FAIL: out-of-tree imports found:" >&2
  echo "$bad" >&2
  exit 1
fi

echo "[ext-build] OK — extensions/tn-decrypt/ is self-contained."
echo "[ext-build] load unpacked: chrome://extensions → Developer mode → Load unpacked → pick $EXT_DIR"
