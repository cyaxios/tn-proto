# tn-wasm

WebAssembly bindings for `tn-core`. Sibling crate to `tn-py` (PyO3).
One Rust core, many bindings: Python gets `tn_core`, JS/TS gets `tn_wasm`.

## Phase A surface

Minimal: `adminReduce`, `adminCatalogKinds`, `adminValidateEmit`. Enough
to prove byte-identical behavior with Python before expanding.

Later phases add `canonicalJson`, `computeRowHash`, `buildEnvelope`,
`verifyEnvelope`, `signMessage`, `btnEncrypt`, `btnDecrypt`.

## Build

```
cd tn-protocol/crypto/tn-wasm
wasm-pack build --target nodejs --release
```

Output lands in `pkg/`. Gitignored. Regenerate whenever Rust changes.

For browser targets:

```
wasm-pack build --target web --release --out-dir pkg-web
```

Serve the crate root over HTTP and open `test/browser-smoke.html` to run
the same admin catalog, canonical JSON, and Ed25519 sign-verify checks
entirely in the browser. A launch config named `tn-wasm-browser` is
wired into `.claude/launch.json` so agents can preview it on port
8765.

## Interop test

```
node tn-protocol/crypto/tn-wasm/test/node_smoke.mjs
.venv/Scripts/python.exe tn-protocol/crypto/tn-wasm/test/py_cross_check.py
```

Or both:

```
bash tn-protocol/crypto/tn-wasm/test/run_interop.sh
```

Node exercises the WASM surface. Python runs the same fixtures through
`tn_core.admin.reduce` (the PyO3 binding) and diffs the JSON outputs
key by key, sorted, so whitespace and ordering cannot hide drift.

## Null handling (subtle but important)

`serde-wasm-bindgen` defaults serialize `Option::None` as `undefined`,
which drops keys like `recipient_did: null` on the way out. We go
through `JSON.stringify` and `JSON.parse` instead so null is preserved
end to end. If you add new bindings, use `js_to_json` and `json_to_js`
from `lib.rs`.
