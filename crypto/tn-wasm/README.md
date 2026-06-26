# tn-wasm

WebAssembly bindings for `tn-core`, for Node and the browser. Sibling to
the PyO3 path: one Rust core, many bindings. Python gets `tn._native`,
JavaScript and TypeScript get `tn_wasm`. The TypeScript SDK consumes the
output of this crate.

## What it exposes

The bindings cover canonical JSON, the row-hash chain, indexing, Ed25519
signing and verification, envelope build and verify, the admin catalog
and reducer, btn encrypt and decrypt, and `.tnpkg` read and write. With
the `runtime` feature (on by default) it also exports `WasmRuntime`,
which surfaces the tn-core `Runtime` to JS over an injected
`JsStorageAdapter` rather than touching the filesystem directly. The
Rust reducer is the source of truth: every JSON output must match what
the PyO3 path produces, byte for byte.

Every export uses a camelCase `js_name` so the generated `.d.ts` reads
like idiomatic TypeScript; internal Rust names stay snake_case.

## Build

```
wasm-pack build --target nodejs --release
```

Output lands in `pkg/` (gitignored; regenerate whenever the Rust
changes). For browser targets:

```
wasm-pack build --target web --release --out-dir pkg-web
```

To build the minimal crypto-only surface without `WasmRuntime`, opt out:
`wasm-pack build --no-default-features`.

## Notes

tn-core is pulled in with `default-features = false` (no `fs-locking`,
since `fs4 -> rustix -> errno` will not compile for
`wasm32-unknown-unknown`; single-process wasm has no writer to race).

JS values round-trip through `JSON.stringify` / `JSON.parse` rather than
the `serde-wasm-bindgen` default, which maps `Option::None` to
`undefined` and would drop keys like `recipient_did: null`. New bindings
should use the `js_to_json` / `json_to_js` helpers in `lib.rs`.

## Interop test

```
node test/node_smoke.mjs
.venv/Scripts/python.exe test/py_cross_check.py
```

Node exercises the WASM surface; Python runs the same fixtures through
the PyO3 binding and diffs the JSON key by key, sorted, so whitespace and
ordering cannot hide drift. `test/run_interop.sh` runs both.
