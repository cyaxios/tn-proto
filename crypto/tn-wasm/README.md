# tn-wasm

WebAssembly bindings for `tn-core`, for Node and the browser. Sibling to
the PyO3 path: one Rust core, many bindings. Python gets `tn._native`,
JavaScript and TypeScript get `tn_wasm`. The TypeScript SDK consumes the
output of this crate.

## What it exposes

The bindings cover canonical JSON, the row-hash chain, indexing, Ed25519
signing and verification, envelope build and verify, the admin catalog
and reducer, btn encrypt and decrypt, standalone HIBE primitives
(`hibeSetup`, `hibeKeygen`, `hibeKemWrap`, and siblings), and `.tnpkg`
read and write. With the `runtime` feature (on by default) it also
exports `WasmRuntime`, which surfaces the tn-core `Runtime` to JS over an
injected `JsStorageAdapter` rather than touching the filesystem directly.
The Rust reducer is the source of truth: every JSON output must match what
the PyO3 path produces, byte for byte.

Cipher support:

- `WasmRuntime` supports BTN runtime groups through tn-core.
- HIBE is available through low-level WASM primitive exports. The TypeScript
  runtime uses these primitives for HIBE groups.
- The TypeScript SDK uses the JS JOSE pipeline for `cipher: jwe`.
  Native Rust applications use tn-core's `native-jwe` feature.

Every export uses a camelCase `js_name` so the generated `.d.ts` reads
like idiomatic TypeScript; internal Rust names stay snake_case.

## Build

Run the build commands from the repository's `crypto/tn-wasm/` directory:

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
The `runtime` feature enables tn-core's `fs` feature. HIBE uses the
standalone WASM primitive exports; TypeScript JWE uses JS JOSE.

JS values round-trip through `JSON.stringify` / `JSON.parse` rather than
the `serde-wasm-bindgen` default, which maps `Option::None` to
`undefined` and would drop keys like `recipient_did: null`. New bindings
should use the `js_to_json` / `json_to_js` helpers in `lib.rs`.

## Interop test

After building the Node target, run the conformance check from the repository root:

```shell
node crypto/tn-wasm/test/conformance_golden.mjs
```

This is the [CI check](../../.github/workflows/ci.yml) for the shared
[conformance vectors](../tn-core/tests/fixtures/README.md). It compares WASM
results with the retained Rust/Python vectors.
