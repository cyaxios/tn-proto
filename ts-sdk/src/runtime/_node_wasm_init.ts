// Eager wasm init for Node-side consumers.
//
// Importing this file as a side effect loads `tn_wasm_bg.wasm` from
// the resolved `tn-wasm` package directory and calls `initSync` on the
// pkg JS glue. After that, every named export from `tn-wasm` (and the
// TS wrappers in `src/core/signing.ts`, `src/raw.ts`, etc.) is callable
// immediately.
//
// Why this exists: the wasm-pack "nodejs" target's JS file declares a
// module-level `let wasm;` that's only populated by `initSync(...)` or
// `await default()`. The browser-bundle entry handles this via the
// inlined-bytes initSync trick (see scripts/build-browser-bundle.mjs);
// Node had no equivalent, so every NodeRuntime / DeviceKey.fromSeed
// call from a fresh import path used to throw
// `Cannot read properties of undefined (reading '__wbindgen_malloc')`.
// Importing this module from `src/index.ts` runs the init once at
// module load and the rest of the SDK works.
//
// initSync is idempotent (it short-circuits when `wasm !== undefined`),
// so callers that also explicitly initSync — e.g. test scripts that
// pre-load the wasm to avoid an import-order dependency — pay nothing.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync } from "tn-wasm";

// `import.meta.resolve("tn-wasm")` returns the URL of the package's
// main entry (per package.json `main`). The `.wasm` binary sits in the
// same directory. Standard since Node 20.6; the SDK's engines field
// already requires Node >= 20.
const wasmJsUrl = import.meta.resolve("tn-wasm");
const wasmDir = dirname(fileURLToPath(wasmJsUrl));
const wasmBytes = readFileSync(resolve(wasmDir, "tn_wasm_bg.wasm"));

initSync({ module: wasmBytes });
