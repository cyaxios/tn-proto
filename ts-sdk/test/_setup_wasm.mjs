// Test-runner-level wasm init.
//
// Loaded via `node --import ./test/_setup_wasm.mjs --test ...` so it
// runs ONCE before any test file gets imported. Calls `initSync` on
// the tn-wasm pkg glue with the .wasm bytes off disk; after that,
// every wasm-backed export is callable from any test, regardless of
// whether that test goes through `src/index.ts` (which has its own
// init) or imports browser-safe Layer 1 modules directly (which
// deliberately do not — they're tested for browser-safety).
//
// initSync is idempotent — production paths that init themselves
// (NodeRuntime.attachWasm via src/runtime/_node_wasm_init.ts) keep
// working.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync } from "tn-wasm";

const wasmJsUrl = import.meta.resolve("tn-wasm");
const wasmDir = dirname(fileURLToPath(wasmJsUrl));
const wasmBytes = readFileSync(resolve(wasmDir, "tn_wasm_bg.wasm"));
initSync({ module: wasmBytes });
