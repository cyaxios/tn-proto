/**
 * Eager wasm `initSync` for Node-side consumers.
 *
 * **Side-effect module** — importing this file runs the wasm init. There
 * are no named exports to call; the file's purpose is to populate the
 * tn-wasm package's module-level `wasm` reference at import time so
 * every wasm-bound symbol (`BtnPublisher`, `WasmRuntime`,
 * `deviceKeyFromSeed`, `zeroHash`, ...) is callable from the very next
 * line of consumer code.
 *
 * ## Why this exists
 *
 * The wasm-pack "nodejs" pkg target ships a JS glue file whose named
 * exports all reference a module-level `let wasm;` that's `undefined`
 * until `initSync({module: bytes})` or `await default()` is called.
 * The browser bundle handles this in its build entry
 * ({@link https://github.com/cyaxios/tn-protocol/blob/main/ts-sdk/scripts/build-browser-bundle.mjs | scripts/build-browser-bundle.mjs} —
 * inlines the .wasm via esbuild's binary loader, top-level-awaits the
 * `initSync`). Node has no such bundle step, so without this module
 * every `DeviceKey.fromSeed(...)` or `WasmRuntime.initWith(...)` call
 * from a fresh import path throws:
 *
 * ```text
 * TypeError: Cannot read properties of undefined (reading '__wbindgen_malloc')
 * ```
 *
 * ## Where it's imported
 *
 * - `src/index.ts` — covers public consumers (`import {...} from "@tnproto/sdk"`).
 * - `src/runtime/node_runtime.ts` — covers callers that import `Tn` or
 *   `NodeRuntime` directly via the relative path `../src/tn.js`,
 *   bypassing the public index.
 *
 * Tests load it once more via `test/_setup_wasm.mjs` plus
 * `node --import` so even browser-contract tests that import only
 * Layer 1 symbols get the wasm.
 *
 * ## Idempotency
 *
 * `initSync` short-circuits when `wasm !== undefined`. Callers that
 * pre-load wasm explicitly (e.g. test scripts that initSync from raw
 * bytes for control over ordering) pay nothing here.
 *
 * @packageDocumentation
 * @internal
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync } from "tn-wasm";

// `import.meta.resolve("tn-wasm")` returns the URL of the package's
// main entry (per package.json `main`). The `.wasm` binary sits in the
// same directory. Standard since Node 20.6; the SDK's `engines` field
// already requires Node >= 20.
const wasmJsUrl = import.meta.resolve("tn-wasm");
const wasmDir = dirname(fileURLToPath(wasmJsUrl));
const wasmBytes = readFileSync(resolve(wasmDir, "tn_wasm_bg.wasm"));

initSync({ module: wasmBytes });
