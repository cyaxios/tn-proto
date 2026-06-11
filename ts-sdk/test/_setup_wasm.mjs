// Test-runner-level wasm init.
//
// Loaded via `node --import ./test/_setup_wasm.mjs --test ...` so it
// runs ONCE before any test file gets imported.
//
// The nodejs target of tn-wasm (the file: dep ts-sdk consumes) auto-
// instantiates the .wasm at module load time — see the bottom of
// `pkg/tn_wasm.js`:
//
//     const wasmBytes = require('fs').readFileSync(...);
//     const wasmModule = new WebAssembly.Module(wasmBytes);
//     let wasm = new WebAssembly.Instance(...).exports;
//     wasm.__wbindgen_start();
//
// So a bare side-effect `import "tn-wasm"` here is enough: every
// wasm-bound export is callable as soon as the module finishes
// loading, regardless of whether a given test file goes through
// `src/index.ts` (which also imports tn-wasm) or imports browser-safe
// Layer 1 modules directly.
//
// `initSync` is NOT exported by the nodejs-target glue — only by the
// web / bundler targets. Earlier versions of this file called
// `initSync({module: bytes})` here, which silently failed at runtime
// (`initSync is undefined`) and broke the typecheck on the now-removed
// `src/runtime/_node_wasm_init.ts`.
import "tn-wasm";
