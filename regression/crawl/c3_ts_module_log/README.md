# C3 — TS module-level logging

**Status: scaffolded, no tests yet. Implemented in the C1+C3 PR.**

## What this silo proves

The simplest possible TN-protocol round-trip on the Node-TS side, using
the top-level module verbs:

```typescript
import * as tn from "tn-proto";

await tn.init(yamlPath);
tn.info("app.hello", { a: 1 });
const entries = Array.from(tn.read());
```

Mirrors C1's contract on the TS side. After 0.4.1's slim-down the TS
runtime delegates emit/read through `WasmRuntime` → `tn-core::Runtime`,
so this also indirectly proves the wasm boundary is intact.

## Why it's load-bearing

The Node-TS surface is consumed by witness server (future), CF Workers
(future), and any in-house tooling on the Node side. If module-level
logging is broken on TS, every Node consumer is broken.

## Code paths exercised

- `ts-sdk/src/tn.ts` — top-level module exports
- `ts-sdk/src/runtime/node_runtime.ts:emit` — slim-down delegate to wasm
- `ts-sdk/src/runtime/storage_node.ts` — Node fs storage adapter
- `crypto/tn-wasm/src/runtime.rs:WasmRuntime` — wasm runtime entry
- `ts-sdk/src/runtime/wasm_shim.ts:lastEmitReceipt` — receipt synthesis from log

## Tests to add (in the C1+C3 PR)

- `default_handlers.test.ts` — round-trip + both default handlers produce output
- `file_handler_only.test.ts` — stdout-disabled, file output still produced
- `stdout_handler_only.test.ts` — file disabled, stdout still produces lines

## How to run only this silo

```bash
make -C regression c3
# or, from ts-sdk/
cd ts-sdk && node --import tsx --test ../regression/crawl/c3_ts_module_log/*.test.ts
```

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| `tn.init(...)` throws | `tn.ts` init entry + `node_runtime.ts:attachWasm` |
| wasm path traps on emit | `wasm_runtime.rs:emit_js` + `time/wasm-bindgen` feature gate |
| `read()` returns empty | `node_runtime.ts:read()` — admin-log merge + filter chain |
| Receipt fields wrong | `wasm_shim.ts:lastEmitReceipt` — verify log path argument |
