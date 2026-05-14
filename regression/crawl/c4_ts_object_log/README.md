# C4 — TS object-level logging

**Status: scaffolded, no tests yet. Implemented in the C2+C4 PR.**

## What this silo proves

`Tn` class instance round-trip on the TS side:

```typescript
import { Tn } from "@tnproto/sdk";

const t = await Tn.init(yamlPath);
t.info("app.hello", { a: 1 });
const entries = Array.from(t.read());
await t.close();
```

Same observable outcome as C3, different dispatch path: the `Tn` class
holds its own `NodeRuntime` instance. Mirrors C2 on the Python side —
catches bugs that only appear when a process holds multiple `Tn`
instances or when the module-level vs instance-level paths drift.

## Why it's load-bearing

Any Node service that owns multiple ceremonies (witness server,
multi-tenant tooling) goes through the class-level path. If it
diverges from module-level, those consumers get inconsistent
behavior.

## Code paths exercised

- `ts-sdk/src/tn.ts:Tn` class — instance constructor + methods
- `ts-sdk/src/runtime/node_runtime.ts:emit / read` — per-instance dispatch
- `ts-sdk/src/multi.ts` — named-ceremony registry (instance lookups)

## Tests to add (in the C2+C4 PR)

- `instance_round_trip.test.ts` — `Tn.init()` → `t.info()` → `t.read()` round-trip
- `instance_close_releases.test.ts` — `t.close()` drops resources
- `module_vs_instance_parity.test.ts` — same inputs produce identical envelopes regardless of which API

## How to run only this silo

```bash
make -C regression c4
```

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| `Tn.init()` rejects | `tn.ts:Tn.init` factory + `node_runtime.ts:NodeRuntime.init` |
| `t.info` writes to wrong ceremony | `tn.ts:Tn.info` delegation + per-instance NodeRuntime |
| `t.close()` leaves wasm runtime alive | `node_runtime.ts:close` + wasm `WasmRuntime.close_js` |
| Instance and module results disagree | `tn.ts` module re-exports vs class methods — diff signatures |
