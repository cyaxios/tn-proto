# C4 — TS object-level logging

## What this silo proves

`Tn` class instance round-trip on the TS side:

```typescript
import { Tn } from "@tnproto/sdk";

const t = await Tn.use("payments");        // class-level use
t.info("payments.charge", { amount: 1000 });
const entries = Array.from(t.read());      // only sees payments' entries
await t.close();
```

Same observable outcome as C3 (module-level), different dispatch path:
each `Tn` instance holds its own `NodeRuntime`. Mirrors C2 on the
Python side.

## Why it's load-bearing

Any Node service that owns multiple ceremonies (witness server, the
vault itself, multi-tenant tooling) goes through the class-level path.
If it diverges from module-level, those consumers get inconsistent
behavior. The TS-side multi-ceremony rework had its own version of Bug
#1 (handle interning collision via `Tn.use`); this silo regresses against
re-drift.

## Code paths exercised

- `ts-sdk/src/tn.ts:Tn` — class definition + instance methods
- `ts-sdk/src/tn.ts:Tn.use` — registry + interning by
  `(projectDir, name)` (Bug 8 fix)
- `ts-sdk/src/multi.ts:ensureCeremonyOnDisk` + `ceremonyYamlPath`
- `ts-sdk/src/runtime/node_runtime.ts:emit / read` — per-instance
  dispatch

## Tests in this silo

- `handle_round_trip.test.ts` — `Tn.use(name).info(...)` writes; same
  handle's `read()` returns the entry.
- `multi_ceremony_isolation.test.ts` — payments and billing handles
  don't cross-contaminate.
- `handle_severity_verbs.test.ts` — info/warning/error/debug/log
  methods stamp the correct level.

## How to run only this silo

```
make c4
```

No vault contact — the tests don't call `link` or wire up vault
handlers.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `Tn.use("name")` rejects | `tn.ts:Tn.use` name validation regex |
| Handle's `t.info` writes to wrong ceremony | `tn.ts:Tn` instance methods — per-instance NodeRuntime dispatch |
| Two handles share state | the `_registry` cache key in `tn.ts:Tn.use` — (projectDir, name) tuple must be distinct |
| `t.read()` returns empty unexpectedly | wasm runtime loaded an empty/wrong yaml; check `node_runtime.ts` log-path resolution |
