// Scenario ex06 — yaml-driven multi-handler fan-out with event_type filters.
//
// Python original: tn_proto/python/examples/ex06_multi_handler.py
//
// PORT STATUS: STRUCTURAL SKIP (outcome c)
//
// WHY SKIPPED
// -----------
// The Python example works by appending a `handlers:` YAML block with three
// entries of kind `file.rotating` and `file.timed_rotating`, re-calling
// `tn.init(yamlPath)` to pick up the new handlers, then asserting per-file
// line counts (tn.ndjson = 6, auth.ndjson = 2, pages.ndjson = 2).
//
// The TS SDK's handler registry (`src/handlers/registry.ts → buildHandlers`)
// recognises these kinds:
//   vault.push, vault.pull, fs.drop, fs.scan, stdout
//
// `file.rotating` and `file.timed_rotating` are NOT in that list. When
// `buildHandlers` encounters an unknown `kind` it throws:
//   Error: tn.yaml: unknown handler kind "file.rotating" on handler "everything"
//
// Additionally, the TS runtime does not call `buildHandlers` at all during
// `Tn.init()` — the yaml `handlers:` block is read into `config.handlers` for
// informational use (FINDINGS S0.4 stdout-suppression logic) but is NOT
// instantiated into live handler objects. File fan-out in the TS runtime is
// handled by the single hardcoded `FileHandler` that the runtime opens on the
// `logs.path` key.
//
// WHAT NEEDS TO CHANGE TO UNBLOCK THIS TEST
// ------------------------------------------
// 1. Add `file.rotating` (and optionally `file.timed_rotating`) to
//    `buildHandlers` in `src/handlers/registry.ts`, wiring them to the
//    existing `FileHandler` class in `src/handlers/file.ts`.
// 2. Call `buildHandlers(config.handlers, ...)` during `NodeRuntime.init()`
//    so yaml-declared handlers are registered as live fan-out targets.
// 3. Wire the yaml `filter.event_type.starts_with` field to
//    `FilterSpec.eventTypePrefix` in the filter compilation step
//    (Python uses `starts_with:` as the sub-key; the TS `compileFilter` in
//    `src/handlers/base.ts` uses `eventTypePrefix`).
//
// FILTER MAPPING NOTE
// -------------------
// Python yaml filter shape:
//   filter:
//     event_type:
//       starts_with: "auth."
//
// TS FilterSpec (src/handlers/base.ts):
//   { eventTypePrefix: "auth." }
//
// The registry would need to translate the nested yaml shape to the flat
// FilterSpec before passing to the handler constructor.
//
// Once those three gaps are closed, this test can be ported directly:
// write the yaml, Tn.init(yamlPath) picks up the three handlers, emit
// the 6 events, assert line counts in the three output files.

import { test } from "node:test";

test("ex06/multi-handler-fan-out — yaml file.rotating handlers with event_type filters", (t) => {
  t.skip(
    "TS SDK gap: file.rotating / file.timed_rotating kinds are not wired into " +
      "buildHandlers (src/handlers/registry.ts). " +
      "See comment at top of this file for the three changes needed to unblock.",
  );
});
