import { test } from "node:test";
import { strict as assert } from "node:assert";

import { compileFilter, type FilterSpec } from "../src/handlers/base.js";

// Cross-SDK filter parity with python/tn/handlers/filter.py: all 7
// predicates, AND-ed, with the `sync`-missing-means-true rule.

function env(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { event_type: "tn.test", level: "info", ...over };
}

test("empty filter matches everything", () => {
  const f = compileFilter(undefined);
  assert.equal(f(env()), true);
  assert.equal(f(env({ event_type: "anything", level: "debug" })), true);
});

test("event_type / prefix / not_prefix / in predicates", () => {
  assert.equal(compileFilter({ eventType: "tn.test" })(env()), true);
  assert.equal(compileFilter({ eventType: "tn.other" })(env()), false);
  assert.equal(compileFilter({ eventTypePrefix: "tn." })(env()), true);
  assert.equal(compileFilter({ eventTypePrefix: "auth." })(env()), false);
  assert.equal(compileFilter({ notEventTypePrefix: "auth." })(env()), true);
  assert.equal(compileFilter({ notEventTypePrefix: "tn." })(env()), false);
  assert.equal(compileFilter({ eventTypeIn: ["a", "tn.test"] })(env()), true);
  assert.equal(compileFilter({ eventTypeIn: ["a", "b"] })(env()), false);
});

test("level / level_in predicates", () => {
  assert.equal(compileFilter({ level: "info" })(env()), true);
  assert.equal(compileFilter({ level: "error" })(env()), false);
  assert.equal(compileFilter({ levelIn: ["info", "warning"] })(env()), true);
  assert.equal(compileFilter({ levelIn: ["error"] })(env()), false);
});

test("sync predicate — missing sync field is treated as true", () => {
  // Envelope with no `sync` field -> effective true.
  assert.equal(compileFilter({ sync: true })(env()), true);
  assert.equal(compileFilter({ sync: false })(env()), false);
  // Explicit sync values.
  assert.equal(compileFilter({ sync: true })(env({ sync: true })), true);
  assert.equal(compileFilter({ sync: true })(env({ sync: false })), false);
  assert.equal(compileFilter({ sync: false })(env({ sync: false })), true);
});

test("all predicates AND together", () => {
  const spec: FilterSpec = { eventTypePrefix: "tn.", levelIn: ["info", "warning"], sync: true };
  const f = compileFilter(spec);
  assert.equal(f(env()), true);
  assert.equal(f(env({ level: "error" })), false); // level fails
  assert.equal(f(env({ event_type: "auth.x" })), false); // prefix fails
  assert.equal(f(env({ sync: false })), false); // sync fails
});
