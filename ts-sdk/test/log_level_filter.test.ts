// AVL J3.2 — log-level filtering parity. setLevel("error") drops
// debug/info/warning emits before any work happens; severity-less log()
// always emits regardless.

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { LOG_LEVELS } from "../src/index.js";
import { Tn } from "../src/tn.js";

test("setLevel('error') filters debug/info/warning, keeps error + log()", async () => {
  // Snapshot + restore the threshold so concurrent tests don't leak.
  const priorLevel = Tn.getLevel();
  const c = await Tn.ephemeral({ stdout: false });
  try {
    // Default is debug — everything passes.
    assert.equal(Tn.isEnabledFor("debug"), true);
    assert.equal(Tn.isEnabledFor("info"), true);

    Tn.setLevel("error");
    assert.equal(Tn.getLevel(), "error");
    assert.equal(Tn.isEnabledFor("debug"), false);
    assert.equal(Tn.isEnabledFor("info"), false);
    assert.equal(Tn.isEnabledFor("warning"), false);
    assert.equal(Tn.isEnabledFor("error"), true);

    c.debug("evt.dropped_debug", { marker: "x" });
    c.info("evt.dropped_info", { marker: "x" });
    c.warning("evt.dropped_warn", { marker: "x" });
    c.error("evt.kept_error", { marker: "x" });
    c.log("evt.always", { marker: "severity_less" });

    const events = new Set<string>();
    for (const entry of c.read({ raw: true })) {
      const t = (entry as { envelope: Record<string, unknown> }).envelope["event_type"];
      if (typeof t === "string") events.add(t);
    }

    assert.ok(events.has("evt.kept_error"), `missing error: ${[...events]}`);
    assert.ok(events.has("evt.always"), `missing severity-less: ${[...events]}`);
    assert.ok(!events.has("evt.dropped_debug"), `debug should be filtered`);
    assert.ok(!events.has("evt.dropped_info"), `info should be filtered`);
    assert.ok(!events.has("evt.dropped_warn"), `warning should be filtered`);
  } finally {
    Tn.setLevel(priorLevel as Parameters<typeof Tn.setLevel>[0]);
    await c.close();
  }
});

test("LOG_LEVELS exports stdlib-aligned numeric values", () => {
  assert.equal(LOG_LEVELS.debug, 10);
  assert.equal(LOG_LEVELS.info, 20);
  assert.equal(LOG_LEVELS.warning, 30);
  assert.equal(LOG_LEVELS.error, 40);
});

test("setLevel rejects unknown level names", () => {
  const prior = Tn.getLevel();
  try {
    assert.throws(() => Tn.setLevel("trace" as never), /unknown log level/);
    assert.throws(() => Tn.setLevel("verbose" as never), /unknown log level/);
  } finally {
    Tn.setLevel(prior as Parameters<typeof Tn.setLevel>[0]);
  }
});
