// AVL J3.2 — log-level filtering parity. setLevel("error") drops
// debug/info/warning emits before any work happens; severity-less log()
// always emits regardless.

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { TNClient, LOG_LEVELS } from "../src/index.js";

test("setLevel('error') filters debug/info/warning, keeps error + log()", () => {
  // Snapshot + restore the threshold so concurrent tests don't leak.
  const priorLevel = TNClient.getLevel();
  const c = TNClient.ephemeral({ stdout: false });
  try {
    // Default is debug — everything passes.
    assert.equal(TNClient.isEnabledFor("debug"), true);
    assert.equal(TNClient.isEnabledFor("info"), true);

    TNClient.setLevel("error");
    assert.equal(TNClient.getLevel(), "error");
    assert.equal(TNClient.isEnabledFor("debug"), false);
    assert.equal(TNClient.isEnabledFor("info"), false);
    assert.equal(TNClient.isEnabledFor("warning"), false);
    assert.equal(TNClient.isEnabledFor("error"), true);

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
    TNClient.setLevel(priorLevel as Parameters<typeof TNClient.setLevel>[0]);
    c.close();
  }
});

test("LOG_LEVELS exports stdlib-aligned numeric values", () => {
  assert.equal(LOG_LEVELS.debug, 10);
  assert.equal(LOG_LEVELS.info, 20);
  assert.equal(LOG_LEVELS.warning, 30);
  assert.equal(LOG_LEVELS.error, 40);
});

test("setLevel rejects unknown level names", () => {
  const prior = TNClient.getLevel();
  try {
    assert.throws(() => TNClient.setLevel("trace" as never), /unknown log level/);
    assert.throws(() => TNClient.setLevel("verbose" as never), /unknown log level/);
  } finally {
    TNClient.setLevel(prior as Parameters<typeof TNClient.setLevel>[0]);
  }
});
