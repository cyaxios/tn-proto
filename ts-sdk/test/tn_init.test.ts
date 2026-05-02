import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Tn } from "../src/tn.js";

test("Tn.ephemeral returns a working instance", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const receipt = tn.info("smoke.test", { ok: 1 });
    assert.equal(typeof receipt.eventId, "string");
    assert.equal(typeof receipt.rowHash, "string");
  } finally {
    await tn.close();
  }
});

test("Tn.setLevel filters emits below threshold", () => {
  Tn.setLevel("info");
  try {
    assert.equal(Tn.isEnabledFor("debug"), false);
    assert.equal(Tn.isEnabledFor("info"), true);
    assert.equal(Tn.isEnabledFor("warning"), true);
  } finally {
    Tn.setLevel("debug");
  }
});

test("Tn.read iterates emitted entries", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("evt.a", { x: 1 });
    tn.info("evt.b", { x: 2 });
    const entries = [...tn.read()];
    assert.equal(entries.length, 2);
    const first = entries[0] as Record<string, unknown>;
    const second = entries[1] as Record<string, unknown>;
    assert.equal(first["event_type"], "evt.a");
    assert.equal(second["event_type"], "evt.b");
  } finally {
    await tn.close();
  }
});
