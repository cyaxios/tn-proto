// Tests for `Tn.read()` shape — Entry default + raw + verify modes
// (post-0.4.0a1 thin read/watch refactor).

import { strict as assert } from "node:assert";
import { rmSync } from "node:fs";
import { test } from "node:test";

import { Entry } from "../src/Entry.js";
import { Tn } from "../src/tn.js";

async function makeEphemeral(): Promise<{ client: Tn; cleanup: () => Promise<void> }> {
  const client = await Tn.ephemeral();
  return {
    client,
    cleanup: async () => {
      try {
        await client.close();
      } catch {
        /* ignore */
      }
    },
  };
}

test("Tn.read() default returns Entry instances with envelope basics + decrypted fields", async () => {
  const { client, cleanup } = await makeEphemeral();
  try {
    client.info("order.created", { amount: 99, currency: "USD" });
    const entries: Entry[] = [];
    for (const e of client.read()) {
      if (e instanceof Entry) entries.push(e);
    }
    const biz = entries.find((e) => e.event_type === "order.created");
    assert.ok(biz, "must find the order.created entry");
    assert.equal(biz!.event_type, "order.created");
    assert.equal(biz!.level, "info");
    assert.ok(typeof biz!.device_identity === "string");
    assert.ok(biz!.timestamp instanceof Date);
    assert.ok(typeof biz!.sequence === "number");
    assert.ok(typeof biz!.event_id === "string");

    // Decrypted fields are in fields.
    assert.equal(biz!.fields["amount"], 99);
    assert.equal(biz!.fields["currency"], "USD");

    // Crypto plumbing surfaces as typed attributes (not fields).
    assert.ok(typeof biz!.row_hash === "string");
    assert.ok(typeof biz!.prev_hash === "string");
    assert.ok(typeof biz!.signature === "string");
  } finally {
    await cleanup();
  }
});

test("Tn.read({raw: true}) returns the {envelope, ...} shape", async () => {
  const { client, cleanup } = await makeEphemeral();
  try {
    client.info("evt.test", { k: 1 });
    const entries: Record<string, unknown>[] = [];
    for (const env of client.read({ raw: true })) {
      entries.push(env as Record<string, unknown>);
    }
    const evt = entries.find((e) => e["event_type"] === "evt.test");
    assert.ok(evt, "must find evt.test");
    // raw=true yields the on-disk envelope dict directly.
    assert.ok(evt!["default"], "envelope carries group ciphertext");
    const grp = evt!["default"] as Record<string, unknown>;
    assert.ok("ciphertext" in grp);
    assert.ok(typeof evt!["row_hash"] === "string");
  } finally {
    await cleanup();
  }
});

test("a row with only public fields surfaces as Entry with empty fields beyond public extras", async () => {
  const { client, cleanup } = await makeEphemeral();
  try {
    client.info("evt.public", { request_id: "req-123" });
    const entries: Entry[] = [];
    for (const e of client.read()) {
      if (e instanceof Entry) entries.push(e);
    }
    const evt = entries.find((e) => e.event_type === "evt.public");
    assert.ok(evt);
    assert.equal(evt!.fields["request_id"], "req-123");
  } finally {
    await cleanup();
  }
});

test("read({verify: true, raw: true}) — raw wins; no error", async () => {
  const { client, cleanup } = await makeEphemeral();
  try {
    client.info("evt.compose", { x: 1 });
    const entries: Record<string, unknown>[] = [];
    for (const env of client.read({ verify: true, raw: true })) {
      entries.push(env as Record<string, unknown>);
    }
    const evt = entries.find((e) => e["event_type"] === "evt.compose");
    assert.ok(evt);
  } finally {
    await cleanup();
  }
});

void rmSync; // keep typed import alive for potential future cleanup helpers
