// Tests for `client.read()` shape — flat default + verify + raw flags
// per the 2026-04-25 read-ergonomics spec §1.

import { strict as assert } from "node:assert";
import { rmSync } from "node:fs";
import { test } from "node:test";

import { TNClient, type ReadEntry } from "../src/index.js";

function makeEphemeral(): { client: TNClient; cleanup: () => void } {
  const client = TNClient.ephemeral();
  return {
    client,
    cleanup: () => {
      try {
        client.close();
      } catch {
        /* ignore */
      }
    },
  };
}

test("client.read() default returns flat dict with envelope basics + decrypted fields", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    client.info("order.created", { amount: 99, currency: "USD" });
    const entries = [...client.read()] as Array<Record<string, unknown>>;
    const biz = entries.find((e) => e["event_type"] === "order.created");
    assert.ok(biz, "must find the order.created entry");
    // Envelope basics flat at top-level (snake_case).
    assert.equal(biz!["event_type"], "order.created");
    assert.equal(biz!["level"], "info");
    assert.ok(typeof biz!["did"] === "string");
    assert.ok(typeof biz!["timestamp"] === "string");
    assert.ok(typeof biz!["sequence"] === "number");
    assert.ok(typeof biz!["event_id"] === "string");

    // Decrypted fields surface flat.
    assert.equal(biz!["amount"], 99);
    assert.equal(biz!["currency"], "USD");

    // Crypto plumbing absent.
    assert.equal(biz!["row_hash"], undefined);
    assert.equal(biz!["prev_hash"], undefined);
    assert.equal(biz!["signature"], undefined);
    assert.equal(biz!["envelope"], undefined);
    assert.equal(biz!["plaintext"], undefined);
  } finally {
    cleanup();
  }
});

test("client.read({verify: true}) adds _valid block", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    client.info("evt.test", { k: 1 });
    const entries = [...client.read({ verify: true })] as Array<Record<string, unknown>>;
    const evt = entries.find((e) => e["event_type"] === "evt.test");
    assert.ok(evt, "must find evt.test");
    const valid = evt!["_valid"] as Record<string, unknown> | undefined;
    assert.ok(valid, "_valid must be present");
    assert.equal(valid!["signature"], true);
    assert.equal(valid!["row_hash"], true);
    assert.equal(valid!["chain"], true);
  } finally {
    cleanup();
  }
});

test("client.read({raw: true}) returns the {envelope, plaintext, valid} shape", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    client.info("evt.test", { k: 1 });
    const entries = [...client.read({ raw: true })] as ReadEntry[];
    const evt = entries.find((e) => e.envelope["event_type"] === "evt.test");
    assert.ok(evt, "must find evt.test");
    assert.ok(evt!.envelope, "raw shape carries envelope");
    assert.ok(evt!.plaintext, "raw shape carries plaintext");
    assert.ok(evt!.valid, "raw shape carries valid");
    assert.equal(evt!.valid.signature, true);
    assert.equal(evt!.valid.rowHash, true);
    assert.equal(evt!.valid.chain, true);
  } finally {
    cleanup();
  }
});

test("client.readRaw is an alias for read({raw: true})", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    client.info("evt.alias", { x: 1 });
    const entries = [...client.readRaw()];
    const evt = entries.find((e) => e.envelope["event_type"] === "evt.alias");
    assert.ok(evt, "readRaw yields the audit-grade shape");
    assert.ok(evt!.envelope);
  } finally {
    cleanup();
  }
});

test("flat dict omits empty _hidden_groups / _decrypt_errors keys", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    client.info("evt.test", { k: 1 });
    const entries = [...client.read()] as Array<Record<string, unknown>>;
    const evt = entries.find((e) => e["event_type"] === "evt.test");
    assert.ok(evt);
    assert.equal(evt!["_hidden_groups"], undefined);
    assert.equal(evt!["_decrypt_errors"], undefined);
  } finally {
    cleanup();
  }
});

test("a row with only public fields returns just envelope basics in flat dict", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    // No groups — just envelope basics + a public field.
    // request_id is in the auto-injected public_fields list.
    client.info("evt.public", { request_id: "req-123" });
    const entries = [...client.read()] as Array<Record<string, unknown>>;
    const evt = entries.find((e) => e["event_type"] === "evt.public");
    assert.ok(evt);
    // Public field flat at top level.
    assert.equal(evt!["request_id"], "req-123");
  } finally {
    cleanup();
  }
});

test("read({verify: true, raw: true}) — raw wins; no error", () => {
  const { client, cleanup } = makeEphemeral();
  try {
    client.info("evt.compose", { x: 1 });
    const entries = [...client.read({ verify: true, raw: true })] as ReadEntry[];
    const evt = entries.find((e) => e.envelope["event_type"] === "evt.compose");
    assert.ok(evt);
    // raw=true returns the audit-grade shape; valid is on the entry.
    assert.equal(evt!.valid.signature, true);
  } finally {
    cleanup();
  }
});
void rmSync; // keep typed import alive for potential future cleanup helpers
