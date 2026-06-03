// Cross-language parity for the vault verbs.
//
// Decision (locked with the user): vault.link / vault.unlink stay on the
// EMIT path in BOTH SDKs. The dedicated Rust vault_link / vault_unlink
// binding is intentionally NOT used. These tests pin the TS emit shape to
// Python's `_vault_link_impl` / `_vault_unlink_impl` (python/tn/_vault_impl.py)
// so the on-log event_type + field names stay in lock-step.
//
// Python emits:
//   tn.vault.linked   -> { vault_identity, project_id, linked_at }
//   tn.vault.unlinked -> { vault_identity, project_id, reason, unlinked_at }
//
// node:test + tsx, mirroring ts-sdk/test/vault_namespace.test.ts.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";

/** Collect decrypted Entry rows for a given event_type from the local log. */
function readEvents(tn: Tn, eventType: string): Entry[] {
  const out: Entry[] = [];
  for (const e of tn.read()) {
    if (e instanceof Entry && e.event_type === eventType) out.push(e);
  }
  return out;
}

test("tn.vault.link appends a tn.vault.linked event with the Python field set", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await tn.vault.link("did:key:zVault", "proj_123");

    const events = readEvents(tn, "tn.vault.linked");
    assert.equal(events.length, 1, "exactly one tn.vault.linked row");

    const f = events[0]!.fields;
    assert.equal(f["vault_identity"], "did:key:zVault");
    assert.equal(f["project_id"], "proj_123");
    assert.equal(typeof f["linked_at"], "string");
    // linked_at is an ISO-8601 timestamp (Python: datetime.now(utc).isoformat()).
    assert.ok(!Number.isNaN(Date.parse(String(f["linked_at"]))), "linked_at parses as a date");
  } finally {
    await tn.close();
  }
});

test("tn.vault.unlink appends a tn.vault.unlinked event with the Python field set", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await tn.vault.unlink("did:key:zVault", "proj_123", "rotating credentials");

    const events = readEvents(tn, "tn.vault.unlinked");
    assert.equal(events.length, 1, "exactly one tn.vault.unlinked row");

    const f = events[0]!.fields;
    assert.equal(f["vault_identity"], "did:key:zVault");
    assert.equal(f["project_id"], "proj_123");
    assert.equal(f["reason"], "rotating credentials");
    assert.equal(typeof f["unlinked_at"], "string");
    assert.ok(!Number.isNaN(Date.parse(String(f["unlinked_at"]))), "unlinked_at parses as a date");
  } finally {
    await tn.close();
  }
});

test("tn.vault.unlink writes reason:null when none supplied (matches Python)", async () => {
  // Python's _vault_unlink_impl always writes `reason` (value None when
  // omitted). TS now matches: it writes `reason: null` rather than leaving
  // the key absent, so the on-log event is byte-equivalent across SDKs.
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    await tn.vault.unlink("did:key:zVault", "proj_123");

    const events = readEvents(tn, "tn.vault.unlinked");
    assert.equal(events.length, 1, "exactly one tn.vault.unlinked row");

    const f = events[0]!.fields;
    assert.equal(f["vault_identity"], "did:key:zVault");
    assert.equal(f["project_id"], "proj_123");
    assert.equal(typeof f["unlinked_at"], "string");
    assert.equal(f["reason"], null, "reason is null when omitted, matching Python");
  } finally {
    await tn.close();
  }
});
