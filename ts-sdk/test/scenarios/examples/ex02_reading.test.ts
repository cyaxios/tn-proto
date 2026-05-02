// Scenario ex02 — audit-grade tn.readRaw() shape, signature verification,
// chain integrity.
//
// Python original: tn_proto/python/examples/ex02_reading.py
//
// What this tests:
//   1. Envelope shape: every reserved key is present on a raw entry.
//   2. All entries verify: valid.signature === true, valid.chain === true,
//      valid.rowHash === true for every user event.
//   3. Per-event_type chain coherence: page.view sequences are [1,2,3] in
//      order; auth.login sequence is [1].
//   4. Independent verification using ONLY public material (did + row_hash +
//      signature) — no Tn instance or keystore needed for the verify call.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { ScenarioContext } from "../_harness.js";
import {
  verify,
  signatureFromB64,
  asDid,
  asRowHash,
} from "../../../src/core/index.js";

// TS envelope uses snake_case keys on the wire.
const RESERVED_ENVELOPE_KEYS = [
  "did",
  "timestamp",
  "event_type",
  "event_id",
  "level",
  "sequence",
  "prev_hash",
  "row_hash",
  "signature",
] as const;

test("ex02/envelope-shape — every reserved envelope key is present on first user entry", async () => {
  const tn = await ScenarioContext.newTn();
  try {
    tn.info("page.view", { path: "/", user: "alice" });
    tn.info("page.view", { path: "/about", user: "alice" });
    tn.info("auth.login", { user: "alice" });
    tn.info("page.view", { path: "/checkout", user: "alice" });

    // First user entry (skip tn.* bootstrap events).
    const firstUser = [...tn.readRaw()].find(
      (e) => !String(e.envelope["event_type"] ?? "").startsWith("tn."),
    );

    assert.ok(firstUser !== undefined, "expected at least one user entry");

    const env = firstUser.envelope;
    for (const key of RESERVED_ENVELOPE_KEYS) {
      assert.ok(
        key in env,
        `reserved envelope key "${key}" missing from envelope`,
      );
    }

    // Sanity-check types.
    assert.strictEqual(typeof env["did"], "string");
    assert.strictEqual(typeof env["timestamp"], "string");
    assert.strictEqual(typeof env["event_type"], "string");
    assert.strictEqual(typeof env["event_id"], "string");
    assert.strictEqual(typeof env["level"], "string");
    assert.strictEqual(typeof env["sequence"], "number");
    assert.strictEqual(typeof env["prev_hash"], "string");
    assert.strictEqual(typeof env["row_hash"], "string");
    assert.strictEqual(typeof env["signature"], "string");
  } finally {
    await tn.close();
  }
});

test("ex02/all-entries-verify — signature, chain, rowHash all pass for every user entry", async () => {
  const tn = await ScenarioContext.newTn();
  try {
    tn.info("page.view", { path: "/", user: "alice" });
    tn.info("page.view", { path: "/about", user: "alice" });
    tn.info("auth.login", { user: "alice" });
    tn.info("page.view", { path: "/checkout", user: "alice" });

    const userEntries = [...tn.readRaw()].filter(
      (e) => !String(e.envelope["event_type"] ?? "").startsWith("tn."),
    );

    assert.ok(userEntries.length === 4, `expected 4 user entries, got ${userEntries.length}`);

    for (const e of userEntries) {
      const et = String(e.envelope["event_type"] ?? "");
      assert.strictEqual(e.valid.signature, true, `signature failed for ${et} seq=${e.envelope["sequence"]}`);
      assert.strictEqual(e.valid.chain, true, `chain broken for ${et} seq=${e.envelope["sequence"]}`);
      assert.strictEqual(e.valid.rowHash, true, `row_hash mismatch for ${et} seq=${e.envelope["sequence"]}`);
    }
  } finally {
    await tn.close();
  }
});

test("ex02/chain-coherence — page.view sequences [1,2,3] and auth.login sequence [1]", async () => {
  const tn = await ScenarioContext.newTn();
  try {
    tn.info("page.view", { path: "/", user: "alice" });
    tn.info("page.view", { path: "/about", user: "alice" });
    tn.info("auth.login", { user: "alice" });
    tn.info("page.view", { path: "/checkout", user: "alice" });

    // Build per-event_type sequence lists (mirrors Python chains dict).
    const chains = new Map<string, number[]>();
    for (const e of tn.readRaw()) {
      const et = String(e.envelope["event_type"] ?? "");
      if (et.startsWith("tn.")) continue; // skip bootstrap events
      const seq = e.envelope["sequence"] as number;
      const list = chains.get(et) ?? [];
      list.push(seq);
      chains.set(et, list);
    }

    const pageSeqs = chains.get("page.view") ?? [];
    const authSeqs = chains.get("auth.login") ?? [];

    assert.deepStrictEqual(pageSeqs, [1, 2, 3], `page.view sequences: expected [1,2,3], got ${JSON.stringify(pageSeqs)}`);
    assert.deepStrictEqual(authSeqs, [1], `auth.login sequences: expected [1], got ${JSON.stringify(authSeqs)}`);
  } finally {
    await tn.close();
  }
});

test("ex02/independent-verify — verify signature with public material only (did + row_hash + signature)", async () => {
  const tn = await ScenarioContext.newTn();
  try {
    tn.info("page.view", { path: "/", user: "alice" });

    // Grab the first user entry.
    const entry = [...tn.readRaw()].find(
      (e) => !String(e.envelope["event_type"] ?? "").startsWith("tn."),
    );
    assert.ok(entry !== undefined, "expected a user entry");

    const env = entry.envelope;
    const did = asDid(String(env["did"]));
    const rowHashStr = asRowHash(String(env["row_hash"]));
    const sigStr = String(env["signature"]);

    // Decode the base64url signature bytes.
    const sigBytes = signatureFromB64(sigStr);

    // Verify using ONLY the DID + row_hash (public material). No Tn instance,
    // no keystore, no network. Mirrors Python: DeviceKey.verify(did, row_hash, sig).
    const ok = verify(did, new Uint8Array(Buffer.from(rowHashStr, "utf8")), sigBytes);

    assert.strictEqual(ok, true, "independent public-key verification failed");
  } finally {
    await tn.close();
  }
});
