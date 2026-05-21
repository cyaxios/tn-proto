// Scenario ex02 — audit-grade Tn.read({raw}) shape, signature verification,
// chain integrity.
//
// Python original: tn_proto/python/examples/ex02_reading.py
//
// What this tests:
//   1. Envelope shape: every reserved key is present on a raw entry.
//   2. All entries verify: tn.read({verify: true}) doesn't throw on a clean
//      log (covers signature + chain + row_hash collectively).
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
  "device_identity",
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

    // First user entry (skip tn.* bootstrap events) — raw envelope dict.
    let firstUser: Record<string, unknown> | undefined;
    for (const env of tn.read({ raw: true, allRuns: true })) {
      const e = env as Record<string, unknown>;
      if (!String(e["event_type"] ?? "").startsWith("tn.")) {
        firstUser = e;
        break;
      }
    }
    assert.ok(firstUser !== undefined, "expected at least one user entry");

    for (const key of RESERVED_ENVELOPE_KEYS) {
      assert.ok(
        key in firstUser!,
        `reserved envelope key "${key}" missing from envelope`,
      );
    }

    // Sanity-check types.
    assert.strictEqual(typeof firstUser!["device_identity"], "string");
    assert.strictEqual(typeof firstUser!["timestamp"], "string");
    assert.strictEqual(typeof firstUser!["event_type"], "string");
    assert.strictEqual(typeof firstUser!["event_id"], "string");
    assert.strictEqual(typeof firstUser!["level"], "string");
    assert.strictEqual(typeof firstUser!["sequence"], "number");
    assert.strictEqual(typeof firstUser!["prev_hash"], "string");
    assert.strictEqual(typeof firstUser!["row_hash"], "string");
    assert.strictEqual(typeof firstUser!["signature"], "string");
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

    // verify: true raises VerifyError on failure. A clean log must not throw.
    let userCount = 0;
    for (const env of tn.read({ verify: true, raw: true, allRuns: true })) {
      const e = env as Record<string, unknown>;
      if (!String(e["event_type"] ?? "").startsWith("tn.")) userCount += 1;
    }
    assert.equal(userCount, 4, `expected 4 user entries, got ${userCount}`);
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

    const chains = new Map<string, number[]>();
    for (const env of tn.read({ raw: true, allRuns: true })) {
      const e = env as Record<string, unknown>;
      const et = String(e["event_type"] ?? "");
      if (et.startsWith("tn.")) continue;
      const seq = e["sequence"] as number;
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

test("ex02/independent-verify — verify signature with public material only (device_identity + row_hash + signature)", async () => {
  const tn = await ScenarioContext.newTn();
  try {
    tn.info("page.view", { path: "/", user: "alice" });

    let firstUser: Record<string, unknown> | undefined;
    for (const env of tn.read({ raw: true, allRuns: true })) {
      const e = env as Record<string, unknown>;
      if (!String(e["event_type"] ?? "").startsWith("tn.")) {
        firstUser = e;
        break;
      }
    }
    assert.ok(firstUser !== undefined, "expected a user entry");

    const did = asDid(String(firstUser!["device_identity"]));
    const rowHashStr = asRowHash(String(firstUser!["row_hash"]));
    const sigStr = String(firstUser!["signature"]);

    const sigBytes = signatureFromB64(sigStr);
    const ok = verify(did, new Uint8Array(Buffer.from(rowHashStr, "utf8")), sigBytes);

    assert.strictEqual(ok, true, "independent public-key verification failed");
  } finally {
    await tn.close();
  }
});
