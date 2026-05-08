// Alice s01 — emit 200 events, read back, verify chain + signature + decrypt + no-plaintext-leak.
//
// Python original: python/scenarios/alice/s01_hello.py
// LOG_COUNT reduced from 1000 → 200 to keep the test fast.
//
// 0.4.0a1 read refactor: `tn.readRaw()` was removed. We use
// `tn.read({allRuns: true})` to bypass run_id filtering and get Entry
// instances; signature/chain integrity is verified collectively via
// `tn.read({verify: true, allRuns: true})` (raises VerifyError on
// failure). For the no-leak check we re-read with `raw: true` to get
// the on-disk envelope dict and assert plaintext samples are absent.

import { test } from "node:test";
import { ScenarioContext } from "../_harness.js";
import { Entry, VerifyError } from "../../../src/Entry.js";

const LOG_COUNT = 200;

test("alice/s01_hello — emit 200 events, read back, verify chain+sig+decrypt+no-leak", async () => {
  const ctx = new ScenarioContext();
  const tn = await ScenarioContext.newTn();

  try {
    const inputs: Array<{ order_id: string; amount: number; email: string }> = [];
    for (let i = 0; i < LOG_COUNT; i++) {
      const event = {
        order_id: `O${String(i).padStart(6, "0")}`,
        amount: 1000 + i,
        email: `u${i}@ex.com`,
      };
      inputs.push(event);
      tn.info("order.created", event);
    }
    ctx.record("log_count", LOG_COUNT);

    // Read back as Entry instances. allRuns=true to see every persisted
    // entry across runs, mirroring Python's post-close re-init read.
    const entries: Entry[] = [];
    for (const e of tn.read({ allRuns: true })) {
      if (e instanceof Entry && e.event_type === "order.created") entries.push(e);
    }

    ctx.assertInvariant(
      "entry_count",
      entries.length === LOG_COUNT,
      `expected ${LOG_COUNT} order.created entries, got ${entries.length}`,
    );

    // Sig + chain verification: a clean log under verify: true must not throw.
    let chainAndSigOk = true;
    try {
      let n = 0;
      for (const _ of tn.read({ verify: true, allRuns: true })) {
        n += 1;
        void _;
      }
      ctx.record("verified_count", n);
    } catch (e) {
      if (e instanceof VerifyError) chainAndSigOk = false;
      else throw e;
    }
    ctx.assertInvariant("chain_verified", chainAndSigOk);
    ctx.assertInvariant("signature_verified", chainAndSigOk);

    // Decrypt round-trip: sequence maps to inputs[seq-1].
    let decryptionVerified = true;
    let decryptedCount = 0;
    for (const e of entries) {
      const seq = e.sequence;
      if (seq >= 1 && seq <= inputs.length) {
        const expected = inputs[seq - 1]!;
        if (
          e.fields["order_id"] === expected.order_id &&
          e.fields["amount"] === expected.amount &&
          e.fields["email"] === expected.email
        ) {
          decryptedCount += 1;
        } else {
          decryptionVerified = false;
        }
      } else {
        decryptionVerified = false;
      }
    }
    ctx.assertInvariant(
      "decryption_verified",
      decryptionVerified && decryptedCount === LOG_COUNT,
      `decrypted ${decryptedCount}/${LOG_COUNT} entries correctly`,
    );

    // No-plaintext-leak check via raw envelope.
    const leakSamples = ["u0@ex.com", "u100@ex.com", "O000000", "O000100"];
    let noPlaintextLeak = true;
    for (const env of tn.read({ raw: true, allRuns: true })) {
      const e = env as Record<string, unknown>;
      if (e["event_type"] !== "order.created") continue;
      const rawEnv = JSON.stringify(env);
      for (const leak of leakSamples) {
        if (rawEnv.includes(leak)) {
          noPlaintextLeak = false;
          break;
        }
      }
      if (!noPlaintextLeak) break;
    }
    ctx.assertInvariant("no_plaintext_in_envelope", noPlaintextLeak);

    ctx.record("decrypted_count", decryptedCount);
    ctx.record("entry_count_read", entries.length);
  } finally {
    await tn.close();
  }
});
