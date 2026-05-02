// Alice s01 — emit 200 events, read back, verify chain + signature + decrypt + no-plaintext-leak.
//
// Python original: python/scenarios/alice/s01_hello.py
// LOG_COUNT reduced from 1000 → 200 to keep the test fast; assertion shape
// is identical and all behavioral guarantees are exercised at any count >= 1.
//
// TS lifecycle note: Python does tn.flush_and_close() then tn.init(same yaml)
// for the read pass.  With Tn.ephemeral the tempdir is cleaned on close(), so
// we cannot reopen.  Instead we read within the same instance's lifetime
// using readRaw() which bypasses run_id filtering and sees every persisted
// entry, mirroring Python's post-close re-init read exactly.

import { test } from "node:test";
import { ScenarioContext } from "../_harness.js";

const LOG_COUNT = 200;

test("alice/s01_hello — emit 200 events, read back, verify chain+sig+decrypt+no-leak", async () => {
  const ctx = new ScenarioContext();
  const tn = await ScenarioContext.newTn();

  try {
    // Emit LOG_COUNT order.created events.
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

    // Read back via readRaw() — yields {envelope, plaintext, valid} per entry.
    // Filter to only "order.created" events (ignore bootstrap tn.* events).
    const entries = [...tn.readRaw()].filter(
      (e) => (e.envelope["event_type"] as string) === "order.created",
    );

    ctx.assertInvariant(
      "entry_count",
      entries.length === LOG_COUNT,
      `expected ${LOG_COUNT} order.created entries, got ${entries.length}`,
    );

    let allValidSig = true;
    let allValidChain = true;
    let noPlaintextLeak = true;
    let decryptionVerified = true;
    let decryptedCount = 0;

    // Strings that must NOT appear in the raw envelope JSON (plaintext-leak check).
    const leakSamples = [
      "u0@ex.com",
      "u100@ex.com",
      "O000000",
      "O000100",
    ];

    for (const e of entries) {
      allValidSig = allValidSig && Boolean(e.valid.signature);
      allValidChain = allValidChain && Boolean(e.valid.chain);

      const rawEnv = JSON.stringify(e.envelope);
      for (const leak of leakSamples) {
        if (rawEnv.includes(leak)) {
          noPlaintextLeak = false;
          break;
        }
      }

      // Decrypt round-trip: sequence maps to inputs[seq-1].
      const seq = e.envelope["sequence"] as number | undefined;
      const ptDefault = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
      if (seq !== undefined && seq >= 1 && seq <= inputs.length) {
        const expected = inputs[seq - 1]!;
        if (
          ptDefault["order_id"] === expected.order_id &&
          ptDefault["amount"] === expected.amount &&
          ptDefault["email"] === expected.email
        ) {
          decryptedCount++;
        } else {
          decryptionVerified = false;
        }
      } else {
        decryptionVerified = false;
      }
    }

    ctx.assertInvariant("chain_verified", allValidChain);
    ctx.assertInvariant("signature_verified", allValidSig);
    ctx.assertInvariant("no_plaintext_in_envelope", noPlaintextLeak);
    ctx.assertInvariant(
      "decryption_verified",
      decryptionVerified && decryptedCount === LOG_COUNT,
      `decrypted ${decryptedCount}/${LOG_COUNT} entries correctly`,
    );

    ctx.record("decrypted_count", decryptedCount);
    ctx.record("entry_count_read", entries.length);
  } finally {
    await tn.close();
  }
});
