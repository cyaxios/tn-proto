// Alice s03 — ceremony matrix sweep, 15 cells varying (groups, recipients,
// context_keys, field_count). Each cell is its own fresh Tn.ephemeral()
// ceremony emitting 200 entries and asserting per-cell chain+sig+decrypt.
//
// Python original: python/scenarios/alice/s03_ceremony_matrix.py
//
// Isolation note: Python uses fresh yaml+keystore dirs per cell because of
// yaml-file persistence. Tn.ephemeral() gives us equivalent isolation — each
// cell gets its own ceremony in a private tempdir cleaned on close().
//
// Recipient cosmetic note (mirrors Python's comment):
//   tn.admin.ensureGroup(name) creates a group with the publisher as the
//   only recipient; n_recips is recorded for design-intent coverage but
//   true multi-recipient encryption per cell is a separate concern.

import { test } from "node:test";
import { Tn } from "../../../src/tn.js";
import { ScenarioContext } from "../_harness.js";

// (groups, recipients_per_group, context_keys, field_count)
const MATRIX: Array<[number, number, number, number]> = [
  [1, 1, 0, 5],
  [1, 1, 3, 5],
  [1, 3, 0, 20],
  [1, 10, 0, 20],
  [2, 1, 0, 20],
  [2, 3, 3, 20],
  [2, 3, 10, 100],
  [5, 1, 0, 20],
  [5, 3, 0, 20],
  [5, 3, 3, 100],
  [5, 10, 0, 20],
  [1, 1, 0, 50],
  [1, 3, 10, 50],
  [3, 3, 3, 20],
  [3, 1, 10, 100],
];

const LOG_COUNT_PER_CELL = 200;

function makeFields(n: number): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < n; i++) {
    out[`f${String(i).padStart(3, "0")}`] = `v${String(i).padStart(3, "0")}`;
  }
  return out;
}

test("alice/s03_ceremony_matrix — 15-cell matrix, each cell passes chain+sig+decrypt", async () => {
  for (let idx = 0; idx < MATRIX.length; idx++) {
    const [nGroups, nRecips, nCtx, nFields] = MATRIX[idx]!;
    const cellId = `cell_${String(idx).padStart(2, "0")}`;

    const ctx = new ScenarioContext();
    const tn = await Tn.ephemeral({ stdout: false });

    try {
      // Add extra groups beyond the default (default group is created by ephemeral()).
      for (let g = 1; g < nGroups; g++) {
        await tn.admin.ensureGroup(`g${g}`);
      }

      // Set context fields if requested.
      if (nCtx > 0) {
        const kv: Record<string, string> = {};
        for (let i = 0; i < nCtx; i++) {
          kv[`ck${i}`] = `cv${i}`;
        }
        tn.setContext(kv);
      }

      const evt = makeFields(nFields);

      for (let i = 0; i < LOG_COUNT_PER_CELL; i++) {
        tn.info("matrix.row", evt);
      }

      if (nCtx > 0) {
        tn.clearContext();
      }

      // Read back and assert per-cell invariants.
      const entries = [...tn.readRaw()].filter(
        (e) => (e.envelope["event_type"] as string) === "matrix.row",
      );

      let chainOk = true;
      let sigOk = true;
      let decryptionOk = true;
      let decryptedCount = 0;

      for (const e of entries) {
        chainOk = chainOk && Boolean(e.valid.chain);
        sigOk = sigOk && Boolean(e.valid.signature);
        const pt = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
        if (Object.entries(evt).every(([k, v]) => pt[k] === v)) {
          decryptedCount++;
        } else {
          decryptionOk = false;
        }
      }

      ctx.record("cell_id", cellId);
      ctx.record("group_count", nGroups);
      ctx.record("recipient_count", nRecips * nGroups); // design intent
      ctx.record("context_key_count", nCtx);
      ctx.record("field_count", nFields);
      ctx.record("log_count", LOG_COUNT_PER_CELL);
      ctx.record("decrypted_count", decryptedCount);

      ctx.assertInvariant(
        `${cellId}_entry_count`,
        entries.length === LOG_COUNT_PER_CELL,
        `${cellId}: expected ${LOG_COUNT_PER_CELL} matrix.row entries, got ${entries.length}`,
      );
      ctx.assertInvariant(`${cellId}_chain_verified`, chainOk, `${cellId}: chain failed`);
      ctx.assertInvariant(`${cellId}_signature_verified`, sigOk, `${cellId}: signature failed`);
      ctx.assertInvariant(
        `${cellId}_decryption_verified`,
        decryptionOk && decryptedCount === LOG_COUNT_PER_CELL,
        `${cellId}: decrypted ${decryptedCount}/${LOG_COUNT_PER_CELL}`,
      );
    } finally {
      await tn.close();
    }
  }
});
