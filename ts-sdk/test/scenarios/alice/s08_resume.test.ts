// Alice s08 — init, emit 500 before.restart, close, re-init same yaml,
// emit 500 after.restart, verify single coherent chain across both sessions.
//
// Python original: python/scenarios/alice/s08_resume.py
//
// Persistence requirement: same as s06 — needs a yaml that survives across
// close/re-init cycles.  Uses mkdtempSync + Tn.init(yamlPath).
//
// rotate_on_init note: NodeRuntime.init() rotates the log on each session
// start by default.  For this scenario we need a single append-only log
// across both sessions, so we patch the generated yaml to set
// rotate_on_init: false after the first session creates it.
//
// The chain spans both sessions: the second session's genesis reads the
// last row_hash from the log and continues from there, so a single
// unbroken chain verification over all 1000 entries is expected.

import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Tn } from "../../../src/tn.js";
import { ScenarioContext } from "../_harness.js";

/** Patch the yaml at `yamlPath` to disable log rotation across re-inits. */
function disableRotateOnInit(yamlPath: string): void {
  const text = readFileSync(yamlPath, "utf8");
  const patched = text.replace(/rotate_on_init:\s*true/g, "rotate_on_init: false");
  writeFileSync(yamlPath, patched, "utf8");
}

test("alice/s08_resume — two sessions on same yaml, single coherent chain of 1000 entries", async () => {
  const ctx = new ScenarioContext();
  const dir = mkdtempSync(join(tmpdir(), "tn-s08-"));
  const yamlPath = join(dir, "tn.yaml");

  try {
    // Session 1: emit 500 before.restart and patch yaml to stop log rotation.
    {
      const tn = await Tn.init(yamlPath, { stdout: false });
      try {
        for (let i = 0; i < 500; i++) {
          tn.info("before.restart", { seq: i });
        }
      } finally {
        await tn.close();
      }
      // Patch before the next session starts so its init doesn't rotate the log.
      disableRotateOnInit(yamlPath);
    }

    // Session 2: emit 500 after.restart.
    {
      const tn = await Tn.init(yamlPath, { stdout: false });
      try {
        for (let i = 0; i < 500; i++) {
          tn.info("after.restart", { seq: i });
        }
      } finally {
        await tn.close();
      }
    }

    // Session 3: read and verify.
    {
      const tn = await Tn.init(yamlPath, { stdout: false });
      try {
        // readRaw() returns all entries across all sessions (no run_id filter).
        const allEntries = [...tn.readRaw()];
        const before = allEntries.filter((e) => e.envelope["event_type"] === "before.restart");
        const after = allEntries.filter((e) => e.envelope["event_type"] === "after.restart");

        ctx.assertInvariant(
          "before_count",
          before.length === 500,
          `expected 500 before.restart entries, got ${before.length}`,
        );
        ctx.assertInvariant(
          "after_count",
          after.length === 500,
          `expected 500 after.restart entries, got ${after.length}`,
        );

        let chainOk = true;
        let sigOk = true;
        let decryptionOk = true;
        let decryptedCount = 0;

        for (const entry of allEntries) {
          chainOk = chainOk && Boolean(entry.valid.chain);
          sigOk = sigOk && Boolean(entry.valid.signature);
        }

        for (const bucket of [before, after]) {
          for (let idx = 0; idx < bucket.length; idx++) {
            const e = bucket[idx]!;
            const pt = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
            if (pt["seq"] === idx) {
              decryptedCount++;
            } else {
              decryptionOk = false;
            }
          }
        }

        ctx.record("log_count", allEntries.length);
        ctx.record("before_count", before.length);
        ctx.record("after_count", after.length);
        ctx.record("decrypted_count", decryptedCount);

        ctx.assertInvariant("chain_verified", chainOk);
        ctx.assertInvariant("signature_verified", sigOk);
        ctx.assertInvariant(
          "decryption_verified",
          decryptionOk && decryptedCount === 1000,
          `decrypted ${decryptedCount}/1000 entries`,
        );
      } finally {
        await tn.close();
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
