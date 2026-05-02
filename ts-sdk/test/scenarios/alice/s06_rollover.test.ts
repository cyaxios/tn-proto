// Alice s06 — period rollover: init → emit segment.one → close → init →
// emit segment.two → close → init → read all, verify both segments decrypt.
//
// Python original: python/scenarios/alice/s06_rollover.py
//
// Persistence requirement: this scenario requires a yaml that survives
// across close/re-init cycles, so Tn.ephemeral() is NOT used here.
// Instead we use mkdtempSync + Tn.init(yamlPath) so the yaml and keystore
// persist between sessions.  The tempdir is cleaned up in the finally block.
//
// rotate_on_init note: NodeRuntime.init() rotates the log on each session
// start by default (mirrors Python's RotatingFileHandler behavior).  For
// this scenario we need a single append-only log across all three sessions,
// so we patch the generated yaml to set rotate_on_init: false after the
// first session creates it.
//
// Read-all note: readRaw() is not run-id filtered (it goes through
// _rt.read() directly), so after the third init it sees entries from ALL
// prior sessions in the append-only log.  We filter by event_type to
// isolate the two segments.

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

test("alice/s06_rollover — two sessions on same yaml, both segments decrypt", async () => {
  const ctx = new ScenarioContext();
  const dir = mkdtempSync(join(tmpdir(), "tn-s06-"));
  const yamlPath = join(dir, "tn.yaml");

  try {
    // Session 1: emit segment.one and patch yaml to stop future log rotation.
    {
      const tn = await Tn.init(yamlPath, { stdout: false });
      try {
        for (let i = 0; i < 100; i++) {
          tn.info("segment.one", { seq: i });
        }
      } finally {
        await tn.close();
      }
      // Patch before the next session starts so its init doesn't rotate the log.
      disableRotateOnInit(yamlPath);
    }

    // Session 2: emit segment.two.
    {
      const tn = await Tn.init(yamlPath, { stdout: false });
      try {
        for (let i = 0; i < 100; i++) {
          tn.info("segment.two", { seq: i });
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
        const seg1 = allEntries.filter((e) => e.envelope["event_type"] === "segment.one");
        const seg2 = allEntries.filter((e) => e.envelope["event_type"] === "segment.two");

        ctx.assertInvariant(
          "seg1_count",
          seg1.length === 100,
          `expected 100 segment.one entries, got ${seg1.length}`,
        );
        ctx.assertInvariant(
          "seg2_count",
          seg2.length === 100,
          `expected 100 segment.two entries, got ${seg2.length}`,
        );

        let chainOk = true;
        let sigOk = true;
        let decryptionOk = true;
        let decryptedCount = 0;

        for (const entry of allEntries) {
          chainOk = chainOk && Boolean(entry.valid.chain);
          sigOk = sigOk && Boolean(entry.valid.signature);
        }

        for (const bucket of [seg1, seg2]) {
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
        ctx.record("seg1_count", seg1.length);
        ctx.record("seg2_count", seg2.length);
        ctx.record("decrypted_count", decryptedCount);

        ctx.assertInvariant("chain_verified", chainOk);
        ctx.assertInvariant("signature_verified", sigOk);
        ctx.assertInvariant(
          "decryption_verified",
          decryptionOk && decryptedCount === 200,
          `decrypted ${decryptedCount}/200 entries`,
        );
      } finally {
        await tn.close();
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
