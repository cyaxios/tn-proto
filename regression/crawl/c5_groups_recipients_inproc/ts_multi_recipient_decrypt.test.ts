/**
 * SILO: C5 — Local groups + recipients in-process
 * TEST: Alice (TS) mints kits for Frank AND Bob; both decrypt the same envelopes.
 *
 * TS analogue of the Python multi-recipient test. The BTN "add second
 * recipient" path exercises tree-extend logic in the wasm cipher; if
 * that breaks, the second recipient's kit either doesn't unlock the
 * existing entries or silently shares state with the first.
 *
 * Asserts (named):
 *   - "ts-alice-minted-two-distinct-kits"
 *   - "ts-frank-decrypted-both-entries"
 *   - "ts-bob-decrypted-both-entries"
 *   - "ts-frank-and-bob-saw-same-content"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const FRANK_DID = "did:key:zFrank0123456789abcdefghjkmnpqrstuvwx";
const BOB_DID = "did:key:zBob0123456789abcdefghjkmnpqrstuvwxyzz";

async function readAsRecipient(
  yamlDir: string,
  aliceLog: string,
  keystorePath: string,
): Promise<Array<{ eventType: string; fields: Record<string, unknown> }>> {
  const cwdBefore = process.cwd();
  process.chdir(yamlDir);
  let t: Tn | undefined;
  try {
    t = await Tn.use("default");
    const out: Array<{ eventType: string; fields: Record<string, unknown> }> = [];
    for (const entry of t.read({
      log: aliceLog,
      asRecipient: keystorePath,
      group: "default",
    })) {
      const e = entry as unknown as {
        event_type?: string;
        hidden_groups?: string[];
        fields?: Record<string, unknown>;
      };
      if (e.event_type === "c5.ts.multi.event") {
        if (!(e.hidden_groups ?? []).includes("default")) {
          out.push({ eventType: e.event_type, fields: e.fields ?? {} });
        }
      }
    }
    return out;
  } finally {
    if (t !== undefined) await t.close();
    process.chdir(cwdBefore);
  }
}

test("C5 (TS): two recipients both decrypt the same envelopes", async () => {
  setTestContext({
    silo: "c5",
    test: "c5_ts_multi_recipient_decrypt::two_recipients",
  });

  const aliceDir = mkdtempSync(join(tmpdir(), "c5-multi-alice-"));
  const frankDir = mkdtempSync(join(tmpdir(), "c5-multi-frank-"));
  const bobDir = mkdtempSync(join(tmpdir(), "c5-multi-bob-"));
  const cwdBefore = process.cwd();

  // ── Alice publishes ────────────────────────────────────────────
  process.chdir(aliceDir);
  const alice = await Tn.use("default");
  const aliceLog = alice.logPath;

  const aliceBundleDir = join(aliceDir, "alice_bundles");
  mkdirSync(aliceBundleDir, { recursive: true });

  // Mint Frank's kit first, bundle it, then mint Bob and bundle his.
  // bundleForRecipient mints a FRESH kit at bundle time, so the
  // explicit addRecipient is only here for parity with the Python test.
  const frankAdd = await alice.admin.addRecipient("default", { recipientDid: FRANK_DID });
  const frankTnpkg = join(aliceBundleDir, "frank.tnpkg");
  await alice.pkg.bundleForRecipient({
    recipientDid: FRANK_DID,
    outPath: frankTnpkg,
    groups: ["default"],
  });

  const bobAdd = await alice.admin.addRecipient("default", { recipientDid: BOB_DID });
  const bobTnpkg = join(aliceBundleDir, "bob.tnpkg");
  await alice.pkg.bundleForRecipient({
    recipientDid: BOB_DID,
    outPath: bobTnpkg,
    groups: ["default"],
  });

  assertNamed({
    name: "ts-alice-minted-two-distinct-kits",
    expected: true,
    observed:
      typeof frankAdd.leafIndex === "number" &&
      typeof bobAdd.leafIndex === "number" &&
      frankAdd.leafIndex !== bobAdd.leafIndex,
    onMiss:
      `Two kits should land at distinct leaf indices. Frank=${frankAdd.leafIndex}, ` +
      `Bob=${bobAdd.leafIndex}. If they collide, the publisher's tree is single-slot.`,
  });

  alice.info("c5.ts.multi.event", { marker: "event-1" });
  alice.info("c5.ts.multi.event", { marker: "event-2" });
  await alice.close();

  // ── Frank reads (separate process state via chdir + Tn.use) ────
  process.chdir(frankDir);
  let frank: Tn | undefined = await Tn.use("default");
  const frankKeystore = (frank.config() as { keystorePath: string }).keystorePath;
  await frank.pkg.absorb(frankTnpkg);
  await frank.close();
  frank = undefined;
  const frankDecrypted = await readAsRecipient(frankDir, aliceLog, frankKeystore);
  process.chdir(cwdBefore);

  assertNamed({
    name: "ts-frank-decrypted-both-entries",
    expected: 2,
    observed: frankDecrypted.length,
    onMiss:
      `Frank decrypted ${frankDecrypted.length} entries; expected 2. ` +
      `Got: ${JSON.stringify(frankDecrypted)}. ` +
      `If 1, the second event was encrypted to a tree state Frank's ` +
      `kit doesn't see — check addRecipient sequencing in wasm.`,
  });

  // ── Bob reads ──────────────────────────────────────────────────
  process.chdir(bobDir);
  let bob: Tn | undefined = await Tn.use("default");
  const bobKeystore = (bob.config() as { keystorePath: string }).keystorePath;
  await bob.pkg.absorb(bobTnpkg);
  await bob.close();
  bob = undefined;
  const bobDecrypted = await readAsRecipient(bobDir, aliceLog, bobKeystore);
  process.chdir(cwdBefore);

  assertNamed({
    name: "ts-bob-decrypted-both-entries",
    expected: 2,
    observed: bobDecrypted.length,
    onMiss:
      `Bob decrypted ${bobDecrypted.length} entries; expected 2. ` +
      `Got: ${JSON.stringify(bobDecrypted)}.`,
  });

  // Cross-check: same payload visible to both.
  const frankSet = new Set(frankDecrypted.map((d) => JSON.stringify(d.fields)));
  const bobSet = new Set(bobDecrypted.map((d) => JSON.stringify(d.fields)));
  const same =
    frankSet.size === bobSet.size &&
    [...frankSet].every((k) => bobSet.has(k));
  assertNamed({
    name: "ts-frank-and-bob-saw-same-content",
    expected: true,
    observed: same,
    onMiss:
      `Frank's set: ${[...frankSet].join(" | ")}. ` +
      `Bob's set: ${[...bobSet].join(" | ")}. ` +
      `Different recipients should decode the same plaintext.`,
  });

  void assert;
});
