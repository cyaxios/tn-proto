/**
 * SILO: C5 — Local groups + recipients in-process
 * TEST: TS publisher Alice mints a kit, TS recipient Frank absorbs + decrypts.
 *
 * This is the browser-shape use case: all-TS encrypt + decrypt round-trip.
 * If this works, two TS Node processes can act as publisher / reader on
 * the same machine; if it works in Node, the browser path (with the same
 * wasm crypto) should too.
 *
 * Flow:
 *   1. Alice cwd → Tn.use("default"). Capture log path + keystore.
 *   2. alice.admin.addRecipient("default", { recipientDid: FRANK_DID }).
 *   3. alice.pkg.bundleForRecipient({ recipientDid: FRANK_DID,
 *        outPath: frank.tnpkg, groups: ["default"] }).
 *   4. alice.info("c5.ts.payment", ...) ×2. alice.close().
 *   5. Frank cwd (chdir) → Tn.use("default"). Capture his keystore path.
 *   6. frank.pkg.absorb(frank.tnpkg) — kit lands in Frank's keystore.
 *   7. Iterate frank.read({ log: aliceLog, asRecipient: frankKeystore,
 *        group: "default" }). Assert both events surface.
 *
 * Asserts (named):
 *   - "alice-bundled-kit-on-disk"
 *   - "frank-absorb-receipt-kind-kit-bundle"
 *   - "frank-absorbed-kit-in-keystore"
 *   - "frank-decrypted-both-events"
 *   - "frank-fields-round-tripped"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, readdirSync } from "node:fs";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const FRANK_DID = "did:key:zFrank0123456789abcdefghjkmnpqrstuvwx";

test("C5 (TS): Alice mints kit, Frank absorbs + decrypts publisher log", async () => {
  setTestContext({
    silo: "c5",
    test: "c5_ts_recipient_decrypts::single_recipient_round_trip",
  });

  // Two distinct tmpdirs — Alice's cwd and Frank's cwd.
  const aliceDir = mkdtempSync(join(tmpdir(), "c5-ts-alice-"));
  const frankDir = mkdtempSync(join(tmpdir(), "c5-ts-frank-"));
  const cwdBefore = process.cwd();

  // ── Alice (publisher) ───────────────────────────────────────────
  process.chdir(aliceDir);
  const alice = await Tn.use("default");
  const aliceLog = alice.logPath;
  const aliceCfg = alice.config() as { keystorePath: string };
  const aliceBundleDir = join(aliceDir, "alice_bundles");
  mkdirSync(aliceBundleDir, { recursive: true });

  await alice.admin.addRecipient("default", { recipientDid: FRANK_DID });
  const frankTnpkg = join(aliceBundleDir, "frank.tnpkg");
  await alice.pkg.bundleForRecipient({
    recipientDid: FRANK_DID,
    outPath: frankTnpkg,
    groups: ["default"],
  });

  assertNamed({
    name: "alice-bundled-kit-on-disk",
    expected: true,
    observed: existsSync(frankTnpkg),
    onMiss:
      `Alice's bundleForRecipient didn't produce ${frankTnpkg}. ` +
      "Check ts-sdk/src/pkg/index.ts:bundleForRecipient and the wasm-side packer.",
  });

  alice.info("c5.ts.payment", { amount: 1000, currency: "USD" });
  alice.info("c5.ts.payment", { amount: 250, currency: "USD" });
  await alice.close();

  // ── Frank (recipient, separate cwd + ceremony) ──────────────────
  process.chdir(frankDir);
  let frank: Tn | undefined;
  try {
    frank = await Tn.use("default");
    const frankKeystore = (frank.config() as { keystorePath: string }).keystorePath;

    const receipt = await frank.pkg.absorb(frankTnpkg);
    assertNamed({
      name: "frank-absorb-receipt-kind-kit-bundle",
      expected: "kit_bundle",
      observed: receipt.kind,
      onMiss:
        `absorb receipt kind=${JSON.stringify(receipt.kind)}; expected ` +
        "kit_bundle. Check ts-sdk/src/runtime/node_runtime.ts:absorbPkg dispatch.",
    });

    const absorbedKit = join(frankKeystore, "default.btn.mykit");
    assertNamed({
      name: "frank-absorbed-kit-in-keystore",
      expected: true,
      observed: existsSync(absorbedKit),
      onMiss:
        `After absorb, expected ${absorbedKit} on disk. Receipt: ` +
        `${JSON.stringify(receipt)}. Keystore inventory: ` +
        `${existsSync(frankKeystore) ? JSON.stringify(readdirSync(frankKeystore)) : "no-dir"}.`,
    });

    // Decrypt Alice's log under Frank's keystore.
    const decrypted: Array<{ event_type: string; fields: Record<string, unknown> }> = [];
    for (const entry of frank.read({
      log: aliceLog,
      asRecipient: frankKeystore,
      group: "default",
    })) {
      const e = entry as unknown as {
        event_type?: string;
        hidden_groups?: string[];
        fields?: Record<string, unknown>;
      };
      if (e.event_type === "c5.ts.payment") {
        const hidden = e.hidden_groups ?? [];
        if (!hidden.includes("default")) {
          decrypted.push({ event_type: e.event_type, fields: e.fields ?? {} });
        }
      }
    }

    assertNamed({
      name: "frank-decrypted-both-events",
      expected: 2,
      observed: decrypted.length,
      onMiss:
        `Frank decrypted ${decrypted.length} events; expected 2. ` +
        "If 0: the kit didn't land where the reader looks (check " +
        "ts-sdk/src/runtime/node_runtime.ts read path + keystore discovery). " +
        "If some were hidden: cipher dispatch failed under wasm.",
    });

    // Fields round-tripped — check the first payment's amount.
    const amounts = decrypted.map((d) => d.fields["amount"]);
    assertNamed({
      name: "frank-fields-round-tripped",
      expected: true,
      observed: amounts.includes(1000) && amounts.includes(250),
      onMiss:
        `Decrypted amounts: ${JSON.stringify(amounts)}; expected to ` +
        "contain 1000 and 250. The canonical-encode round-trip lost field data.",
    });

    void assert;
  } finally {
    if (frank !== undefined) await frank.close();
    process.chdir(cwdBefore);
  }
});
