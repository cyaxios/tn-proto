// Stage-6 cross-publisher btn read parity (FINDINGS S6.2 cross-binding port).
//
// Mirrors Python's `tests/integration/test_cash_register_stage6.py`. Two
// independent ceremonies (Alice + Bob); Alice mints a kit for Bob,
// bundles it, Bob absorbs it, then Bob reads Alice's log. The runtime's
// own decrypt path is bound to Bob's btn state, so a naive read raises;
// `client.read({logPath})` must auto-route through `readAsRecipient`
// using Bob's keystore where the absorbed kit lives.
//
// Also exercises the standalone `readAsRecipient` export — the verb the
// cross-binding survey flagged as missing in TS.

import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { readAsRecipient } from "../src/index.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { Tn } from "../src/tn.js";

const PROFESSOR_DID = "did:key:z6MkfakefakefakefakefakefakefakefakefakefakeProfDID";

test("client.read({logPath}) auto-routes cross-publisher btn logs (FINDINGS S6.2)", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-cross-pub-"));
  const aliceDir = join(root, "alice");
  const bobDir = join(root, "bob");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(bobDir, { recursive: true });

  try {
    // Alice publishes a log + bundles a kit for Bob.
    const alice = await Tn.init(join(aliceDir, "alice.yaml"));
    alice.info("evt.cross", { marker: "alpha" });
    alice.info("evt.cross", { marker: "beta" });
    const aliceLog = alice.logPath;

    const bundle = join(aliceDir, "bob.tnpkg");
    await alice.pkg.bundleForRecipient({ recipientDid: PROFESSOR_DID, outPath: bundle });
    await alice.close();

    // Bob inits + absorbs.
    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    const receipt = await bob.pkg.absorb(bundle);
    assert.equal(receipt.kind, "kit_bundle", `unexpected absorb kind: ${receipt.kind}`);
    assert.ok(receipt.acceptedCount >= 1, "absorb didn't apply kit");

    // Direct read of Alice's log — this is the historically broken path.
    // Without auto-routing, the runtime tries to decrypt with Bob's btn
    // state and Rust raises "kit not entitled". With the fix in
    // client.read({logPath}), the verb peeks at the first envelope's
    // publisher did, sees it's not Bob's, and routes through
    // readAsRecipient using Bob's keystore.
    const markers: string[] = [];
    for (const entry of bob.read({ logPath: aliceLog })) {
      const flat = entry as Record<string, unknown>;
      if (flat["event_type"] === "evt.cross" && typeof flat["marker"] === "string") {
        markers.push(flat["marker"] as string);
      }
    }
    await bob.close();

    assert.deepEqual(
      markers.sort(),
      ["alpha", "beta"],
      `cross-publisher read should yield both events, got ${JSON.stringify(markers)}`,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("readAsRecipient standalone verb decrypts a foreign btn log", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-foreign-read-"));
  const aliceDir = join(root, "alice");
  const bobDir = join(root, "bob");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(bobDir, { recursive: true });

  try {
    const alice = await Tn.init(join(aliceDir, "alice.yaml"));
    alice.info("evt.solo", { marker: "x" });
    const aliceLog = alice.logPath;
    const bundle = join(aliceDir, "frank.tnpkg");
    await alice.pkg.bundleForRecipient({ recipientDid: PROFESSOR_DID, outPath: bundle });
    await alice.close();

    // Bob inits + absorbs to get the kit on disk.
    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    await bob.pkg.absorb(bundle);
    const bobKeystore = (bob.config() as CeremonyConfig).keystorePath;
    await bob.close();

    // Use the standalone verb — no client instance, just (logPath, keystorePath).
    const entries = [...readAsRecipient(aliceLog, bobKeystore, { group: "default" })];
    const decrypted = entries
      .map((e) => e.plaintext["default"])
      .filter((pt): pt is Record<string, unknown> => !!pt && !pt["$no_read_key"] && !pt["$decrypt_error"]);

    assert.ok(
      decrypted.some((pt) => pt["marker"] === "x"),
      `expected marker='x' to round-trip, got ${JSON.stringify(decrypted)}`,
    );

    // Sig + chain validity should be true for a non-tampered log.
    for (const entry of entries) {
      assert.equal(entry.valid.signature, true, `signature failed for ${JSON.stringify(entry.envelope)}`);
      assert.equal(entry.valid.chain, true, `chain failed for ${JSON.stringify(entry.envelope)}`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("readAsRecipient raises when no kit is present", () => {
  const root = mkdtempSync(join(tmpdir(), "tn-no-kit-"));
  try {
    // Empty keystore dir — no .btn.mykit, no .jwe.mykey.
    assert.throws(
      () => [...readAsRecipient("/no/such/log.ndjson", root, { group: "default" })],
      /no recipient kit for group/i,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
