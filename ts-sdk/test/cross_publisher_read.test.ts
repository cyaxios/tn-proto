// Stage-6 cross-publisher btn read parity (FINDINGS S6.2 cross-binding port).
//
// Mirrors Python's `tests/integration/test_cash_register_stage6.py`. Two
// independent ceremonies (Alice + Bob); Alice mints a kit for Bob,
// bundles it, Bob absorbs it, then Bob reads Alice's log via
// `Tn.read({log, asRecipient})` — the new public surface for foreign-log
// reads (post-0.4.0a1; replaces the now-internal `readAsRecipient`
// free function).

import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Entry } from "../src/Entry.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { Tn } from "../src/tn.js";

const PROFESSOR_DID = "did:key:z6MkfakefakefakefakefakefakefakefakefakefakeProfDID";

test("Tn.read({log}) auto-routes cross-publisher btn logs (FINDINGS S6.2)", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-cross-pub-"));
  const aliceDir = join(root, "alice");
  const bobDir = join(root, "bob");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(bobDir, { recursive: true });

  try {
    const alice = await Tn.init(join(aliceDir, "alice.yaml"));
    alice.info("evt.cross", { marker: "alpha" });
    alice.info("evt.cross", { marker: "beta" });
    const aliceLog = alice.logPath;

    const bundle = join(aliceDir, "bob.tnpkg");
    await alice.pkg.bundleForRecipient({ recipientDid: PROFESSOR_DID, outPath: bundle });
    await alice.close();

    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    const receipt = await bob.pkg.absorb(bundle);
    assert.equal(receipt.kind, "kit_bundle", `unexpected absorb kind: ${receipt.kind}`);
    assert.ok(receipt.acceptedCount >= 1, "absorb didn't apply kit");

    const markers: string[] = [];
    for (const entry of bob.read({ log: aliceLog })) {
      if (entry instanceof Entry && entry.event_type === "evt.cross") {
        const m = entry.fields["marker"];
        if (typeof m === "string") markers.push(m);
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

test("Tn.read({asRecipient}) decrypts a foreign btn log via the recipient verb", async () => {
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

    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    await bob.pkg.absorb(bundle);
    const bobKeystore = (bob.config() as CeremonyConfig).keystorePath;

    const entries: Entry[] = [];
    for (const e of bob.read({ log: aliceLog, asRecipient: bobKeystore, group: "default" })) {
      if (e instanceof Entry) entries.push(e);
    }
    const markers = entries.map((e) => e.fields["marker"]).filter((m) => typeof m === "string");
    assert.ok(
      markers.includes("x"),
      `expected marker='x' to round-trip, got ${JSON.stringify(markers)}`,
    );

    await bob.close();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Tn.read({asRecipient}) raises when no kit is present", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-no-kit-"));
  try {
    const tn = await Tn.ephemeral();
    try {
      assert.throws(
        () => [...tn.read({ log: "/no/such/log.ndjson", asRecipient: root, group: "default" })],
        /no recipient kit for group/i,
      );
    } finally {
      await tn.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
