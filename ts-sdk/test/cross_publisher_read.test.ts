// Stage-6 cross-publisher btn read parity (FINDINGS S6.2 cross-binding port).
//
// Mirrors Python's `tests/integration/test_cash_register_stage6.py`. Two
// independent ceremonies (Alice + Bob); Alice mints a kit for Bob,
// bundles it, Bob absorbs it, then Bob reads Alice's log via
// `Tn.read({log, asRecipient})` — the new public surface for foreign-log
// reads (post-0.4.0a1; replaces the now-internal `readAsRecipient`
// free function).

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Entry } from "../src/Entry.js";
import type { CeremonyConfig } from "../src/runtime/config.js";
import { Tn } from "../src/tn.js";

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
    const aliceDid = alice.did;
    const bob = await Tn.init(join(bobDir, "bob.yaml"));

    const bundle = join(aliceDir, "bob.tnpkg");
    await alice.pkg.bundleForRecipient({ recipientDid: bob.did, outPath: bundle });
    await alice.close();

    const receipt = await bob.pkg.absorb(bundle);
    assert.equal(receipt.kind, "kit_bundle", `unexpected absorb kind: ${receipt.kind}`);
    assert.ok(receipt.acceptedCount >= 1, "absorb didn't apply kit");
    assert.equal(receipt.verifiedPublisherDid, aliceDid);

    const markers: string[] = [];
    for (const entry of bob.read({ log: aliceLog })) {
      if (entry instanceof Entry && entry.event_type === "evt.cross") {
        const m = entry.fields["marker"];
        if (typeof m === "string") markers.push(m);
      }
    }

    const sourceRows = readFileSync(aliceLog, "utf8").trim().split(/\r?\n/);
    for (const [label, replacement] of [
      ["missing", undefined],
      ["non-string", 42],
    ] as const) {
      const malformed = JSON.parse(sourceRows[0]!) as Record<string, unknown>;
      if (replacement === undefined) delete malformed["event_type"];
      else malformed["event_type"] = replacement;
      const badLog = join(root, `${label}-event-type.ndjson`);
      writeFileSync(badLog, `${JSON.stringify(malformed)}\n`, "utf8");
      assert.throws(() => [...bob.read({ log: badLog })], /event_type must be a string/);
      await assert.rejects(async () => {
        for await (const _entry of bob.readAsync({ log: badLog })) {
          // Fully consume the async generator so structural validation runs.
        }
      }, /event_type must be a string/);
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
    const bob = await Tn.init(join(bobDir, "bob.yaml"));
    const bundle = join(aliceDir, "frank.tnpkg");
    await alice.pkg.bundleForRecipient({ recipientDid: bob.did, outPath: bundle });
    await alice.close();

    await bob.pkg.absorb(bundle);
    const bobKeystore = (bob.config() as CeremonyConfig).keystorePath;

    const entries: Entry[] = [];
    for (const e of bob.read({
      log: aliceLog,
      asRecipient: bobKeystore,
      group: "default",
    })) {
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

test("a kit addressed to another DID installs nothing and grants no publisher trust", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-wrong-kit-recipient-"));
  try {
    const alice = await Tn.init(join(root, "alice", "tn.yaml"));
    const bob = await Tn.init(join(root, "bob", "tn.yaml"));
    const eve = await Tn.init(join(root, "eve", "tn.yaml"));
    const bundle = join(root, "for-bob.tnpkg");
    await alice.pkg.bundleForRecipient({ recipientDid: bob.did, outPath: bundle });
    const eveKeystore = (eve.config() as CeremonyConfig).keystorePath;
    const eveKitPath = join(eveKeystore, "default.btn.mykit");
    const before = readFileSync(eveKitPath);

    const receipt = await eve.pkg.absorb(bundle);
    assert.match(receipt.rejectedReason ?? "", /recipient_identity/);
    assert.equal(receipt.acceptedCount, 0);
    assert.deepEqual(readFileSync(eveKitPath), before);
    assert.equal(existsSync(join(eveKeystore, "trust", "verified_publishers.v1.json")), false);

    await alice.close();
    await bob.close();
    await eve.close();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
