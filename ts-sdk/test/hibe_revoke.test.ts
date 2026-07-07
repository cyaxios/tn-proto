// HIBE reader add/remove lifecycle: grant two readers, revoke one, and
// verify the forward/backward semantics the docs promise. Mirrors
// python/tests/test_hibe_revoke.py:
//
//   - revoke = rotate the identity path + re-issue kits to the survivors
//   - the revoked reader keeps pre-revocation entries (permanent-key limit,
//     stated, not hidden) and loses everything after
//   - a survivor absorbs their re-issued kit and reads seamlessly across the
//     rotation (the superseded key is retained for old entries)
//   - grants are recorded in the authority-side registry; the registry and
//     the msk never ride a kit

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { readAsRecipient } from "../src/read_as_recipient.js";
import { readTnpkg } from "../src/tnpkg_io.js";

const ALICE = "did:key:z6Mk-alice";
const BOB = "did:key:z6Mk-bob";

function byType(logPath: string, keystore: string): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const e of readAsRecipient(logPath, keystore, { group: "default" })) {
    out[String(e.envelope["event_type"])] = e.plaintext["default"] ?? {};
  }
  return out;
}

test("hibe revoke: rotate + survivor re-kit; registry and msk never ride a kit", async () => {
  const ws = mkdtempSync(join(tmpdir(), "ts-hibe-revoke-"));
  const aYaml = join(ws, "authority", "tn.yaml");
  try {
    // --- Add two readers, seal epoch 1.
    let a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    const aLog = (a.config() as { logPath: string }).logPath;
    const aKeystore = (a.config() as { keystorePath: string }).keystorePath;
    a.info("e1", { note: "both readers admitted" });
    const aliceKit = join(ws, "alice.tnpkg");
    const bobKit = join(ws, "bob.tnpkg");
    await a.admin.grantReader("default", { readerDid: ALICE, outPath: aliceKit });
    await a.admin.grantReader("default", { readerDid: BOB, outPath: bobKit });
    let grants = JSON.parse(readFileSync(join(aKeystore, "default.hibe.grants"), "utf8")) as Array<{
      reader_did: string;
    }>;
    assert.deepEqual(new Set(grants.map((g) => g.reader_did)), new Set([ALICE, BOB]));

    // --- Remove bob: rotate + re-issue alice's kit.
    const res = await a.admin.revokeReader("default", BOB, { outDir: join(ws, "regrant") });
    assert.ok(res.revoked);
    assert.equal(res.newPath, "self~r1");
    assert.deepEqual(res.remaining, [ALICE]);
    assert.equal(res.kitPaths.length, 1);
    grants = JSON.parse(readFileSync(join(aKeystore, "default.hibe.grants"), "utf8")) as Array<{
      reader_did: string;
    }>;
    assert.deepEqual(new Set(grants.map((g) => g.reader_did)), new Set([ALICE]));
    a.info("e2", { note: "after bob was removed" });
    await a.close();

    // Neither the registry nor any master secret rides a kit.
    for (const kit of [aliceKit, bobKit, res.kitPaths[0]!]) {
      const { body } = readTnpkg(kit);
      const names = [...body.keys()];
      assert.ok(
        !names.some((n) => n.endsWith(".hibe.msk") || n.endsWith(".hibe.grants")),
        `secret rode a kit: ${JSON.stringify(names)}`,
      );
    }

    // --- Bob: keeps e1 (honest limit), locked out of e2.
    const bob = await Tn.init(join(ws, "bob", "tn.yaml"), { stdout: false, link: false });
    const bobKs = (bob.config() as { keystorePath: string }).keystorePath;
    await bob.pkg.absorb(bobKit);
    await bob.close();
    let got = byType(aLog, bobKs);
    assert.equal(got["e1"]!["note"], "both readers admitted");
    assert.deepEqual(got["e2"], { $no_read_key: true });

    // --- Alice: absorbs original + re-issued kit, reads across the
    // rotation without any special handling.
    const alice = await Tn.init(join(ws, "alice", "tn.yaml"), { stdout: false, link: false });
    const aliceKs = (alice.config() as { keystorePath: string }).keystorePath;
    await alice.pkg.absorb(aliceKit);
    await alice.pkg.absorb(res.kitPaths[0]!);
    await alice.close();
    got = byType(aLog, aliceKs);
    assert.equal(got["e1"]!["note"], "both readers admitted");
    assert.equal(got["e2"]!["note"], "after bob was removed");

    // --- Guardrails + the generic verb.
    a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    await assert.rejects(
      () => a.admin.revokeReader("default", "did:key:z6Mk-nobody"),
      /no recorded grant/,
      "revoking an unknown did must raise",
    );
    // revokeRecipient routes hibe groups to the same flow. The default
    // regrant outDir lands under cwd, so hop into the temp workspace for
    // the call (mirrors the Python test's os.chdir dance).
    const cwd = process.cwd();
    process.chdir(ws);
    let r2;
    try {
      r2 = await a.admin.revokeRecipient("default", { recipientDid: ALICE });
    } finally {
      process.chdir(cwd);
    }
    assert.equal(r2.cipher, "hibe");
    assert.equal(r2.newPath, "self~r2"); // counter bumps, not stacks
    assert.deepEqual(r2.kitPaths, []); // nobody left to re-kit
    await a.close();
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});
