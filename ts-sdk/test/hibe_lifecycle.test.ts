// Full hibe lifecycle at the TS layer, as one story through the public
// product surface (no cipher internals). Mirrors
// python/tests/test_hibe_lifecycle.py act for act:
//
//   Act 1  authority mints a hibe ceremony, logs epoch-a, grants reader 1
//   Act 2  reader 1 absorbs the kit and reads epoch-a from the foreign log
//   Act 3  authority rotates the policy path, logs epoch-b, grants reader 2
//   Act 4  reader 1 keeps epoch-a, loses epoch-b (permanent-key semantics)
//   Act 5  reader 2 opens epoch-b but not epoch-a (granted post-rotation)
//   Act 6  the authority reads across both epochs with signature, row_hash,
//          and chain all verifying
//
// Every ceremony is closed and reopened between acts, so the whole keystore
// persistence path is exercised, not just in-memory state.
//
// Readers are enrolled through the verified challenge->proof->grant flow: the
// authority issues a scoped one-time challenge, the reader signs it with its
// real device key, and the grant seals the kit to that proof (no unsafe
// plaintext delivery).

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { readAsRecipient } from "../src/read_as_recipient.js";
import { createHibeReaderProof } from "../src/core/trust.js";
import type { NodeRuntime } from "../src/runtime/node_runtime.js";

function rt(a: Tn): NodeRuntime {
  return (a as unknown as { _rt: NodeRuntime })._rt;
}

function byType(logPath: string, keystore: string): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const e of readAsRecipient(logPath, keystore, { group: "default" })) {
    const et = String(e.envelope["event_type"]);
    out[et] = e.plaintext["default"] ?? {};
  }
  return out;
}

test("hibe lifecycle: grant, rotate, permanent-key epochs, authority spans all", async () => {
  const ws = mkdtempSync(join(tmpdir(), "ts-hibe-lifecycle-"));
  const aYaml = join(ws, "authority", "tn.yaml");
  const r1Yaml = join(ws, "reader1", "tn.yaml");
  const r2Yaml = join(ws, "reader2", "tn.yaml");
  const kit1 = join(ws, "reader1.tnpkg");
  const kit2 = join(ws, "reader2.tnpkg");
  try {
    // Reader runtimes are created up front so their real did:key and device
    // key are on hand for the verified grant. The device key persists in the
    // keystore, so the reopened runtime in Acts 2/5 matches this identity.
    const r1 = await Tn.init(r1Yaml, { stdout: false, link: false });
    const r1Did = r1.did;
    const r1Device = rt(r1).keystore.device;
    await r1.close();
    const r2 = await Tn.init(r2Yaml, { stdout: false, link: false });
    const r2Did = r2.did;
    const r2Device = rt(r2).keystore.device;
    await r2.close();

    // --- Act 1: authority bootstraps, seals epoch-a, grants reader 1.
    let a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    const aLog = (a.config() as { logPath: string }).logPath;
    assert.equal((a.config() as { cipher: string }).cipher, "hibe");
    a.info("epoch.a.first", { note: "before rotation, entry 1" });
    a.info("epoch.a.second", { note: "before rotation, entry 2" });
    const ch1 = await a.admin.issueHibeReaderChallenge("default", r1Did, 60_000);
    const proof1 = await createHibeReaderProof(ch1, r1Device, { expectedAuthorityDid: a.did });
    await a.admin.grantReader("default", { readerDid: r1Did, proof: proof1, outPath: kit1 });
    await a.close();

    // --- Act 2: reader 1 absorbs and reads the foreign log.
    const r1b = await Tn.init(r1Yaml, { stdout: false, link: false });
    const r1Keystore = (r1b.config() as { keystorePath: string }).keystorePath;
    const receipt1 = await r1b.pkg.absorb(kit1);
    assert.equal(receipt1.rejectedReason, undefined);
    assert.ok(receipt1.acceptedCount >= 3, `expected mpk+idpath+sk installed, got ${receipt1.acceptedCount}`);
    await r1b.close();
    let got = byType(aLog, r1Keystore);
    assert.equal(got["epoch.a.first"]!["note"], "before rotation, entry 1");
    assert.equal(got["epoch.a.second"]!["note"], "before rotation, entry 2");

    // --- Act 3: rotation, epoch-b, a post-rotation grant.
    a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    await a.admin.rotateReaderPath("default", "policy-b");
    a.info("epoch.b.first", { note: "after rotation" });
    const ch2 = await a.admin.issueHibeReaderChallenge("default", r2Did, 60_000);
    const proof2 = await createHibeReaderProof(ch2, r2Device, { expectedAuthorityDid: a.did });
    await a.admin.grantReader("default", { readerDid: r2Did, proof: proof2, outPath: kit2 });
    await a.close();

    // --- Act 4: reader 1 keeps history, loses the new epoch.
    got = byType(aLog, r1Keystore);
    assert.equal(got["epoch.a.first"]!["note"], "before rotation, entry 1");
    assert.deepEqual(got["epoch.b.first"], { $no_read_key: true });

    // --- Act 5: reader 2 sees exactly the inverse.
    const r2b = await Tn.init(r2Yaml, { stdout: false, link: false });
    const r2Keystore = (r2b.config() as { keystorePath: string }).keystorePath;
    await r2b.pkg.absorb(kit2);
    await r2b.close();
    got = byType(aLog, r2Keystore);
    assert.equal(got["epoch.b.first"]!["note"], "after rotation");
    assert.deepEqual(got["epoch.a.first"], { $no_read_key: true });

    // --- Act 6: the authority spans both epochs and everything verifies.
    a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    const entries = [...rt(a).read(aLog)];
    assert.equal(entries.length, 3, `expected 3 user entries in the main log, got ${entries.length}`);
    for (const e of entries) {
      const ev = String(e.envelope["event_type"]);
      assert.ok(e.valid.signature, `bad signature: ${ev}`);
      assert.ok(e.valid.rowHash, `bad row_hash: ${ev}`);
      assert.ok(e.valid.chain, `broken chain: ${ev}`);
      assert.ok(
        "note" in (e.plaintext["default"] ?? {}),
        `authority decrypt failed: ${ev} -> ${JSON.stringify(e.plaintext["default"])}`,
      );
    }
    await a.close();
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});
