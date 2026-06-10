import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isManifestSignatureValid, readTnpkg } from "../src/index.js";
import { Tn } from "../src/tn.js";

test("tn.pkg.export adminLogSnapshot writes a tnpkg and returns its path", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-test-"));
  try {
    const outPath = join(tmp, "snapshot.tnpkg");
    const written = await tn.pkg.export({ adminLogSnapshot: { outPath } }, outPath);
    assert.equal(written, outPath);
    assert.ok(statSync(outPath).size > 0, "exported file should be non-empty");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.absorb round-trips an admin-log snapshot", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-absorb-"));
  try {
    const out = join(tmp, "snapshot.tnpkg");
    await tn.pkg.export({ adminLogSnapshot: { outPath: out } }, out);
    const receipt = await tn.pkg.absorb(out);
    assert.equal(typeof receipt.acceptedCount, "number");
    assert.equal(typeof receipt.dedupedCount, "number");
    assert.equal(typeof receipt.kind, "string");
    assert.equal(receipt.kind, "admin_log_snapshot");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.compileEnrolment writes a tnpkg and returns CompiledPackage", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-enrol-"));
  try {
    const outPath = join(tmp, "enrolment.tnpkg");
    const result = await tn.pkg.compileEnrolment({
      group: "default",
      recipientDid: "did:key:zTestRecipient",
      outPath,
    });
    assert.equal(result.outPath, outPath);
    assert.ok(typeof result.manifestSha256 === "string" && result.manifestSha256.length === 64);
    assert.ok(statSync(outPath).size > 0, "compiled enrolment file should be non-empty");

    // The compiled artifact must be a CANONICAL, signed kit_bundle (not the
    // legacy "tnpkg-v1" manifest) so `absorb` accepts it: canonical kind,
    // a verifying signature, readers-only state, and kits packed under body/.
    const { manifest, body } = readTnpkg(outPath);
    assert.equal(manifest.kind, "kit_bundle");
    assert.equal(manifest.version, 1);
    assert.equal(isManifestSignatureValid(manifest), true);
    assert.equal((manifest.state as { kind?: string }).kind, "readers-only");
    const stateKits = (manifest.state as { kits?: Array<{ name: string }> }).kits ?? [];
    assert.ok(stateKits.length >= 1, "state.kits should list at least one kit");
    assert.ok(
      [...body.keys()].some((k) => k.startsWith("body/") && k.endsWith(".btn.mykit")),
      "reader kits must be packed under body/<group>.btn.mykit",
    );
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.offer returns OfferReceipt with status='offered'", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-offer-"));
  try {
    const outPath = join(tmp, "offer.tnpkg");
    const receipt = await tn.pkg.offer({
      group: "default",
      peerDid: "did:key:zTestPeer",
      outPath,
    });
    assert.equal(receipt.status, "offered");
    assert.equal(receipt.group, "default");
    assert.equal(receipt.peerDid, "did:key:zTestPeer");
    assert.ok(typeof receipt.packageSha256 === "string" && receipt.packageSha256.length === 64);
    assert.equal(receipt.packagePath, outPath);
    assert.ok(statSync(outPath).size > 0, "offer package file should be non-empty");
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
