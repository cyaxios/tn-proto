import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, statSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isManifestSignatureValid, readTnpkg } from "../src/index.js";
import { Tn } from "../src/tn.js";
import { DeviceKey } from "../src/core/signing.js";
import { absorbSealedKitBundle } from "../src/seal_bundle_producer.js";
import { Entry } from "../src/Entry.js";

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

test("tn.pkg.bundleForRecipient sealForRecipient produces a recipient-sealed tnpkg", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-seal-"));
  try {
    // A real did:key recipient with an embedded Ed25519 public key.
    const recipientSeed = new Uint8Array(32).fill(0x42);
    const recipient = DeviceKey.fromSeed(recipientSeed);

    const outPath = join(tmp, "sealed.tnpkg");
    const result = await tn.pkg.bundleForRecipient({
      recipientDid: recipient.did,
      outPath,
      groups: ["default"],
      sealForRecipient: true,
    });
    assert.equal(result.bundlePath, outPath);
    assert.equal(result.recipientDid, recipient.did);
    assert.ok(statSync(outPath).size > 0, "sealed bundle should be non-empty");

    // Artifact shape parity with Python's sealed bundle: kit_bundle kind,
    // verifying signature, body collapsed to a single body/encrypted.bin,
    // and recipient wraps in state.body_encryption.
    const { manifest, body } = readTnpkg(outPath);
    assert.equal(manifest.kind, "kit_bundle");
    assert.equal(isManifestSignatureValid(manifest), true);
    assert.ok(body.has("body/encrypted.bin"), "sealed body must be body/encrypted.bin");
    assert.equal(
      [...body.keys()].some((k) => k.endsWith(".btn.mykit")),
      false,
      "no plaintext kit member should leak into a sealed bundle",
    );
    const be = (manifest.state as { body_encryption?: Record<string, unknown> })
      .body_encryption;
    assert.ok(be, "sealed bundle must carry state.body_encryption");
    assert.ok(
      Array.isArray((be as { recipient_wraps?: unknown[] }).recipient_wraps),
      "sealed bundle must carry recipient_wraps[]",
    );

    // The named recipient can recover the kits; a different identity cannot.
    const ksGood = join(tmp, "ks-good");
    mkdirSync(ksGood, { recursive: true });
    const good = await absorbSealedKitBundle(outPath, {
      seed: recipientSeed,
      keystoreDir: ksGood,
    });
    assert.equal(good.rejectedReason, undefined);
    assert.ok(good.acceptedCount >= 1, "named recipient should install >=1 kit");

    const wrongSeed = new Uint8Array(32).fill(0x99);
    const ksBad = join(tmp, "ks-bad");
    mkdirSync(ksBad, { recursive: true });
    const bad = await absorbSealedKitBundle(outPath, {
      seed: wrongSeed,
      keystoreDir: ksBad,
    });
    assert.ok(bad.rejectedReason, "a non-recipient must be rejected");
    assert.equal(bad.acceptedCount, 0);
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.bundleForRecipient sealForRecipient rejects a keyless recipient DID", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-seal-bad-"));
  try {
    // A synthetic / vault DID has no embedded Ed25519 key to wrap under.
    await assert.rejects(
      () =>
        tn.pkg.bundleForRecipient({
          recipientDid: "did:vault:dev:nokey",
          outPath: join(tmp, "nope.tnpkg"),
          groups: ["default"],
          sealForRecipient: true,
        }),
      /requires a recipient did:key/,
    );
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.prepareRecipient seals by default and canonical absorb opens only for the reader", async () => {
  const publisher = await Tn.ephemeral({ stdout: false });
  const reader = await Tn.ephemeral({ stdout: false });
  const stranger = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-prepare-sealed-"));
  try {
    const prepared = await publisher.pkg.prepareRecipient({
      recipientDid: reader.did,
      outDir: tmp,
      groups: ["default"],
    });
    assert.ok(prepared.kitBundle);
    const bundlePath = prepared.kitBundle.bundlePath;
    const { manifest, body } = readTnpkg(bundlePath);
    assert.ok(
      (manifest.state as { body_encryption?: unknown }).body_encryption,
      "prepareRecipient must recipient-seal bearer kits by default",
    );
    assert.deepEqual([...body.keys()], ["body/encrypted.bin"]);

    const rejected = await stranger.pkg.absorb(bundlePath);
    assert.equal(rejected.acceptedCount, 0);
    assert.match(rejected.rejectedReason ?? "", /recipient.*(?:match|wrap)/i);

    const installed = await reader.pkg.absorb(bundlePath);
    assert.equal(installed.rejectedReason, undefined);
    assert.ok(installed.acceptedCount >= 1);

    publisher.info("prepared.secret", { value: "opened" });
    const rows = [...reader.read({ log: (publisher.config() as { logPath: string }).logPath })];
    const entry = rows.find(
      (row): row is Entry => row instanceof Entry && row.event_type === "prepared.secret",
    );
    assert.deepEqual(entry?.fields, { value: "opened" });
  } finally {
    await publisher.close();
    await reader.close();
    await stranger.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.absorb legacy two-arg form returns AbsorbResult", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-absorb-legacy-"));
  try {
    const out = join(tmp, "snapshot.tnpkg");
    await tn.pkg.export({ adminLogSnapshot: { outPath: out } }, out);

    const cfg = tn.config() as Parameters<typeof tn.pkg.absorb>[0];
    const result = await tn.pkg.absorb(cfg, out);

    // Legacy AbsorbResult shape: { status, reason, peerDid } — NOT the
    // richer AbsorbReceipt. status is one of Python's legacy strings.
    assert.equal(typeof result.status, "string");
    assert.equal(typeof result.reason, "string");
    assert.equal("peerDid" in result, true);
    assert.equal(result.peerDid, null);
    assert.ok(
      ["no_op", "enrolment_applied"].includes(result.status),
      `admin_log_snapshot legacy status should be no_op|enrolment_applied, got ${result.status}`,
    );
    // The legacy shape must NOT carry receipt-only fields.
    assert.equal("acceptedCount" in result, false);
    assert.equal("kind" in result, false);
  } finally {
    await tn.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("tn.pkg.absorb single-arg form still returns AbsorbReceipt", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  const tmp = mkdtempSync(join(tmpdir(), "tn-pkg-absorb-new-"));
  try {
    const out = join(tmp, "snapshot.tnpkg");
    await tn.pkg.export({ adminLogSnapshot: { outPath: out } }, out);
    const receipt = await tn.pkg.absorb(out);
    // Receipt shape unchanged by the overload addition.
    assert.equal(typeof receipt.acceptedCount, "number");
    assert.equal(receipt.kind, "admin_log_snapshot");
    assert.equal("status" in receipt, false);
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
