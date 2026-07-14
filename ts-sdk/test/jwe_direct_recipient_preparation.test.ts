import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { AdminNamespace } from "../src/admin/index.js";
import { Entry } from "../src/Entry.js";
import { canonicalize } from "../src/core/canonical.js";
import { didKeyToX25519Pub } from "../src/core/recipient_seal.js";
import { signatureB64 } from "../src/core/signing.js";
import {
  jweRecipientFromExternallyAuthenticatedDidDocument,
  jweRecipientFromFingerprintPin,
  type JweBindingScope,
  type VerifiedJweRecipient,
} from "../src/core/jwe_binding.js";
import { formatTrustTimestamp, sha256Digest } from "../src/core/trust.js";
import {
  foreignReadTrustedPublishers,
  verifyForeignRowIntegrity,
} from "../src/foreign_read_security.js";
import { PkgNamespace } from "../src/pkg/index.js";
import { readAsRecipientAsync } from "../src/read_as_recipient.js";
import { discoverRecipientGroups } from "../src/recipient_group_discovery.js";
import { loadConfig } from "../src/runtime/config.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { Tn } from "../src/tn.js";
import { readTnpkgVerified } from "../src/tnpkg_io.js";
import { computeRowHash } from "../src/raw.js";

function now(): string {
  return formatTrustTimestamp(Date.now() * 1000);
}

function scope(publisher: NodeRuntime, group = "default"): JweBindingScope {
  return {
    audienceDid: publisher.did,
    ceremonyId: publisher.config.ceremonyId,
    group,
    now: now(),
    ttlMs: 10 * 60_000,
  };
}

function localPublicKey(reader: NodeRuntime, group = "default"): Uint8Array {
  const privateKey = new Uint8Array(
    readFileSync(join(reader.config.keystorePath, `${group}.jwe.mykey`)),
  );
  return x25519.getPublicKey(privateKey);
}

function didDocumentBinding(
  publisher: NodeRuntime,
  readerDid: string,
  publicKey: Uint8Array,
): VerifiedJweRecipient {
  const method = `${readerDid}#jwe-1`;
  const document = {
    id: readerDid,
    keyAgreement: [
      {
        id: method,
        type: "JsonWebKey2020",
        controller: readerDid,
        publicKeyJwk: {
          kty: "OKP",
          crv: "X25519",
          x: Buffer.from(publicKey).toString("base64url"),
        },
      },
    ],
  };
  return jweRecipientFromExternallyAuthenticatedDidDocument({
    document,
    expectedDid: readerDid,
    verificationMethodId: method,
    scope: scope(publisher),
    evidence: {
      resolver: "did:key resolver with authenticated method result",
      resolutionDigest: sha256Digest(new TextEncoder().encode("authenticated result")),
      documentDigest: sha256Digest(canonicalize(document)),
    },
  });
}

test("authenticated DID document activation requires an exact reader expectation", async () => {
  const publisherDir = mkdtempSync(join(tmpdir(), "tn-jwe-direct-publisher-"));
  const readerDir = mkdtempSync(join(tmpdir(), "tn-jwe-direct-reader-"));
  const readerYaml = join(readerDir, "tn.yaml");
  const publisher = NodeRuntime.init(join(publisherDir, "tn.yaml"), { cipher: "jwe" });
  const reader = Tn.initSync(readerYaml);
  const publisherPkg = new PkgNamespace(publisher);
  const preparedReaderKey = reader.pkg.prepareDidKeyBoundJweReaderKey("default");
  assert.deepEqual(Object.keys(preparedReaderKey).sort(), [
    "group",
    "publicKey",
    "publicKeySha256",
  ]);
  assert.deepEqual(preparedReaderKey.publicKey, didKeyToX25519Pub(reader.did));
  const binding = didDocumentBinding(publisher, reader.did, preparedReaderKey.publicKey);
  assert.equal(preparedReaderKey.publicKeySha256, binding.publicKeySha256);
  const outDir = join(publisherDir, "prepared");

  const prepared = await publisherPkg.prepareRecipient({
    recipientDid: reader.did,
    outDir,
    groups: ["default"],
    jweRecipients: [binding],
  });
  const activation = prepared.jweActivations[0]!;
  assert.equal(activation.bindingDigest, binding.bindingDigest);
  assert.equal(activation.publicKeySha256, binding.publicKeySha256);
  await publisher.emitAsync("info", "direct.secret", { value: "opened" });

  const readerKeystore = loadConfig(readerYaml).keystorePath;
  const privateKey = readFileSync(join(readerKeystore, "default.jwe.mykey"));
  const archive = readTnpkgVerified(activation.package.outPath);
  for (const bytes of archive.body.values()) {
    assert.equal(Buffer.from(bytes).includes(privateKey), false);
  }

  const rejected = await reader.pkg.absorb(activation.package.outPath);
  assert.match(rejected.rejectedReason ?? "", /retained sent offer|activation expectation/);
  assert.equal(existsSync(join(readerKeystore, "trust", "verified_publishers.v1.json")), false);
  await assert.rejects(async () => {
    for await (const _row of reader.readAsync({ log: publisher.config.logPath })) {
      // consume the secure reader
    }
  }, /untrusted_principal/);
  const explicitlyWeakened = [];
  for await (const row of reader.readAsync({
    log: publisher.config.logPath,
    unsafeAllowUnverifiedPublisher: true,
  })) {
    explicitlyWeakened.push(row);
  }
  assert.equal(explicitlyWeakened.length > 0, true);

  const expectation = reader.pkg.expectJweActivation({
    publisherDid: publisher.did,
    ceremonyId: publisher.config.ceremonyId,
    group: "default",
    bindingDigest: binding.bindingDigest,
    x25519PublicKeySha256: binding.publicKeySha256,
    expiresAt: binding.expiresAt,
  });
  assert.equal(expectation.bindingDigest, binding.bindingDigest);

  const installed = await reader.pkg.absorb(activation.package.outPath);
  assert.equal(installed.rejectedReason, undefined);
  assert.equal(installed.verifiedPublisherDid, publisher.did);
  assert.equal(foreignReadTrustedPublishers(readerKeystore, {}).has(publisher.did), true);

  const rows = [];
  for await (const row of readAsRecipientAsync(publisher.config.logPath, readerKeystore)) {
    if (row.envelope["event_type"] === "direct.secret") rows.push(row);
  }
  assert.deepEqual(rows[0]?.plaintext["default"], { value: "opened" });

  const secureRows: Entry[] = [];
  for await (const row of reader.readAsync({ log: publisher.config.logPath })) {
    if (row instanceof Entry && row.event_type === "direct.secret") secureRows.push(row);
  }
  assert.deepEqual(secureRows[0]?.fields, { value: "opened" });

  const source = readFileSync(publisher.config.logPath, "utf8").trim().split(/\r?\n/);
  const tampered = JSON.parse(source.at(-1)!) as Record<string, unknown>;
  tampered["foreign_public_tamper"] = "changed";
  const integrity = verifyForeignRowIntegrity(tampered);
  assert.equal(integrity.signature, true);
  assert.equal(integrity.rowHash, false);
  const tamperedPath = join(readerDir, "tampered.ndjson");
  writeFileSync(tamperedPath, `${JSON.stringify(tampered)}\n`);
  await assert.rejects(async () => {
    for await (const _row of reader.readAsync({ log: tamperedPath })) {
      // consume the secure reader
    }
  }, /row_hash/);

  publisher.close();
  await reader.close();
});

test("foreign row integrity recomputation is shared by BTN envelopes", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-btn-foreign-integrity-"));
  const runtime = NodeRuntime.init(join(dir, "tn.yaml"));
  runtime.emit("info", "btn.integrity", { value: "sealed" });
  const line = readFileSync(runtime.config.logPath, "utf8").trim().split(/\r?\n/).at(-1)!;
  const envelope = JSON.parse(line) as Record<string, unknown>;
  assert.deepEqual(verifyForeignRowIntegrity(envelope), { signature: true, rowHash: true });

  const block = envelope["default"] as {
    ciphertext: string;
    field_hashes: Record<string, string>;
  };
  envelope["public_payload"] = { ciphertext: "literal public value", note: "not a group" };
  const nextHash = computeRowHash({
    device_identity: String(envelope["device_identity"]),
    timestamp: String(envelope["timestamp"]),
    event_id: String(envelope["event_id"]),
    event_type: String(envelope["event_type"]),
    level: String(envelope["level"]),
    prev_hash: String(envelope["prev_hash"]),
    public_fields: { public_payload: envelope["public_payload"] },
    groups: {
      default: {
        ciphertext_b64: block.ciphertext,
        field_hashes: block.field_hashes,
      },
    },
  });
  envelope["row_hash"] = nextHash;
  envelope["signature"] = signatureB64(
    runtime.keystore.device.sign(new TextEncoder().encode(nextHash)),
  );
  assert.deepEqual(verifyForeignRowIntegrity(envelope), { signature: true, rowHash: true });

  envelope["foreign_public_tamper"] = "changed";
  assert.deepEqual(verifyForeignRowIntegrity(envelope), { signature: true, rowHash: false });
  runtime.close();
});

test("reader-group discovery ignores HIBE public-only writer material", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-reader-group-discovery-"));
  writeFileSync(join(dir, "writer-only.hibe.mpk"), new Uint8Array([1]));
  assert.deepEqual(discoverRecipientGroups(dir), []);
  writeFileSync(join(dir, "court.hibe.sk.previous.1"), new Uint8Array([2]));
  assert.deepEqual(discoverRecipientGroups(dir), ["court"]);
});

test("normal read auto-discovers BTN and JWE keys for one mixed row", async () => {
  const publisherDir = mkdtempSync(join(tmpdir(), "tn-mixed-read-publisher-"));
  const readerDir = mkdtempSync(join(tmpdir(), "tn-mixed-read-reader-"));
  const readerYaml = join(readerDir, "tn.yaml");
  const publisher = NodeRuntime.init(join(publisherDir, "tn.yaml"));
  await new AdminNamespace(publisher).ensureGroup("partners", {
    cipher: "jwe",
    fields: ["jwe_secret"],
  });
  const reader = Tn.initSync(readerYaml);
  const readerKey = reader.pkg.prepareJweReaderKey("partners");
  const binding = jweRecipientFromFingerprintPin({
    readerDid: reader.did,
    publicKey: readerKey.publicKey,
    scope: scope(publisher, "partners"),
    pin: {
      expectedFingerprint: readerKey.publicKeySha256,
      verifiedBy: "operator:mixed",
      verificationMethod: "in-person QR comparison",
      evidence: "ticket-mixed-1",
    },
  });
  reader.pkg.expectJweActivation({
    publisherDid: publisher.did,
    ceremonyId: publisher.config.ceremonyId,
    group: "partners",
    bindingDigest: binding.bindingDigest,
    x25519PublicKeySha256: binding.publicKeySha256,
    expiresAt: binding.expiresAt,
  });
  const prepared = await new PkgNamespace(publisher).prepareRecipient({
    recipientDid: reader.did,
    outDir: join(publisherDir, "prepared"),
    groups: ["default", "partners"],
    jweRecipients: [binding],
  });
  assert.ok(prepared.kitBundle);
  await reader.pkg.absorb(prepared.kitBundle!.bundlePath);
  await reader.pkg.absorb(prepared.jweActivations[0]!.package.outPath);

  await publisher.emitAsync("info", "mixed.secret", {
    btn_secret: "btn-opened",
    jwe_secret: "jwe-opened",
  });
  const entries: Entry[] = [];
  for await (const row of reader.readAsync({ log: publisher.config.logPath })) {
    if (row instanceof Entry && row.event_type === "mixed.secret") entries.push(row);
  }
  assert.deepEqual(entries[0]?.fields, {
    btn_secret: "btn-opened",
    jwe_secret: "jwe-opened",
  });

  const jweOnly: Entry[] = [];
  for await (const row of reader.readAsync({
    log: publisher.config.logPath,
    group: "partners",
  })) {
    if (row instanceof Entry && row.event_type === "mixed.secret") jweOnly.push(row);
  }
  assert.deepEqual(jweOnly[0]?.fields, { jwe_secret: "jwe-opened" });

  publisher.close();
  await reader.close();
});

test("fingerprint activation persists public evidence and exact replay stays idempotent", async () => {
  const publisherDir = mkdtempSync(join(tmpdir(), "tn-jwe-pin-publisher-"));
  const readerDir = mkdtempSync(join(tmpdir(), "tn-jwe-pin-reader-"));
  const publisher = NodeRuntime.init(join(publisherDir, "tn.yaml"), { cipher: "jwe" });
  const reader = NodeRuntime.init(join(readerDir, "tn.yaml"), { cipher: "jwe" });
  const publisherPkg = new PkgNamespace(publisher);
  const readerPkg = new PkgNamespace(reader);
  const publicKey = localPublicKey(reader);
  const binding = jweRecipientFromFingerprintPin({
    readerDid: reader.did,
    publicKey,
    scope: scope(publisher),
    pin: {
      expectedFingerprint: sha256Digest(publicKey),
      verifiedBy: "operator:alice",
      verificationMethod: "voice call plus QR comparison",
      evidence: "ticket-493",
    },
  });
  readerPkg.expectJweActivation({
    publisherDid: publisher.did,
    ceremonyId: publisher.config.ceremonyId,
    group: "default",
    bindingDigest: binding.bindingDigest,
    x25519PublicKeySha256: binding.publicKeySha256,
    expiresAt: binding.expiresAt,
  });

  const prepared = await publisherPkg.prepareRecipient({
    recipientDid: reader.did,
    outDir: join(publisherDir, "prepared"),
    groups: ["default"],
    jweRecipients: [binding],
  });
  const activationPath = prepared.jweActivations[0]!.package.outPath;
  const first = await readerPkg.absorb(activationPath);
  const second = await readerPkg.absorb(activationPath);
  assert.equal(first.rejectedReason, undefined);
  assert.equal(second.rejectedReason, undefined);

  const trust = JSON.parse(
    readFileSync(join(publisher.config.keystorePath, "trust", "jwe_recipients.v1.json"), "utf8"),
  ) as Record<string, unknown>;
  const recipients = trust["recipients"] as Record<string, Record<string, unknown>>;
  const record = recipients["default"]![reader.did] as Record<string, unknown>;
  assert.equal(record["binding_digest"], binding.bindingDigest);
  assert.equal(record["evidence_kind"], "fingerprint-pin");
  assert.equal(JSON.stringify(record).includes("ticket-493"), false);

  publisher.close();
  reader.close();
});

test("invalid direct sources fail before mixed BTN or JWE state mutates", async () => {
  const publisherDir = mkdtempSync(join(tmpdir(), "tn-jwe-direct-atomic-publisher-"));
  const readerDir = mkdtempSync(join(tmpdir(), "tn-jwe-direct-atomic-reader-"));
  const publisher = NodeRuntime.init(join(publisherDir, "tn.yaml"));
  const reader = NodeRuntime.init(join(readerDir, "tn.yaml"));
  const admin = new AdminNamespace(publisher);
  const readerAdmin = new AdminNamespace(reader);
  await admin.ensureGroup("partners", { cipher: "jwe" });
  await readerAdmin.ensureGroup("partners", { cipher: "jwe" });
  const publicKey = localPublicKey(reader, "partners");
  const binding = jweRecipientFromFingerprintPin({
    readerDid: reader.did,
    publicKey,
    scope: scope(publisher, "partners"),
    pin: {
      expectedFingerprint: sha256Digest(publicKey),
      verifiedBy: "operator:bob",
      verificationMethod: "in-person fingerprint comparison",
      evidence: "ticket-997",
    },
  });
  const btnPath = join(publisher.config.keystorePath, "default.btn.state");
  const jwePath = join(publisher.config.keystorePath, "partners.jwe.recipients");
  const beforeBtn = readFileSync(btnPath);
  const beforeJwe = readFileSync(jwePath);
  const outDir = join(publisherDir, "must-not-exist");

  await assert.rejects(
    new PkgNamespace(publisher).prepareRecipient({
      recipientDid: reader.did,
      outDir,
      groups: ["default", "partners"],
      jweRecipients: [binding, binding],
    }),
    /exactly one verified JWE source/,
  );
  assert.deepEqual(readFileSync(btnPath), beforeBtn);
  assert.deepEqual(readFileSync(jwePath), beforeJwe);
  assert.equal(existsSync(outDir), false);
  assert.equal(
    existsSync(join(publisher.config.keystorePath, "trust", "jwe_recipients.v1.json")),
    false,
  );

  const mutated = { ...binding, bindingDigest: sha256Digest(new Uint8Array([1])) };
  await assert.rejects(
    new PkgNamespace(publisher).prepareRecipient({
      recipientDid: reader.did,
      outDir,
      groups: ["default", "partners"],
      jweRecipients: [mutated],
    }),
    /binding digest does not match/,
  );
  assert.deepEqual(readFileSync(btnPath), beforeBtn);
  assert.deepEqual(readFileSync(jwePath), beforeJwe);
  assert.equal(existsSync(outDir), false);

  const addRecipientJwe = publisher.addRecipientJwe.bind(publisher);
  publisher.addRecipientJwe = () => {
    throw new Error("simulated recipient activation failure");
  };
  await assert.rejects(
    admin.addRecipient("partners", { verifiedRecipient: binding }),
    /simulated recipient activation failure/,
  );
  publisher.addRecipientJwe = addRecipientJwe;
  assert.deepEqual(readFileSync(jwePath), beforeJwe);
  const retainedTrust = JSON.parse(
    readFileSync(join(publisher.config.keystorePath, "trust", "jwe_recipients.v1.json"), "utf8"),
  ) as Record<string, unknown>;
  const retainedGroups = retainedTrust["recipients"] as Record<
    string,
    Record<string, Record<string, unknown>>
  >;
  const retained = retainedGroups["partners"]![reader.did]!;
  assert.equal(retained["binding_digest"], binding.bindingDigest);
  assert.equal(retained["public_key_sha256"], binding.publicKeySha256);
  assert.equal(retained["verified"], true);

  publisher.close();
  reader.close();
});
