import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { bytesToB64 } from "../src/core/encoding.js";
import { DeviceKey } from "../src/core/signing.js";
import {
  enrollmentChallengeDigest,
  sha256Digest,
  signEnrollmentChallenge,
  signKeyBindingProof,
  verifyJweEnrollmentSource,
  type EnrollmentChallengeV1,
  type KeyBindingProofV1,
} from "../src/core/trust.js";
import { PkgNamespace } from "../src/pkg/index.js";
import { AdminNamespace } from "../src/admin/index.js";
import { readAsRecipientAsync } from "../src/read_as_recipient.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { readTnpkgVerified } from "../src/tnpkg_io.js";

const NOW = "2026-07-14T18:00:00Z";
const EXPIRES = "2026-07-14T18:10:00Z";

function signedChallenge(publisher: DeviceKey, reader: DeviceKey): EnrollmentChallengeV1 {
  return signEnrollmentChallenge(
    {
      version: 1,
      kind: "tn-enrollment-challenge",
      publisher_did: publisher.did,
      expected_reader_did: reader.did,
      ceremony_id: "ceremony-public-jwe",
      group: "partners",
      nonce_b64: bytesToB64(new Uint8Array(32).fill(1)),
      issued_at: NOW,
      expires_at: EXPIRES,
      challenge_id: "challenge-public-jwe",
      signature_b64: "",
    },
    publisher,
  );
}

function signedProof(
  publisher: DeviceKey,
  reader: DeviceKey,
  challenge: EnrollmentChallengeV1 | null,
): KeyBindingProofV1 {
  const privateKey = new Uint8Array(32).fill(7);
  return signKeyBindingProof(
    {
      version: 1,
      purpose: "jwe-reader",
      subject_did: reader.did,
      audience_did: publisher.did,
      ceremony_id: "ceremony-public-jwe",
      group: "partners",
      issued_at: NOW,
      expires_at: EXPIRES,
      nonce_b64: bytesToB64(new Uint8Array(32).fill(2)),
      binding: {
        algorithm: "X25519",
        public_key_b64: bytesToB64(x25519.getPublicKey(privateKey)),
        challenge_digest: challenge === null ? null : enrollmentChallengeDigest(challenge),
      },
      signature_b64: "",
    },
    reader,
  );
}

test("signed key cards and challenge responses normalize to one verified JWE binding", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const challenge = signedChallenge(publisher, reader);
  const expected = {
    publisherDid: publisher.did,
    ceremonyId: "ceremony-public-jwe",
    group: "partners",
    now: NOW,
  };

  const card = signedProof(publisher, reader, null);
  const fromCard = verifyJweEnrollmentSource({ kind: "signed-key-card", proof: card }, expected);
  assert.equal(fromCard.principal.did, reader.did);
  assert.equal(fromCard.challengeDigest, null);
  assert.equal(fromCard.publicKeySha256, sha256Digest(fromCard.publicKey));

  const response = signedProof(publisher, reader, challenge);
  const fromChallenge = verifyJweEnrollmentSource(
    { kind: "challenge-response", proof: response, challenge },
    expected,
  );
  assert.equal(fromChallenge.principal.did, reader.did);
  assert.equal(fromChallenge.challengeDigest, enrollmentChallengeDigest(challenge));

  assert.throws(
    () => verifyJweEnrollmentSource({ kind: "signed-key-card", proof: response }, expected),
    /challenge_missing/,
  );
});

test("pkg.offer emits a public-only signed JWE key card and retains the private key locally", async () => {
  const publisherDir = mkdtempSync(join(tmpdir(), "tn-jwe-card-publisher-"));
  const readerDir = mkdtempSync(join(tmpdir(), "tn-jwe-card-reader-"));
  const publisher = NodeRuntime.init(join(publisherDir, "tn.yaml"), { cipher: "jwe" });
  const reader = NodeRuntime.init(join(readerDir, "tn.yaml"));
  const publisherPkg = new PkgNamespace(publisher);
  const readerPkg = new PkgNamespace(reader);
  const outPath = join(readerDir, "reader-key-card.tnpkg");

  const offered = await readerPkg.offer({
    group: "default",
    peerDid: publisher.did,
    outPath,
    jweEnrollment: {
      kind: "signed-key-card",
      ceremonyId: publisher.config.ceremonyId,
      ttlMs: 5 * 60_000,
    },
  });
  assert.ok(offered.offerDigest?.startsWith("sha256:"));

  const privatePath = join(reader.config.keystorePath, "default.jwe.mykey");
  const privateKey = new Uint8Array(readFileSync(privatePath));
  assert.equal(privateKey.length, 32);

  const opened = readTnpkgVerified(outPath);
  assert.deepEqual([...opened.body.keys()], ["body/package.json"]);
  const packageJson = JSON.parse(
    new TextDecoder().decode(opened.body.get("body/package.json")),
  ) as Record<string, unknown>;
  const payload = packageJson["payload"] as Record<string, unknown>;
  const proof = payload["key_binding_proof"] as Record<string, unknown>;
  const binding = proof["binding"] as Record<string, unknown>;
  assert.equal(binding["challenge_digest"], null);
  assert.equal(packageJson["recipient_identity"], publisher.did);
  assert.equal(JSON.stringify(packageJson).includes(bytesToB64(privateKey)), false);
  assert.equal(JSON.stringify(packageJson).includes("jwe.mykey"), false);

  const absorbed = await publisherPkg.absorb(outPath);
  assert.equal(absorbed.rejectedReason, undefined);
  await assert.rejects(publisherPkg.reconcilePending(offered.offerDigest!), /untrusted_principal/);
  const accepted = await publisherPkg.approveAndReconcile(offered.offerDigest!);
  assert.equal(accepted.binding.principal.did, reader.did);

  await assert.rejects(
    publisherPkg.bundleForRecipient({
      recipientDid: reader.did,
      outPath: join(publisherDir, "invalid-jwe-kit.tnpkg"),
      groups: ["default"],
    }),
    /use tn\.pkg\.prepareRecipient.*public-only JWE activation/,
  );

  await assert.rejects(
    publisherPkg.prepareRecipient({
      recipientDid: reader.did,
      outDir: join(publisherDir, "invalid-ttl"),
      groups: ["default"],
      acceptedOffers: [accepted],
      activationTtlMs: 1.5,
    }),
    /activationTtlMs must be a positive safe integer/,
  );

  const prepared = await publisherPkg.prepareRecipient({
    recipientDid: reader.did,
    outDir: join(publisherDir, "prepared"),
    groups: ["default"],
    acceptedOffers: [accepted],
    activationTtlMs: 10 * 60_000,
  });
  assert.equal(prepared.kitBundle, null);
  assert.deepEqual(prepared.requestedGroups, ["default"]);
  assert.equal(prepared.jweActivations.length, 1);

  const activationPath = prepared.jweActivations[0]!.package.outPath;
  const activation = readTnpkgVerified(activationPath);
  assert.deepEqual([...activation.body.keys()], ["body/package.json"]);
  for (const [name, bytes] of activation.body) {
    assert.equal(name.includes(".jwe.mykey"), false);
    assert.equal(Buffer.from(bytes).includes(Buffer.from(privateKey)), false);
  }
  const installed = await readerPkg.absorb(activationPath);
  assert.equal(installed.rejectedReason, undefined);
  assert.equal(installed.verifiedPublisherDid, publisher.did);

  await publisher.emitAsync("info", "prepared.secret", { value: "opened" });
  const rows = [];
  for await (const row of readAsRecipientAsync(
    publisher.config.logPath,
    reader.config.keystorePath,
    { group: "default" },
  )) {
    if (row.envelope["event_type"] === "prepared.secret") rows.push(row);
  }
  assert.deepEqual(rows[0]?.plaintext["default"], { value: "opened" });

  publisher.close();
  reader.close();
});

test("bundleForRecipient rejects mixed JWE requests before minting a BTN kit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-jwe-mixed-bundle-"));
  const publisher = NodeRuntime.init(join(dir, "tn.yaml"));
  const admin = new AdminNamespace(publisher);
  await admin.ensureGroup("partners", { cipher: "jwe" });

  const statePath = join(publisher.config.keystorePath, "default.btn.state");
  const before = new Uint8Array(readFileSync(statePath));
  const outPath = join(dir, "must-not-exist.tnpkg");
  await assert.rejects(
    new PkgNamespace(publisher).bundleForRecipient({
      recipientDid: DeviceKey.generate().did,
      outPath,
      groups: ["default", "partners"],
    }),
    /use tn\.pkg\.prepareRecipient/,
  );
  assert.deepEqual(new Uint8Array(readFileSync(statePath)), before);
  assert.equal(existsSync(outPath), false);
  publisher.close();
});
