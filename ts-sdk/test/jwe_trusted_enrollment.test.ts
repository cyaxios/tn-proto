// Two-home public JWE trusted enrollment through first decrypt.
//
// Publisher and reader homes each run their own NodeRuntime; every step goes
// through the public PkgNamespace / AdminNamespace verbs:
//
//   publisher issueEnrollmentChallenge -> reader pkg.offer(challenge)
//   -> publisher pkg.absorb -> reconcilePending/approveAndReconcile
//   -> admin.addRecipient({acceptedOffer}) -> pkg.compileEnrolment
//   -> reader pkg.absorb (verified publisher install) -> publisher seal
//   -> reader first decrypt via readAsRecipientAsync.
//
// Also covers exact/conflicting replay and the unsafe raw registration
// warning + audit trail.
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { AdminNamespace } from "../src/admin/index.js";
import { PkgNamespace } from "../src/pkg/index.js";
import { readAsRecipientAsync } from "../src/read_as_recipient.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { UNSAFE_OPERATION_EVENT_TYPE } from "../src/runtime/enrollment.js";
import { newManifest, signManifest, toWireDict, type Manifest } from "../src/core/tnpkg.js";
import { canonicalize } from "../src/core/canonical.js";
import { packTnpkg } from "../src/tnpkg_io.js";

function collectWarnings(): { warnings: Error[]; stop: () => void } {
  const warnings: Error[] = [];
  const handler = (warning: Error): void => {
    if (warning.name === "TnSecurityWarning") warnings.push(warning);
  };
  process.on("warning", handler);
  return { warnings, stop: () => process.removeListener("warning", handler) };
}

async function flushWarnings(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

/** Every ndjson log under the ceremony dir (main + admin + protocol logs). */
function ndjsonFiles(root: string): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      const full = join(dir, name);
      try {
        if (statSync(full).isDirectory()) stack.push(full);
        else if (name.endsWith(".ndjson")) out.push(full);
      } catch {
        // skip unreadable entries
      }
    }
  }
  return out;
}

function auditEvents(rt: NodeRuntime): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const path of ndjsonFiles(rt.config.yamlDir)) {
    for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
      if (!line) continue;
      try {
        const env = JSON.parse(line) as Record<string, unknown>;
        if (env["event_type"] === UNSAFE_OPERATION_EVENT_TYPE) out.push(env);
      } catch {
        // skip non-JSON lines
      }
    }
  }
  return out;
}

test("two-home JWE trusted enrollment completes through first decrypt", async () => {
  const pubDir = mkdtempSync(join(tmpdir(), "tn-jwe-pub-"));
  const readDir = mkdtempSync(join(tmpdir(), "tn-jwe-read-"));
  const rtPub = NodeRuntime.init(join(pubDir, "tn.yaml"), { cipher: "jwe" });
  const rtReader = NodeRuntime.init(join(readDir, "tn.yaml"));
  const pkgPub = new PkgNamespace(rtPub);
  const adminPub = new AdminNamespace(rtPub);
  const pkgReader = new PkgNamespace(rtReader);

  // 1. Publisher pre-authorizes the exact reader DID with a signed challenge.
  const challenge = await pkgPub.issueEnrollmentChallenge(rtReader.did, "default", 5 * 60_000);
  assert.equal(challenge.kind, "tn-enrollment-challenge");
  assert.equal(challenge.publisher_did, rtPub.did);
  assert.equal(challenge.expected_reader_did, rtReader.did);
  assert.ok(challenge.signature_b64.length > 0);

  // 2. Reader answers with a signed key-binding offer bound to the challenge.
  const offerPath = join(readDir, "offer.tnpkg");
  const offer = await pkgReader.offer({
    group: "default",
    peerDid: rtPub.did,
    outPath: offerPath,
    challenge,
  });
  assert.equal(offer.status, "offered");
  assert.ok(offer.offerDigest?.startsWith("sha256:"), "trusted offer carries its digest");

  const myKeyPath = join(rtReader.config.keystorePath, "default.jwe.mykey");
  const myKeyBytes = new Uint8Array(readFileSync(myKeyPath));
  assert.equal(myKeyBytes.length, 32, "reader created a 32-byte X25519 private key");

  // Re-running the offer reuses the same private key.
  await pkgReader.offer({
    group: "default",
    peerDid: rtPub.did,
    outPath: join(readDir, "offer-again.tnpkg"),
    challenge,
  });
  assert.deepEqual(new Uint8Array(readFileSync(myKeyPath)), myKeyBytes);

  // 3. Publisher absorbs the offer into pending enrollment state.
  const absorbed = await pkgPub.absorb(offerPath);
  assert.equal(absorbed.kind, "offer");
  assert.equal(absorbed.rejectedReason, undefined);
  assert.equal(absorbed.acceptedCount, 1);
  assert.equal(absorbed.offerDigest, offer.offerDigest);

  // Exact replay converges without a rejection.
  const replay = await pkgPub.absorb(offerPath);
  assert.equal(replay.rejectedReason, undefined);
  assert.equal(replay.offerDigest, offer.offerDigest);

  // 4. Reconcile promotes the challenged, preauthorized binding.
  const accepted = await pkgPub.reconcilePending(offer.offerDigest!);
  assert.equal(accepted.offerDigest, offer.offerDigest);
  assert.equal(accepted.binding.principal.did, rtReader.did);
  assert.equal(accepted.binding.principal.audienceDid, rtPub.did);

  // approveAndReconcile on the same digest is idempotent.
  const approved = await pkgPub.approveAndReconcile(offer.offerDigest!);
  assert.deepEqual(approved, accepted);

  // A conflicting variant for the consumed challenge is rejected: a re-offer
  // signs a fresh nonce, so its digest differs while naming the same challenge.
  const conflictPath = join(readDir, "conflict.tnpkg");
  const conflictOffer = await pkgReader.offer({
    group: "default",
    peerDid: rtPub.did,
    outPath: conflictPath,
    challenge,
  });
  assert.notEqual(conflictOffer.offerDigest, offer.offerDigest);
  const conflicted = await pkgPub.absorb(conflictPath);
  assert.match(conflicted.rejectedReason ?? "", /replay_conflict/);

  // 5. Registration consumes the AcceptedOffer as one value.
  const added = await adminPub.addRecipient("default", { acceptedOffer: accepted });
  assert.equal(added.cipher, "jwe");
  assert.equal(added.recipientDid, rtReader.did);
  assert.equal(added.verified, true);
  assert.equal(added.proofDigest, accepted.binding.proofDigest);
  const recipientsDoc = JSON.parse(
    readFileSync(join(rtPub.config.keystorePath, "default.jwe.recipients"), "utf8"),
  ) as Array<Record<string, unknown>>;
  const entry = recipientsDoc.find((r) => r["recipient_identity"] === rtReader.did);
  assert.ok(entry, "reader missing from recipients file");
  assert.equal(entry!["verified"], true);
  assert.equal(entry!["proof_digest"], accepted.binding.proofDigest);

  // A pairing with a different DID/key than the accepted binding is rejected.
  await assert.rejects(
    () =>
      adminPub.addRecipient("default", {
        acceptedOffer: accepted,
        recipientDid: rtPub.did,
      }),
    /did_signer_mismatch/,
  );

  // 6. Publisher compiles the signed enrollment response for the reader.
  const responsePath = join(pubDir, "response.tnpkg");
  const compiled = await pkgPub.compileEnrolment({
    group: "default",
    recipientDid: rtReader.did,
    outPath: responsePath,
    acceptedOffer: accepted,
    ttlMs: 10 * 60_000,
  });
  assert.ok(existsSync(compiled.outPath));

  // A home that never sent the offer cannot install the response.
  const strangerDir = mkdtempSync(join(tmpdir(), "tn-jwe-stranger-"));
  const rtStranger = NodeRuntime.init(join(strangerDir, "tn.yaml"));
  const strangerReceipt = await new PkgNamespace(rtStranger).absorb(responsePath);
  assert.match(strangerReceipt.rejectedReason ?? "", /wrong_recipient|scope_mismatch/);

  // 7. Reader verifies and installs the publisher as a verified writer.
  const installed = await pkgReader.absorb(responsePath);
  assert.equal(installed.rejectedReason, undefined);
  assert.equal(installed.verifiedPublisherDid, rtPub.did);
  const verifiedPublishers = JSON.parse(
    readFileSync(join(rtReader.config.keystorePath, "trust", "verified_publishers.v1.json"), "utf8"),
  ) as Record<string, Record<string, unknown>>;
  assert.ok(verifiedPublishers["publishers"]![rtPub.did], "publisher not installed as verified");
  // The reader's private key was reused, never regenerated or exported.
  assert.deepEqual(new Uint8Array(readFileSync(myKeyPath)), myKeyBytes);
  const publisherKeystoreFiles = readFileSync(
    join(rtPub.config.keystorePath, "default.jwe.recipients"),
    "utf8",
  );
  assert.ok(
    !publisherKeystoreFiles.includes(Buffer.from(myKeyBytes).toString("base64")),
    "reader private key leaked to the publisher",
  );

  // 8. First decrypt: the next publisher seal opens under the enrolled key.
  await rtPub.emitAsync("info", "enrolled.secret", { code: "first-decrypt-ok" });
  const opened: Array<Record<string, unknown>> = [];
  for await (const e of readAsRecipientAsync(rtPub.config.logPath, rtReader.config.keystorePath, {
    group: "default",
  })) {
    if (e.envelope["event_type"] !== "enrolled.secret") continue;
    opened.push(e.plaintext["default"] as Record<string, unknown>);
  }
  assert.equal(opened.length, 1, "reader could not open the publisher's sealed entry");
  assert.deepEqual(opened[0], { code: "first-decrypt-ok" });
});

test("legacy packages without a body index need unsafeLegacySigner and stay unverified", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-legacy-"));
  const rt = NodeRuntime.init(join(dir, "tn.yaml"));
  const pkg = new PkgNamespace(rt);

  // A signed pre-body-index package: the manifest carries NO body_sha256, so
  // its signature domain simply omits the index (the historical wire form).
  const buildLegacy = (kind: Manifest["kind"]): string => {
    const manifest = newManifest({ kind, fromDid: rt.did, ceremonyId: rt.config.ceremonyId, toDid: rt.did });
    signManifest(manifest, rt.keystore.device);
    const body = { "body/package.json": new TextEncoder().encode("{}") };
    const bytes = packTnpkg([
      { name: "manifest.json", data: canonicalize(toWireDict(manifest, true)) },
      { name: "body/package.json", data: body["body/package.json"] },
    ]);
    const path = join(dir, `legacy-${String(kind)}.tnpkg`);
    writeFileSync(path, Buffer.from(bytes));
    return path;
  };
  const legacyPath = buildLegacy("admin_log_snapshot");

  // Fails closed by default.
  const rejected = await pkg.absorb(legacyPath);
  assert.match(rejected.rejectedReason ?? "", /body_digest_mismatch/);

  // Enters only through the named unsafe path, warned + audited + labeled.
  const { warnings, stop } = collectWarnings();
  try {
    const receipt = await pkg.absorb(legacyPath, { unsafeLegacySigner: true });
    assert.equal(receipt.rejectedReason, undefined);
    assert.equal(receipt.unsafeLegacyImport, true);
    await flushWarnings();
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!.message, /"operation":"legacy_package_import"/);
    assert.match(warnings[0]!.message, /"relaxations":\["legacy_signer_mismatch"\]/);
  } finally {
    stop();
  }

  // Security-sensitive kinds never enter through the legacy path.
  const legacyOffer = buildLegacy("offer");
  const offerReceipt = await pkg.absorb(legacyOffer, { unsafeLegacySigner: true });
  assert.match(offerReceipt.rejectedReason ?? "", /cannot enter through unsafeLegacySigner/);
});

test("raw JWE registration is explicit, warned, audited, and unverified", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-jwe-raw-"));
  const rt = NodeRuntime.init(join(dir, "tn.yaml"), { cipher: "jwe" });
  const admin = new AdminNamespace(rt);
  const rawDid = "did:key:z6MkRawUnverifiedReader00000000000000000000";
  const rawPub = new Uint8Array(32).fill(7);

  const { warnings, stop } = collectWarnings();
  try {
    const result = await admin.addRecipient("default", {
      recipientDid: rawDid,
      publicKey: rawPub,
      unsafeUnverified: true,
    });
    await flushWarnings();
    assert.equal(result.verified, false);

    assert.equal(warnings.length, 1, "exactly one TnSecurityWarning");
    assert.match(warnings[0]!.message, /explicit TN security weakening requested/);
    assert.match(warnings[0]!.message, /"operation":"jwe_add_recipient"/);
    assert.match(warnings[0]!.message, /"relaxations":\["unverified_key_binding"\]/);

    const audits = auditEvents(rt);
    assert.equal(audits.length, 1, "exactly one tn.security.unsafe_operation audit event");

    const doc = JSON.parse(
      readFileSync(join(rt.config.keystorePath, "default.jwe.recipients"), "utf8"),
    ) as Array<Record<string, unknown>>;
    const entry = doc.find((r) => r["recipient_identity"] === rawDid);
    assert.equal(entry?.["verified"], false, "raw registration must persist as unverified");

    // The legacy shape (no flag) still registers, with the same observability.
    await admin.addRecipient("default", {
      recipientDid: "did:key:z6MkRawLegacyShape0000000000000000000000000",
      publicKey: new Uint8Array(32).fill(9),
    });
    await flushWarnings();
    assert.equal(warnings.length, 2, "legacy raw registration warns too");
    assert.equal(auditEvents(rt).length, 2);
  } finally {
    stop();
  }
});
