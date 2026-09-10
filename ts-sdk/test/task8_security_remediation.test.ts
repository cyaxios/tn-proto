import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { x25519 } from "@noble/curves/ed25519";

import { AdminNamespace } from "../src/admin/index.js";
import {
  createHibeReaderProof,
  formatTrustTimestamp,
  keyBindingProofDigest,
  sha256Digest,
  signKeyBindingProof,
  TrustError,
  type AcceptedOffer,
} from "../src/core/trust.js";
import { PkgNamespace } from "../src/pkg/index.js";
import {
  assertHibeSealAuthorized,
  createHibeGroup,
  loadHibeGroup,
  loadPinnedHibeAuthority,
} from "../src/runtime/hibe_group.js";
import {
  UNSAFE_OPERATION_EVENT_TYPE,
} from "../src/runtime/enrollment.js";
import {
  createJweGroup,
  jweAddRecipient,
  jweRotateGroup,
} from "../src/runtime/jwe_group.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { readTnpkgVerified } from "../src/tnpkg_io.js";

function runtime(prefix: string, cipher?: "btn" | "hibe" | "jwe"): NodeRuntime {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return NodeRuntime.init(join(dir, "tn.yaml"), cipher === undefined ? {} : { cipher });
}

function reason(err: unknown): string | null {
  return err instanceof TrustError ? err.reason : null;
}

test("JWE registration and response compilation reject a caller-forged AcceptedOffer", async () => {
  const publisher = runtime("tn-ts8-forged-publisher-", "jwe");
  const reader = runtime("tn-ts8-forged-reader-");
  const publicKey = new Uint8Array(32).fill(9);
  const publicKeySha256 = sha256Digest(publicKey);
  const forged: AcceptedOffer = {
    binding: {
      principal: {
        did: reader.did,
        purpose: "jwe-reader",
        audienceDid: publisher.did,
        ceremonyId: publisher.config.ceremonyId,
        group: "default",
        proofDigest: `sha256:${"1".repeat(64)}`,
        issuedAt: "2026-07-12T00:00:00Z",
        expiresAt: "2099-07-12T00:00:00Z",
      },
      publicKey,
      publicKeySha256,
      proofDigest: `sha256:${"1".repeat(64)}`,
      challengeDigest: null,
    },
    offerDigest: `sha256:${"2".repeat(64)}`,
    artifactDigest: `sha256:${"3".repeat(64)}`,
  };

  await assert.rejects(
    () => new AdminNamespace(publisher).addRecipient("default", { acceptedOffer: forged }),
    (err: unknown) => reason(err) === "untrusted_principal",
  );
  await assert.rejects(
    () =>
      new PkgNamespace(publisher).compileEnrolment({
        group: "default",
        recipientDid: reader.did,
        outPath: join(publisher.config.yamlDir, "forged-response.tnpkg"),
        acceptedOffer: forged,
        ttlMs: 60_000,
      }),
    (err: unknown) => reason(err) === "untrusted_principal",
  );
});

test("the main PkgNamespace absorb transparently installs a recipient-sealed HIBE grant", async () => {
  const authority = runtime("tn-ts8-sealed-authority-");
  const reader = runtime("tn-ts8-sealed-reader-");
  const admin = new AdminNamespace(authority);
  await admin.ensureGroup("cases", { cipher: "hibe" });
  const challenge = await admin.issueHibeReaderChallenge("cases", reader.did, 60_000);
  const proof = await createHibeReaderProof(challenge, reader.keystore.device, {
    expectedAuthorityDid: authority.did,
  });
  const outPath = join(authority.config.yamlDir, "sealed-grant.tnpkg");
  await admin.grantReader("cases", { readerDid: reader.did, proof, outPath });

  const receipt = await new PkgNamespace(reader).absorb(outPath);
  assert.equal(receipt.rejectedReason, undefined);
  assert.equal(receipt.acceptedCount, 3);
  assert.equal(existsSync(join(reader.config.keystorePath, "cases.hibe.sk")), true);
  assert.equal(existsSync(join(reader.config.keystorePath, "encrypted.bin")), false);
});

test("HIBE reader proofs require the caller's expected authority DID", async () => {
  const authority = runtime("tn-ts8-proof-authority-");
  const impostor = runtime("tn-ts8-proof-impostor-");
  const reader = runtime("tn-ts8-proof-reader-");
  const admin = new AdminNamespace(authority);
  await admin.ensureGroup("cases", { cipher: "hibe" });
  const challenge = await admin.issueHibeReaderChallenge("cases", reader.did, 60_000);

  await assert.rejects(
    () =>
      createHibeReaderProof(challenge, reader.keystore.device, {
        expectedAuthorityDid: impostor.did,
      }),
    (err: unknown) => reason(err) === "did_signer_mismatch",
  );
});

test("HIBE grants reject proofless safe admission, null-challenge proofs, and challenge reuse", async () => {
  const authority = runtime("tn-ts8-grant-authority-");
  const reader = runtime("tn-ts8-grant-reader-");
  const admin = new AdminNamespace(authority);
  await admin.ensureGroup("cases", { cipher: "hibe" });

  await assert.rejects(
    () =>
      admin.grantReader("cases", {
        readerDid: reader.did,
        outPath: join(authority.config.yamlDir, "proofless.tnpkg"),
      }),
    (err: unknown) => reason(err) === "untrusted_principal",
  );

  const now = Date.now() * 1000;
  const nullChallengeProof = signKeyBindingProof(
    {
      version: 1,
      purpose: "hibe-reader",
      subject_did: reader.did,
      audience_did: authority.did,
      ceremony_id: authority.config.ceremonyId,
      group: "cases",
      issued_at: formatTrustTimestamp(now),
      expires_at: formatTrustTimestamp(now + 60_000_000),
      nonce_b64: Buffer.alloc(32, 7).toString("base64"),
      binding: {
        algorithm: "Ed25519-did-key",
        delivery: "recipient-seal-v1",
        challenge_digest: null,
      },
      signature_b64: "",
    },
    reader.keystore.device,
  );
  await assert.rejects(
    () =>
      admin.grantReader("cases", {
        readerDid: reader.did,
        proof: nullChallengeProof,
        outPath: join(authority.config.yamlDir, "null-challenge.tnpkg"),
      }),
    (err: unknown) => reason(err) === "challenge_missing",
  );

  const challenge = await admin.issueHibeReaderChallenge("cases", reader.did, 60_000);
  const proof = await createHibeReaderProof(challenge, reader.keystore.device, {
    expectedAuthorityDid: authority.did,
  });
  await admin.grantReader("cases", {
    readerDid: reader.did,
    proof,
    outPath: join(authority.config.yamlDir, "first.tnpkg"),
  });
  const replayVariant = await createHibeReaderProof(challenge, reader.keystore.device, {
    expectedAuthorityDid: authority.did,
  });
  await assert.rejects(
    () =>
      admin.grantReader("cases", {
        readerDid: reader.did,
        proof: replayVariant,
        outPath: join(authority.config.yamlDir, "replay.tnpkg"),
      }),
    (err: unknown) => reason(err) === "replay_conflict" || reason(err) === "challenge_replayed",
  );
});

test("unsafe HIBE and JWE admission still requires a complete real Ed25519 did:key", async () => {
  const authority = runtime("tn-ts8-real-did-hibe-");
  const hibeAdmin = new AdminNamespace(authority);
  await hibeAdmin.ensureGroup("cases", { cipher: "hibe" });
  await assert.rejects(
    () =>
      hibeAdmin.grantReader("cases", {
        readerDid: "did:key:z6Mk-not-a-real-key",
        unsafePlaintext: true,
        outPath: join(authority.config.yamlDir, "unsafe.tnpkg"),
      }),
    (err: unknown) => reason(err) === "did_invalid",
  );

  const jwe = runtime("tn-ts8-real-did-jwe-", "jwe");
  await assert.rejects(
    () =>
      new AdminNamespace(jwe).addRecipient("default", {
        recipientDid: "did:key:z6Mk-not-a-real-key",
        publicKey: new Uint8Array(32).fill(3),
        unsafeUnverified: true,
      }),
    (err: unknown) => reason(err) === "did_invalid",
  );
});

test("a pinned HIBE authority supports same-epoch renewal and gates expiry and material drift", async () => {
  const authority = runtime("tn-ts8-pin-authority-");
  const writer = runtime("tn-ts8-pin-writer-");
  const authAdmin = new AdminNamespace(authority);
  const writerAdmin = new AdminNamespace(writer);
  await authAdmin.ensureGroup("cases", { cipher: "hibe" });
  const material = loadHibeGroup(authority.config.keystorePath, "cases");
  assert.ok(material);

  const first = await authAdmin.issueHibeAuthorityAssertion("cases", 60_000, {
    audienceDid: writer.did,
  });
  await writerAdmin.installHibeAuthorityAssertion({
    group: "cases",
    mpk: material.mpk,
    assertion: first,
    expectedAuthorityDid: authority.did,
  });
  const renewed = await authAdmin.issueHibeAuthorityAssertion("cases", 120_000, {
    audienceDid: writer.did,
  });
  await writerAdmin.installHibeAuthorityAssertion({
    group: "cases",
    mpk: material.mpk,
    assertion: renewed,
    expectedAuthorityDid: authority.did,
  });
  const pinned = loadPinnedHibeAuthority(writer.config.keystorePath, "cases");
  assert.equal(pinned?.assertionDigest, keyBindingProofDigest(renewed));
  assert.equal(pinned?.expiresAt, renewed.expires_at);
  const writerMaterial = loadHibeGroup(writer.config.keystorePath, "cases");
  assert.ok(writerMaterial);
  assert.doesNotThrow(() =>
    assertHibeSealAuthorized(
      writer.config.keystorePath,
      "cases",
      writerMaterial,
      writer.did,
      renewed.issued_at,
    ),
  );
  assert.throws(
    () =>
      assertHibeSealAuthorized(
        writer.config.keystorePath,
        "cases",
        writerMaterial,
        writer.did,
        renewed.expires_at,
      ),
    (err: unknown) => reason(err) === "statement_expired",
  );
  writeFileSync(join(writer.config.keystorePath, "cases.hibe.idpath"), "tampered/path", "utf8");
  const drifted = loadHibeGroup(writer.config.keystorePath, "cases");
  assert.ok(drifted);
  assert.throws(
    () =>
      assertHibeSealAuthorized(
        writer.config.keystorePath,
        "cases",
        drifted,
        writer.did,
        renewed.issued_at,
      ),
    (err: unknown) => reason(err) === "binding_invalid",
  );
});

test("reader-package APIs are BTN-only and never export a publisher self capability", async () => {
  const reader = runtime("tn-ts8-package-reader-");
  const hibe = runtime("tn-ts8-package-hibe-", "hibe");
  await assert.rejects(
    () =>
      new PkgNamespace(hibe).bundleForRecipient({
        recipientDid: reader.did,
        outPath: join(hibe.config.yamlDir, "hibe-reader.tnpkg"),
        groups: ["default"],
      }),
    /BTN-only/,
  );

  const jwe = runtime("tn-ts8-package-jwe-", "jwe");
  await assert.rejects(
    () =>
      new PkgNamespace(jwe).bundleForRecipient({
        recipientDid: reader.did,
        outPath: join(jwe.config.yamlDir, "jwe-reader.tnpkg"),
        groups: ["default"],
      }),
    /JWE enrollment|BTN-only/,
  );
});

test("concurrent unsafe operations each emit their own warning and audit attempt", async () => {
  const rt = runtime("tn-ts8-audit-");
  const warnings: string[] = [];
  const originalWarning = process.emitWarning;
  const originalEmitAsync = rt.emitAsync.bind(rt);
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  process.emitWarning = ((warning: string | Error) => {
    warnings.push(String(warning));
  }) as typeof process.emitWarning;
  let auditAttempts = 0;
  rt.emitAsync = (async (...args: Parameters<NodeRuntime["emitAsync"]>) => {
    if (args[1] === UNSAFE_OPERATION_EVENT_TYPE) {
      auditAttempts += 1;
      await blocked;
      return { eventId: "audit", rowHash: "0".repeat(64) as never, sequence: auditAttempts };
    }
    return originalEmitAsync(...args);
  }) as NodeRuntime["emitAsync"];
  try {
    const first = rt.recordUnsafeOperation({
      operation: "jwe_add_recipient",
      relaxations: ["unverified_key_binding"],
      group: "a",
      subject_did: rt.did,
      artifact_digest: null,
    });
    const second = rt.recordUnsafeOperation({
      operation: "jwe_add_recipient",
      relaxations: ["unverified_key_binding"],
      group: "b",
      subject_did: rt.did,
      artifact_digest: null,
    });
    assert.equal(warnings.length, 2);
    assert.equal(auditAttempts, 2);
    release();
    await Promise.all([first, second]);
  } finally {
    process.emitWarning = originalWarning;
    rt.emitAsync = originalEmitAsync;
  }
});

test("JWE rotation retains verified recipients only as an inactive reenrollment plan", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-ts8-jwe-rotation-"));
  const owner = runtime("tn-ts8-jwe-owner-");
  const reader = runtime("tn-ts8-jwe-plan-reader-");
  createJweGroup(dir, "cases", owner.did);
  jweAddRecipient(dir, "cases", reader.did, new Uint8Array(32).fill(4), {
    verified: true,
    proof_digest: `sha256:${"4".repeat(64)}`,
    public_key_sha256: `sha256:${"5".repeat(64)}`,
  });

  jweRotateGroup(dir, "cases", owner.did, "20260712T000000Z", 7);
  const planPath = join(dir, "cases.jwe.reenrollment.v1.json");
  assert.equal(existsSync(planPath), true);
  const plan = JSON.parse(readFileSync(planPath, "utf8")) as Record<string, unknown>;
  assert.equal(plan["version"], 1);
  assert.equal(plan["group"], "cases");
  assert.equal(plan["previous_epoch"], 7);
  assert.deepEqual(plan["readers"], [
    {
      reader_did: reader.did,
      public_key_sha256: `sha256:${"5".repeat(64)}`,
      proof_digest: `sha256:${"4".repeat(64)}`,
    },
  ]);
});

test("AdminNamespace.addRecipient and public NodeRuntime.grantReader share the challenged grant gate", async () => {
  const authority = runtime("tn-ts8-unified-authority-");
  const reader = runtime("tn-ts8-unified-reader-");
  const admin = new AdminNamespace(authority);
  await admin.ensureGroup("cases", { cipher: "hibe" });

  await assert.rejects(
    () =>
      admin.addRecipient("cases", {
        recipientDid: reader.did,
        outKitPath: join(authority.config.yamlDir, "generic-proofless.tnpkg"),
      }),
    (err: unknown) => reason(err) === "untrusted_principal",
  );
  await assert.rejects(
    async () =>
      await authority.grantReader("cases", {
        readerDid: reader.did,
        outPath: join(authority.config.yamlDir, "runtime-proofless.tnpkg"),
      }),
    (err: unknown) => reason(err) === "untrusted_principal",
  );

  const challenge = await admin.issueHibeReaderChallenge("cases", reader.did, 60_000);
  const proof = await createHibeReaderProof(challenge, reader.keystore.device, {
    expectedAuthorityDid: authority.did,
  });
  const added = await admin.addRecipient("cases", {
    recipientDid: reader.did,
    outKitPath: join(authority.config.yamlDir, "generic-verified.tnpkg"),
    proof,
  });
  assert.equal(added.verified, true);
  assert.equal(added.sealed, true);
});

test("PkgNamespace.export kit mints a fresh BTN reader capability instead of exporting self", async () => {
  const publisher = runtime("tn-ts8-btn-export-publisher-");
  const reader = runtime("tn-ts8-btn-export-reader-");
  const selfKit = new Uint8Array(
    readFileSync(join(publisher.config.keystorePath, "default.btn.mykit")),
  );
  const outPath = join(publisher.config.yamlDir, "reader.tnpkg");
  await new PkgNamespace(publisher).export(
    { kit: { recipientDid: reader.did, outPath } },
    outPath,
  );
  const parsed = readTnpkgVerified(outPath);
  assert.equal(parsed.manifest.toDid, reader.did);
  const bodyKit = parsed.body.get("body/default.btn.mykit");
  assert.ok(bodyKit);
  assert.notDeepEqual(bodyKit, selfKit);
});

test("synchronous absorb rejects a sealed kit instead of installing encrypted.bin", async () => {
  const authority = runtime("tn-ts8-sync-absorb-authority-");
  const reader = runtime("tn-ts8-sync-absorb-reader-");
  const admin = new AdminNamespace(authority);
  await admin.ensureGroup("cases", { cipher: "hibe" });
  const challenge = await admin.issueHibeReaderChallenge("cases", reader.did, 60_000);
  const proof = await createHibeReaderProof(challenge, reader.keystore.device, {
    expectedAuthorityDid: authority.did,
  });
  const outPath = join(authority.config.yamlDir, "sealed-sync.tnpkg");
  await admin.grantReader("cases", { readerDid: reader.did, proof, outPath });

  const receipt = reader.absorbPkg(outPath);
  assert.match(receipt.rejectedReason ?? "", /absorbPkgAsync|recipient-sealed/);
  assert.equal(receipt.acceptedCount, 0);
  assert.equal(existsSync(join(reader.config.keystorePath, "encrypted.bin")), false);
});

test("failed HIBE material promotion cannot advance the durable authority pin", async () => {
  const authority = runtime("tn-ts8-pin-atomic-authority-");
  const writer = runtime("tn-ts8-pin-atomic-writer-");
  const authAdmin = new AdminNamespace(authority);
  const writerAdmin = new AdminNamespace(writer);
  await authAdmin.ensureGroup("cases", { cipher: "hibe" });
  const firstMat = loadHibeGroup(authority.config.keystorePath, "cases");
  assert.ok(firstMat);
  const first = await authAdmin.issueHibeAuthorityAssertion("cases", 60_000, {
    audienceDid: writer.did,
  });
  await writerAdmin.installHibeAuthorityAssertion({
    group: "cases",
    mpk: firstMat.mpk,
    assertion: first,
    expectedAuthorityDid: authority.did,
  });
  await authAdmin.rotateHibePathWithAssertion("cases", "self~r1");
  const update = await authAdmin.issueHibeAuthorityAssertion("cases", 60_000, {
    audienceDid: writer.did,
  });

  const mpkPath = join(writer.config.keystorePath, "cases.hibe.mpk");
  const backup = `${mpkPath}.test-backup`;
  renameSync(mpkPath, backup);
  mkdirSync(mpkPath);
  await assert.rejects(() =>
    writerAdmin.installHibeAuthorityAssertion({
      group: "cases",
      mpk: firstMat.mpk,
      assertion: update,
      expectedAuthorityDid: authority.did,
    }),
  );
  assert.equal(loadPinnedHibeAuthority(writer.config.keystorePath, "cases")?.pathEpoch, 0);
  rmSync(mpkPath, { recursive: true, force: true });
  renameSync(backup, mpkPath);
});

test("NodeRuntime emit refuses raw external HIBE MPK material without an authenticated pin", () => {
  const authority = runtime("tn-ts8-raw-mpk-authority-", "hibe");
  const writer = runtime("tn-ts8-raw-mpk-writer-");
  const authorityMaterial = loadHibeGroup(authority.config.keystorePath, "default");
  assert.ok(authorityMaterial);
  const raw = createHibeGroup(writer.config.keystorePath, "cases", {
    idPath: authorityMaterial.idPath,
    authorityMpk: authorityMaterial.mpk,
  });
  writer.config.groups.set("cases", {
    name: "cases",
    cipher: "hibe",
    policy: "private",
    recipients: [],
    indexEpoch: 0,
  });
  writer.config.fieldToGroups.set("secret", ["cases"]);
  writer.keystore.groups.set("cases", { kits: [], hibe: raw, hibeKits: [] });

  assert.throws(
    () => writer.emit("info", "raw.mpk", { secret: "must-not-seal" }),
    (err: unknown) => reason(err) === "untrusted_principal",
  );
});

test("HIBE revoke is honest for ancestor grants and seals survivor reissues with an external assertion", async () => {
  const authority = runtime("tn-ts8-revoke-authority-");
  const ancestor = runtime("tn-ts8-revoke-ancestor-");
  const admin = new AdminNamespace(authority);
  await admin.ensureGroup("cases", { cipher: "hibe" });
  await admin.rotateHibePathWithAssertion("cases", "org/fraud");
  const ancestorChallenge = await admin.issueHibeReaderChallenge("cases", ancestor.did, 60_000);
  const ancestorProof = await createHibeReaderProof(ancestorChallenge, ancestor.keystore.device, {
    expectedAuthorityDid: authority.did,
  });
  await admin.grantReader("cases", {
    readerDid: ancestor.did,
    proof: ancestorProof,
    idPath: "org",
    allowSubauthority: true,
    outPath: join(authority.config.yamlDir, "ancestor.tnpkg"),
  });
  const before = loadHibeGroup(authority.config.keystorePath, "cases")!.idPath;
  const ancestorResult = await admin.revokeReader("cases", ancestor.did);
  assert.equal(ancestorResult.revoked, false);
  assert.equal(ancestorResult.newPath, before);

  const survivor = runtime("tn-ts8-revoke-survivor-");
  const revoked = runtime("tn-ts8-revoke-target-");
  const writer = runtime("tn-ts8-revoke-writer-");
  for (const peer of [survivor, revoked]) {
    const challenge = await admin.issueHibeReaderChallenge("cases", peer.did, 60_000);
    const proof = await createHibeReaderProof(challenge, peer.keystore.device, {
      expectedAuthorityDid: authority.did,
    });
    await admin.grantReader("cases", {
      readerDid: peer.did,
      proof,
      outPath: join(authority.config.yamlDir, `${peer.did.slice(-8)}.tnpkg`),
    });
  }
  const result = await admin.revokeReader("cases", revoked.did, {
    outDir: join(authority.config.yamlDir, "regrant"),
    audienceDid: writer.did,
  });
  assert.equal(result.revoked, true);
  assert.ok((result.pathEpoch ?? 0) > 0);
  assert.equal(result.authorityAssertion?.audience_did, writer.did);
  assert.equal(result.kitPaths.length, 2); // ancestor + exact survivor are both retained
  for (const kit of result.kitPaths) {
    const parsed = readTnpkgVerified(kit);
    const state = parsed.manifest.state as Record<string, unknown>;
    assert.ok(state["body_encryption"], `survivor kit ${kit} was plaintext`);
  }
});

function runNodeScript(script: string): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "--eval", script],
      { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    child.once("error", reject);
    child.once("exit", (code) => resolve({ stdout, stderr, code }));
  });
}

test("concurrent first JWE reader-key creation waits for the durable key lock and reuses the winner", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-ts8-jwe-key-lock-"));
  const keyPath = join(dir, "cases.jwe.mykey");
  const lockPath = `${keyPath}.lock`;
  const readyPath = join(dir, "child.ready");
  const returnedPath = join(dir, "child.returned");
  writeFileSync(lockPath, JSON.stringify({ pid: process.pid }) + "\n", "utf8");
  const moduleUrl = new URL("../src/runtime/enrollment.ts", import.meta.url).href;
  const script = `
    import { writeFileSync } from "node:fs";
    import { ensureJweReaderKey } from ${JSON.stringify(moduleUrl)};
    writeFileSync(${JSON.stringify(readyPath)}, "ready");
    const pub = ensureJweReaderKey(${JSON.stringify(dir)}, "cases");
    writeFileSync(${JSON.stringify(returnedPath)}, "returned");
    process.stdout.write(Buffer.from(pub).toString("base64"));
  `;
  const child = runNodeScript(script);
  const readyDeadline = Date.now() + 5_000;
  while (!existsSync(readyPath) && Date.now() < readyDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(existsSync(readyPath), true, "child never reached reader-key creation");
  const blockedDeadline = Date.now() + 300;
  while (!existsSync(returnedPath) && Date.now() < blockedDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const returnedWhileLocked = existsSync(returnedPath);
  const winner = new Uint8Array(32).fill(11);
  writeFileSync(keyPath, Buffer.from(winner), { mode: 0o600 });
  unlinkSync(lockPath);
  const result = await child;
  assert.equal(returnedWhileLocked, false, "reader-key creation ignored the durable lock");
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, Buffer.from(x25519.getPublicKey(winner)).toString("base64"));
  assert.deepEqual(new Uint8Array(readFileSync(keyPath)), winner);
});
