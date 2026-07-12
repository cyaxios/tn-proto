// HIBE trusted-authority lifecycle: assertion issuance, external-writer
// pin/install, monotonic path epochs, rollback/conflict rejection, scoped
// reader challenge/proof grants, fail-closed sealed delivery, explicit
// unsafe plaintext, and the ancestor/subauthority opt-in.
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { AdminNamespace } from "../src/admin/index.js";
import { sha256Digest, signKeyBindingProof, TrustError, createHibeReaderProof } from "../src/core/trust.js";
import { readTnpkgVerified } from "../src/tnpkg_io.js";
import {
  hibeAuthorityEpoch,
  hibeDecrypt,
  hibeEncrypt,
  loadHibeGroup,
  loadPinnedHibeAuthority,
} from "../src/runtime/hibe_group.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import { UNSAFE_OPERATION_EVENT_TYPE } from "../src/runtime/enrollment.js";

const GROUP = "cases";

function newAuthority(): { rt: NodeRuntime; admin: AdminNamespace } {
  const dir = mkdtempSync(join(tmpdir(), "tn-hibe-auth-"));
  const rt = NodeRuntime.init(join(dir, "tn.yaml"));
  const admin = new AdminNamespace(rt);
  return { rt, admin };
}

function newWriter(): { rt: NodeRuntime; admin: AdminNamespace } {
  const dir = mkdtempSync(join(tmpdir(), "tn-hibe-writer-"));
  const rt = NodeRuntime.init(join(dir, "tn.yaml"));
  return { rt, admin: new AdminNamespace(rt) };
}

function reasonOfAsync(promise: Promise<unknown>): Promise<string> {
  return promise.then(
    () => assert.fail("expected a TrustError"),
    (err: unknown) => {
      assert.ok(err instanceof TrustError, `expected TrustError, got ${String(err)}`);
      return err.reason;
    },
  );
}

function auditOperations(rt: NodeRuntime): string[] {
  const out: string[] = [];
  const stack = [rt.config.yamlDir];
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
        if (statSync(full).isDirectory()) {
          stack.push(full);
          continue;
        }
      } catch {
        continue;
      }
      if (!name.endsWith(".ndjson") || !existsSync(full)) continue;
      for (const line of readFileSync(full, "utf8").split(/\r?\n/)) {
        if (!line || !line.includes(UNSAFE_OPERATION_EVENT_TYPE)) continue;
        out.push(line);
      }
    }
  }
  return out;
}

test("authority assertions pin, update monotonically, and gate external seals", async () => {
  const { rt: rtAuth, admin: adminAuth } = newAuthority();
  await adminAuth.ensureGroup(GROUP, { cipher: "hibe" });
  const authorityMat = loadHibeGroup(rtAuth.config.keystorePath, GROUP);
  assert.ok(authorityMat, "authority hibe group material missing");

  const assertion = await adminAuth.issueHibeAuthorityAssertion(GROUP, 10 * 60_000);
  assert.equal(assertion.purpose, "hibe-authority");
  assert.equal(assertion.subject_did, rtAuth.did);
  assert.equal(assertion.binding["mpk_sha256"], sha256Digest(authorityMat.mpk));
  assert.equal(assertion.binding["id_path"], authorityMat.idPath);
  assert.equal(assertion.binding["path_epoch"], 0);
  assert.equal(hibeAuthorityEpoch(authorityMat), 0);

  // The external writer cannot seal before pinning the assertion.
  const { rt: rtWriter, admin: adminWriter } = newWriter();
  assert.equal(loadHibeGroup(rtWriter.config.keystorePath, GROUP), null);

  // Assertions are audience-addressed: reissue for this writer.
  const forWriter = await adminAuth.issueHibeAuthorityAssertion(GROUP, 10 * 60_000, {
    audienceDid: rtWriter.did,
  });
  assert.equal(forWriter.audience_did, rtWriter.did);

  // MPK substitution fails closed before any state is written.
  assert.equal(
    await reasonOfAsync(
      adminWriter.installHibeAuthorityAssertion({
        group: GROUP,
        mpk: new Uint8Array(authorityMat.mpk.length).fill(1),
        assertion: forWriter,
        expectedAuthorityDid: rtAuth.did,
      }),
    ),
    "binding_invalid",
  );
  // A different expected authority DID is a signer mismatch.
  assert.equal(
    await reasonOfAsync(
      adminWriter.installHibeAuthorityAssertion({
        group: GROUP,
        mpk: authorityMat.mpk,
        assertion: forWriter,
        expectedAuthorityDid: rtWriter.did,
      }),
    ),
    "did_signer_mismatch",
  );
  assert.equal(loadPinnedHibeAuthority(rtWriter.config.keystorePath, GROUP), null);

  await adminWriter.installHibeAuthorityAssertion({
    group: GROUP,
    mpk: authorityMat.mpk,
    assertion: forWriter,
    expectedAuthorityDid: rtAuth.did,
  });
  const pinned = loadPinnedHibeAuthority(rtWriter.config.keystorePath, GROUP);
  assert.equal(pinned?.authorityDid, rtAuth.did);
  assert.equal(pinned?.pathEpoch, 0);
  assert.equal(pinned?.mpkSha256, sha256Digest(authorityMat.mpk));

  // The pinned writer can now seal; the authority can open what it sealed.
  const writerMat = loadHibeGroup(rtWriter.config.keystorePath, GROUP);
  assert.ok(writerMat, "writer hibe material missing after install");
  assert.equal(writerMat!.idPath, authorityMat.idPath);
  const sealed = hibeEncrypt(writerMat!, new TextEncoder().encode("external-writer-note"));
  assert.deepEqual(
    hibeDecrypt(loadHibeGroup(rtAuth.config.keystorePath, GROUP)!, sealed),
    new TextEncoder().encode("external-writer-note"),
  );

  // Path rotation returns the next-epoch signed assertion.
  const rotated = await adminAuth.rotateHibePathWithAssertion(GROUP, "org/fraud-2026");
  assert.equal(rotated.group, GROUP);
  assert.equal(rotated.idPath, "org/fraud-2026");
  assert.equal(rotated.pathEpoch, 1);
  assert.equal(rotated.assertion.binding["path_epoch"], 1);

  const rotatedForWriter = await adminAuth.issueHibeAuthorityAssertion(GROUP, 10 * 60_000, {
    audienceDid: rtWriter.did,
  });
  assert.equal(rotatedForWriter.binding["path_epoch"], 1);
  await adminWriter.installHibeAuthorityAssertion({
    group: GROUP,
    mpk: authorityMat.mpk,
    assertion: rotatedForWriter,
    expectedAuthorityDid: rtAuth.did,
  });
  const updated = loadPinnedHibeAuthority(rtWriter.config.keystorePath, GROUP);
  assert.equal(updated?.pathEpoch, 1);
  assert.equal(updated?.idPath, "org/fraud-2026");
  assert.equal(
    readFileSync(join(rtWriter.config.keystorePath, `${GROUP}.hibe.idpath`), "utf8"),
    "org/fraud-2026",
  );

  // Replaying the older epoch is a rollback.
  assert.equal(
    await reasonOfAsync(
      adminWriter.installHibeAuthorityAssertion({
        group: GROUP,
        mpk: authorityMat.mpk,
        assertion: forWriter,
        expectedAuthorityDid: rtAuth.did,
      }),
    ),
    "epoch_rollback",
  );

  // A conflicting MPK at the pinned epoch is a conflict, even when the
  // assertion is authentically signed and self-consistent. Mint a second
  // authority group so real, different MPK bytes exist to bind.
  await adminAuth.ensureGroup("cases2", { cipher: "hibe" });
  const otherMat = loadHibeGroup(rtAuth.config.keystorePath, "cases2")!;
  const conflicting = signKeyBindingProof(
    {
      ...rotatedForWriter,
      binding: { ...rotatedForWriter.binding, mpk_sha256: sha256Digest(otherMat.mpk) },
      signature_b64: "",
    },
    rtAuth.keystore.device,
  );
  assert.equal(
    await reasonOfAsync(
      adminWriter.installHibeAuthorityAssertion({
        group: GROUP,
        mpk: otherMat.mpk,
        assertion: conflicting,
        expectedAuthorityDid: rtAuth.did,
      }),
    ),
    "epoch_conflict",
  );

  // An expired assertion cannot authorize an install.
  const staleForWriter = signKeyBindingProof(
    {
      ...rotatedForWriter,
      issued_at: "2020-01-01T00:00:00Z",
      expires_at: "2020-01-01T00:10:00Z",
      signature_b64: "",
    },
    rtAuth.keystore.device,
  );
  assert.equal(
    await reasonOfAsync(
      adminWriter.installHibeAuthorityAssertion({
        group: GROUP,
        mpk: authorityMat.mpk,
        assertion: staleForWriter,
        expectedAuthorityDid: rtAuth.did,
      }),
    ),
    "statement_expired",
  );
});

test("reader grants require proofs, seal by default, and gate ancestor paths", async () => {
  const { rt: rtAuth, admin: adminAuth } = newAuthority();
  await adminAuth.ensureGroup(GROUP, { cipher: "hibe" });
  // Deepen the sealing path so an ancestor exists.
  await adminAuth.rotateHibePathWithAssertion(GROUP, "org/fraud");

  const readerDir = mkdtempSync(join(tmpdir(), "tn-hibe-reader-"));
  const rtReader = NodeRuntime.init(join(readerDir, "tn.yaml"));

  // Scoped challenge -> reader proof -> verified sealed grant.
  const challenge = await adminAuth.issueHibeReaderChallenge(GROUP, rtReader.did, 5 * 60_000);
  assert.equal(challenge.publisher_did, rtAuth.did);
  assert.equal(challenge.group, GROUP);
  const proof = await createHibeReaderProof(challenge, rtReader.keystore.device);
  assert.equal(proof.purpose, "hibe-reader");
  assert.equal(proof.binding["delivery"], "recipient-seal-v1");

  const kitPath = join(readerDir, "grant.tnpkg");
  const granted = await adminAuth.grantReader(GROUP, {
    readerDid: rtReader.did,
    outPath: kitPath,
    proof,
  });
  assert.equal(granted.verified, true);
  assert.ok(granted.proofDigest?.startsWith("sha256:"));
  assert.equal(granted.sealed, true);

  // Sealed delivery: the kit body is recipient-sealed, not plaintext.
  const sealedKit = readTnpkgVerified(kitPath);
  const bodyEncryption = (sealedKit.manifest.state ?? {}) as Record<string, unknown>;
  assert.ok(bodyEncryption["body_encryption"], "grant kit must be recipient-sealed");

  // The reader absorbs (unseals) and can read a sealed entry end to end.
  await rtReader.absorbPkgAsync(kitPath);
  rtAuth.emit("info", "case.note", { secret: "for-court" });
  const authMat = loadHibeGroup(rtAuth.config.keystorePath, GROUP)!;
  const sealedNote = hibeEncrypt(authMat, new TextEncoder().encode("direct-grant-check"));
  const readerMat = loadHibeGroup(rtReader.config.keystorePath, GROUP);
  assert.ok(readerMat?.sk, "reader kit did not install a delegated key");
  assert.deepEqual(hibeDecrypt(readerMat!, sealedNote), new TextEncoder().encode("direct-grant-check"));

  // The grant registry retains the verified proof metadata.
  const grants = JSON.parse(
    readFileSync(join(rtAuth.config.keystorePath, `${GROUP}.hibe.grants`), "utf8"),
  ) as Array<Record<string, unknown>>;
  const grantEntry = grants.find((g) => g["reader_did"] === rtReader.did);
  assert.equal(grantEntry?.["verified"], true);
  assert.equal(grantEntry?.["proof_digest"], granted.proofDigest);

  // A proof for the wrong scope is rejected before any kit is minted.
  const otherReaderDir = mkdtempSync(join(tmpdir(), "tn-hibe-other-"));
  const rtOther = NodeRuntime.init(join(otherReaderDir, "tn.yaml"));
  const otherChallenge = await adminAuth.issueHibeReaderChallenge(GROUP, rtOther.did, 5 * 60_000);
  const otherProof = await createHibeReaderProof(otherChallenge, rtOther.keystore.device);
  assert.equal(
    await reasonOfAsync(
      adminAuth.grantReader(GROUP, {
        readerDid: rtReader.did,
        outPath: join(readerDir, "mismatch.tnpkg"),
        proof: otherProof,
      }),
    ),
    "did_signer_mismatch",
  );

  // Ancestor grants are an explicit subauthority decision.
  const ancestorProofDenied = await createHibeReaderProof(
    await adminAuth.issueHibeReaderChallenge(GROUP, rtReader.did, 5 * 60_000),
    rtReader.keystore.device,
  );
  await assert.rejects(
    () =>
      adminAuth.grantReader(GROUP, {
        readerDid: rtReader.did,
        idPath: "org",
        outPath: join(readerDir, "ancestor-denied.tnpkg"),
        proof: ancestorProofDenied,
      }),
    /allowSubauthority/,
  );
  const ancestorProof = await createHibeReaderProof(
    await adminAuth.issueHibeReaderChallenge(GROUP, rtReader.did, 5 * 60_000),
    rtReader.keystore.device,
  );
  const subtree = await adminAuth.grantReader(GROUP, {
    readerDid: rtReader.did,
    idPath: "org",
    outPath: join(readerDir, "ancestor.tnpkg"),
    allowSubauthority: true,
    proof: ancestorProof,
  });
  assert.equal(subtree.subtreeDelegation, true);
  assert.equal(subtree.idPath, "org");
});

test("proof-less and plaintext grants stay possible but warned and audited", async () => {
  const { rt: rtAuth, admin: adminAuth } = newAuthority();
  await adminAuth.ensureGroup(GROUP, { cipher: "hibe" });

  const warnings: Error[] = [];
  const handler = (warning: Error): void => {
    if (warning.name === "TnSecurityWarning") warnings.push(warning);
  };
  process.on("warning", handler);
  try {
    const readerDir = mkdtempSync(join(tmpdir(), "tn-hibe-unsafe-"));
    const rtReader = NodeRuntime.init(join(readerDir, "tn.yaml"));

    // Compatibility: a proof-less grant to a real DID still seals, but is
    // recorded as an unverified key binding.
    const compat = await adminAuth.grantReader(GROUP, {
      readerDid: rtReader.did,
      outPath: join(readerDir, "compat.tnpkg"),
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(compat.verified, false);
    assert.equal(compat.sealed, true);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!.message, /"operation":"hibe_grant"/);
    assert.match(warnings[0]!.message, /"relaxations":\["unverified_key_binding"\]/);

    // Explicit plaintext delivery is labeled as unsafe bearer delivery.
    const plaintext = await adminAuth.grantReader(GROUP, {
      readerDid: rtReader.did,
      outPath: join(readerDir, "plaintext.tnpkg"),
      unsafePlaintext: true,
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(plaintext.sealed, false);
    const plainKit = readTnpkgVerified(join(readerDir, "plaintext.tnpkg"));
    const state = (plainKit.manifest.state ?? {}) as Record<string, unknown>;
    assert.equal(state["body_encryption"], undefined, "unsafePlaintext must not seal");
    assert.equal(state["unsafe_plaintext_delivery"], true, "plaintext kit must be labeled");
    assert.equal(warnings.length, 2);
    assert.match(warnings[1]!.message, /plaintext_bearer_delivery/);

    const audits = auditOperations(rtAuth);
    assert.equal(audits.length, 2, "each unsafe grant emits one audit event");
  } finally {
    process.removeListener("warning", handler);
  }
});
