// Trusted-enrollment state machine: challenge issue, offer staging, replay,
// exact-digest approval, response install, and first decrypt — driven by both
// the frozen shared fixtures (tests/fixtures/trust/v1) and live EnrollmentStore
// lifecycles. Mirrors python/tests/test_enrollment_state.py semantics.
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../src/core/canonical.js";
import { b64ToBytes, bytesToB64 } from "../src/core/encoding.js";
import { DeviceKey } from "../src/core/signing.js";
import {
  TrustError,
  enrollmentChallengeDigest,
  parseEnrollmentChallenge,
  parseEnrollmentResponse,
  parseKeyBindingProof,
  sha256Digest,
  signKeyBindingProof,
  type EnrollmentChallengeV1,
  type TrustReason,
} from "../src/core/trust.js";
import {
  EnrollmentStore,
  MAX_ENROLLMENT_ARTIFACT_BYTES,
  buildJweOfferArtifact,
  ensureJweReaderKey,
  evaluateConsumedChallenge,
  installEnrollmentResponse,
  recordSentOffer,
  type EnrollmentCeremony,
} from "../src/runtime/enrollment.js";
import { loadPinnedHibeAuthority, pinHibeAuthority } from "../src/runtime/hibe_group.js";

const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "tests",
  "fixtures",
  "trust",
  "v1",
);

type JsonObject = Record<string, unknown>;

function fixture(name: string): JsonObject {
  return JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as JsonObject;
}

function lifecycleCase(caseId: string): JsonObject {
  const cases = fixture("enrollment_lifecycle.json")["cases"] as JsonObject[];
  const found = cases.find((c) => c["id"] === caseId);
  assert.ok(found, `enrollment_lifecycle case ${caseId} missing`);
  return found;
}

function statementCase(caseId: string): JsonObject {
  const cases = fixture("signed_statements.json")["cases"] as JsonObject[];
  const found = cases.find((c) => c["id"] === caseId);
  assert.ok(found, `signed_statements case ${caseId} missing`);
  return found;
}

function deviceFor(role: "publisher" | "reader" | "authority"): DeviceKey {
  const cases = fixture("did_key_vectors.json")["cases"] as JsonObject[];
  const c = cases.find((x) => x["id"] === `${role}_ed25519_did_key`);
  assert.ok(c, `${role} did key vector missing`);
  return DeviceKey.fromSeed(b64ToBytes(String((c["input"] as JsonObject)["seed_b64"])));
}

function fixtureChallenge(): EnrollmentChallengeV1 {
  const c = statementCase("valid_enrollment_challenge");
  return parseEnrollmentChallenge((c["input"] as JsonObject)["statement"]);
}

function reasonOf(fn: () => unknown): TrustReason {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrustError, `expected TrustError, got ${String(err)}`);
    return err.reason;
  }
  assert.fail("expected a TrustError, but no error was thrown");
}

interface StoreHome {
  ceremony: EnrollmentCeremony;
  store: EnrollmentStore;
  stateRoot: string;
  dir: string;
}

function makeStore(
  publisher: DeviceKey,
  opts: { ceremonyId?: string; groups?: string[] } = {},
): StoreHome {
  const dir = mkdtempSync(join(tmpdir(), "tn-enroll-"));
  const ceremony: EnrollmentCeremony = {
    ceremonyId: opts.ceremonyId ?? "ts-enroll-test-ceremony",
    yamlPath: join(dir, "tn.yaml"),
    groups: new Set(opts.groups ?? ["default"]),
    deviceIdentity: publisher.did,
  };
  const stateRoot = join(dir, "enrollment-state");
  return { ceremony, store: new EnrollmentStore(ceremony, publisher, stateRoot), stateRoot, dir };
}

/** Seed the state root with a retained challenge exactly as issueChallenge writes it. */
function retainChallenge(stateRoot: string, challenge: EnrollmentChallengeV1): void {
  const wire: JsonObject = { ...challenge };
  const record = {
    version: 1,
    challenge_digest: enrollmentChallengeDigest(challenge),
    challenge: wire,
  };
  const dir = join(stateRoot, "challenges");
  mkdirSync(dir, { recursive: true });
  const bytes = new Uint8Array(canonicalize(record).length + 1);
  bytes.set(canonicalize(record), 0);
  bytes[bytes.length - 1] = 0x0a;
  writeFileSync(join(dir, `${challenge.challenge_id}.json`), bytes);
}

function writeConsumedMarker(stateRoot: string, challengeId: string, record: JsonObject): void {
  const dir = join(stateRoot, "consumed");
  mkdirSync(dir, { recursive: true });
  const body = canonicalize(record);
  const bytes = new Uint8Array(body.length + 1);
  bytes.set(body, 0);
  bytes[bytes.length - 1] = 0x0a;
  writeFileSync(join(dir, `${challengeId}.json`), bytes);
}

const NOW = "2026-07-11T14:05:00Z";

// ── Live store lifecycle ────────────────────────────────────────────

test("issueChallenge is signed, scoped, persisted, and preauthorized", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const { ceremony, store, stateRoot } = makeStore(publisher);

  const challenge = store.issueChallenge(reader.did, "default", 5 * 60_000);
  assert.equal(challenge.publisher_did, publisher.did);
  assert.equal(challenge.expected_reader_did, reader.did);
  assert.equal(challenge.ceremony_id, ceremony.ceremonyId);
  assert.equal(challenge.group, "default");
  assert.ok(challenge.signature_b64.length > 0);

  const persisted = JSON.parse(
    readFileSync(join(stateRoot, "challenges", `${challenge.challenge_id}.json`), "utf8"),
  ) as JsonObject;
  assert.equal(persisted["challenge_digest"], enrollmentChallengeDigest(challenge));
  assert.equal((persisted["challenge"] as JsonObject)["signature_b64"], challenge.signature_b64);

  assert.equal(
    reasonOf(() => store.issueChallenge(reader.did, "nope", 60_000)),
    "scope_mismatch",
  );
});

test("stage + reconcile retain the exact artifact; exact replay is idempotent", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const { ceremony, store, dir } = makeStore(publisher);
  store.preauthorize(reader.did, "default");
  const challenge = store.issueChallenge(reader.did, "default", 5 * 60_000);

  const readerKeystore = join(dir, "reader-keys");
  const built = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: readerKeystore,
    publisherDid: publisher.did,
    ceremonyId: ceremony.ceremonyId,
    group: "default",
    challenge,
    now: challenge.issued_at,
  });

  const pending = store.stageOffer(built.artifact, publisher.did, challenge.issued_at);
  assert.equal(pending.ceremonyId, ceremony.ceremonyId);
  assert.equal(pending.group, "default");
  assert.equal(pending.readerDid, reader.did);
  assert.deepEqual(new Uint8Array(readFileSync(pending.artifactPath)), built.artifact);
  assert.equal(pending.offerDigest, built.offerDigest);

  const accepted = store.reconcile(pending, challenge.issued_at);
  assert.equal(accepted.offerDigest, built.offerDigest);
  assert.equal(accepted.artifactDigest, sha256Digest(built.artifact));
  assert.equal(accepted.binding.proofDigest, accepted.offerDigest);
  assert.equal(accepted.binding.publicKeySha256, built.publicKeySha256);

  // Exact replay converges without new state.
  const replayed = store.stageOffer(built.artifact, publisher.did, challenge.issued_at);
  assert.deepEqual(store.reconcile(replayed, challenge.issued_at), accepted);

  // Replay after expiry stays idempotent (freshness authorized the original).
  const afterExpiry = "2026-09-01T00:00:00Z";
  const late = store.stageOffer(built.artifact, publisher.did, afterExpiry);
  assert.deepEqual(store.reconcile(late, afterExpiry), accepted);
});

test("the same challenge with a changed signed body is a replay conflict", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const { ceremony, store, dir } = makeStore(publisher);
  store.preauthorize(reader.did, "default");
  const challenge = store.issueChallenge(reader.did, "default", 5 * 60_000);
  const now = challenge.issued_at;

  const first = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: join(dir, "reader-keys-a"),
    publisherDid: publisher.did,
    ceremonyId: ceremony.ceremonyId,
    group: "default",
    challenge,
    now,
  });
  store.reconcile(store.stageOffer(first.artifact, publisher.did, now), now);

  // A different reader keystore mints a different X25519 key: same challenge,
  // different signed bytes.
  const second = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: join(dir, "reader-keys-b"),
    publisherDid: publisher.did,
    ceremonyId: ceremony.ceremonyId,
    group: "default",
    challenge,
    now,
  });
  assert.notEqual(second.offerDigest, first.offerDigest);
  assert.equal(
    reasonOf(() => store.stageOffer(second.artifact, publisher.did, now)),
    "replay_conflict",
  );
});

test("an unsolicited offer stays pending until its exact digest is approved", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const { ceremony, store, dir } = makeStore(publisher);

  const built = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: join(dir, "reader-keys"),
    publisherDid: publisher.did,
    ceremonyId: ceremony.ceremonyId,
    group: "default",
    challenge: null,
    now: NOW,
  });
  const pending = store.stageOffer(built.artifact, publisher.did, NOW);
  assert.equal(
    reasonOf(() => store.reconcile(pending, NOW)),
    "untrusted_principal",
  );

  // A wrong digest is not found; the exact digest promotes atomically.
  assert.equal(
    reasonOf(() => store.approveAndReconcile("sha256:" + "2".repeat(64), NOW)),
    "untrusted_principal",
  );
  const accepted = store.approveAndReconcile(built.offerDigest, NOW);
  assert.equal(accepted.offerDigest, built.offerDigest);
  // Approval of the exact digest is durable and idempotent.
  assert.deepEqual(store.approveAndReconcile(built.offerDigest, NOW), accepted);
});

test("stage rejects an oversized artifact without creating state", () => {
  const publisher = DeviceKey.generate();
  const { store, stateRoot } = makeStore(publisher);
  const oversized = new Uint8Array(MAX_ENROLLMENT_ARTIFACT_BYTES + 1);
  assert.equal(
    reasonOf(() => store.stageOffer(oversized, publisher.did, NOW)),
    "statement_invalid",
  );
  assert.throws(() => readFileSync(join(stateRoot, "enrollment.lock")), /ENOENT/);
});

// ── Fixture-driven offer absorption ─────────────────────────────────

interface OfferCaseSetup {
  store: EnrollmentStore;
  artifact: Uint8Array;
  validation: JsonObject;
  now: string;
}

function setupOfferCase(c: JsonObject): OfferCaseSetup {
  const input = c["input"] as JsonObject;
  const validation = input["validation"] as JsonObject;
  const publisher = deviceFor("publisher");
  const home = makeStore(publisher, {
    ceremonyId: String(validation["expected_ceremony_id"]),
    groups: [String(validation["expected_group"])],
  });
  const challenge = fixtureChallenge();
  const state = String(validation["challenge_state"]);
  let now = String(validation["now"]);
  if (state === "issued" || state === "expired") {
    retainChallenge(home.stateRoot, challenge);
  }
  if (state === "expired") {
    now = "2026-07-11T14:15:00Z"; // past the challenge acceptance window
  }
  if (state === "consumed") {
    retainChallenge(home.stateRoot, challenge);
    writeConsumedMarker(home.stateRoot, challenge.challenge_id, {
      version: 1,
      challenge_id: challenge.challenge_id,
    });
  }
  for (const did of (validation["trusted_reader_dids"] as string[]) ?? []) {
    home.store.preauthorize(did, String(validation["expected_group"]));
  }
  return {
    store: home.store,
    artifact: b64ToBytes(String(input["tnpkg_b64"])),
    validation,
    now,
  };
}

/** Stage, post-check the binding, and reconcile one fixture offer case. */
function runOfferCase(c: JsonObject): { offerDigest: string; artifactDigest: string } {
  const { store, artifact, validation, now } = setupOfferCase(c);
  const localDid = String(validation["local_recipient_did"]);
  const pending = store.stageOffer(artifact, localDid, now);
  if (pending.verified.publicKeySha256 !== validation["expected_public_key_sha256"]) {
    throw new TrustError(
      "binding_invalid",
      "X25519 public key digest does not match the expected binding",
    );
  }
  const accepted = store.reconcile(pending, now);
  return { offerDigest: accepted.offerDigest, artifactDigest: accepted.artifactDigest };
}

test("fixture: absorb_authenticated_offer stages and reconciles with exact digests", () => {
  const c = lifecycleCase("absorb_authenticated_offer");
  const result = runOfferCase(c);
  const expected = c["expected"] as JsonObject;
  assert.equal(result.offerDigest, expected["offer_digest"]);
  assert.equal(result.artifactDigest, expected["artifact_digest"]);
});

test("fixture: rejected offers map to stable reasons", () => {
  const rejected = [
    "offer_outer_inner_signer_mismatch",
    "offer_wrong_recipient",
    "offer_scope_mismatch",
    "offer_body_digest_mismatch",
    "offer_challenge_missing",
    "offer_challenge_expired",
    "offer_challenge_replayed",
    "offer_binding_invalid",
    "offer_untrusted_principal",
  ];
  for (const caseId of rejected) {
    const c = lifecycleCase(caseId);
    const expected = (c["expected"] as JsonObject)["reason"] as TrustReason;
    assert.equal(
      reasonOf(() => runOfferCase(c)),
      expected,
      caseId,
    );
  }
});

test("fixture: exact-digest approval accepts and a wrong digest stays untrusted", () => {
  const approve = lifecycleCase("approve_exact_offer_digest");
  {
    const input = approve["input"] as JsonObject;
    const publisher = deviceFor("publisher");
    const home = makeStore(publisher, { ceremonyId: "trust-fixture-ceremony-2026-07-11" });
    retainChallenge(home.stateRoot, fixtureChallenge());
    const artifact = b64ToBytes(String(input["tnpkg_b64"]));
    home.store.stageOffer(artifact, publisher.did, NOW);
    const accepted = home.store.approveAndReconcile(String(input["approved_offer_digest"]), NOW);
    assert.equal(accepted.offerDigest, input["pending_offer_digest"]);
  }
  {
    const c = lifecycleCase("approval_digest_not_exact");
    const input = c["input"] as JsonObject;
    const publisher = deviceFor("publisher");
    const home = makeStore(publisher, { ceremonyId: "trust-fixture-ceremony-2026-07-11" });
    retainChallenge(home.stateRoot, fixtureChallenge());
    const artifact = b64ToBytes(String(input["tnpkg_b64"]));
    home.store.stageOffer(artifact, publisher.did, NOW);
    assert.equal(
      reasonOf(() => home.store.approveAndReconcile(String(input["approved_offer_digest"]), NOW)),
      (c["expected"] as JsonObject)["reason"],
    );
  }
});

// ── Fixture-driven enrollment response install (reader side) ───────

function readerKeystoreWithFixtureKey(): string {
  const cases = fixture("did_key_vectors.json")["cases"] as JsonObject[];
  const c = cases.find((x) => x["id"] === "reader_x25519_static_key");
  assert.ok(c, "reader x25519 vector missing");
  const seed = b64ToBytes(String((c["input"] as JsonObject)["private_seed_b64"]));
  const dir = mkdtempSync(join(tmpdir(), "tn-reader-keys-"));
  writeFileSync(join(dir, "default.jwe.mykey"), seed);
  return dir;
}

test("fixture: the accepted enrollment response installs the publisher", () => {
  const c = lifecycleCase("verify_accepted_enrollment_response");
  const input = c["input"] as JsonObject;
  const response = parseEnrollmentResponse(input["response"]);
  const keystoreDir = readerKeystoreWithFixtureKey();
  recordSentOffer(keystoreDir, {
    offerDigest: String(input["expected_offer_digest"]),
    publisherDid: response.publisher_did,
    readerDid: response.reader_did,
    ceremonyId: response.ceremony_id,
    group: response.group,
    publicKeySha256: String(input["expected_public_key_sha256"]),
  });

  const installed = installEnrollmentResponse({
    keystoreDir,
    readerDid: response.reader_did,
    response: input["response"],
    now: NOW,
  });
  assert.equal(installed.publisherDid, response.publisher_did);
  assert.equal(installed.groupEpoch, response.group_epoch);

  const record = JSON.parse(
    readFileSync(join(keystoreDir, "trust", "verified_publishers.v1.json"), "utf8"),
  ) as JsonObject;
  const publishers = record["publishers"] as JsonObject;
  assert.ok(publishers[response.publisher_did], "publisher not recorded as verified");
});

test("fixture: a response naming an unknown offer digest is out of scope", () => {
  const c = lifecycleCase("response_offer_scope_mismatch");
  const input = c["input"] as JsonObject;
  const response = parseEnrollmentResponse(input["response"]);
  const keystoreDir = readerKeystoreWithFixtureKey();
  // The reader retained a DIFFERENT offer digest than the response names.
  recordSentOffer(keystoreDir, {
    offerDigest: String(input["expected_offer_digest"]),
    publisherDid: response.publisher_did,
    readerDid: response.reader_did,
    ceremonyId: response.ceremony_id,
    group: response.group,
    publicKeySha256: String(input["expected_public_key_sha256"]),
  });
  assert.equal(
    reasonOf(() =>
      installEnrollmentResponse({
        keystoreDir,
        readerDid: response.reader_did,
        response: input["response"],
        now: NOW,
      }),
    ),
    (c["expected"] as JsonObject)["reason"],
  );
});

// ── Fixture-driven first decrypt ────────────────────────────────────

async function firstDecrypt(
  c: JsonObject,
): Promise<{ plaintext: Uint8Array; sharedSha256: string }> {
  const input = c["input"] as JsonObject;
  const jwe = JSON.parse(
    new TextDecoder().decode(b64ToBytes(String(input["jwe_b64"]))),
  ) as JsonObject;
  const seed = b64ToBytes(String(input["reader_private_seed_b64"]));
  const recipient = (jwe["recipients"] as JsonObject[])[0]!;
  const header = recipient["header"] as JsonObject;
  const epk = (header["epk"] as JsonObject)["x"];
  const shared = x25519.getSharedSecret(seed, b64ToBytes(String(epk)));

  // Concat-KDF (single round, SHA-256) exactly as the fixture generator built it.
  const alg = new TextEncoder().encode("ECDH-ES+A256KW");
  const kdfInput = new Uint8Array(4 + shared.length + 4 + alg.length + 4 + 4 + 4);
  const view = new DataView(kdfInput.buffer);
  let offset = 0;
  view.setUint32(offset, 1);
  offset += 4;
  kdfInput.set(shared, offset);
  offset += shared.length;
  view.setUint32(offset, alg.length);
  offset += 4;
  kdfInput.set(alg, offset);
  offset += alg.length;
  view.setUint32(offset, 0);
  offset += 4;
  view.setUint32(offset, 0);
  offset += 4;
  view.setUint32(offset, 256);
  const kekBytes = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", kdfInput));

  const kek = await globalThis.crypto.subtle.importKey("raw", kekBytes, { name: "AES-KW" }, false, [
    "unwrapKey",
  ]);
  const cek = await globalThis.crypto.subtle.unwrapKey(
    "raw",
    b64ToBytes(String(recipient["encrypted_key"])),
    kek,
    { name: "AES-KW" },
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const ciphertext = b64ToBytes(String(jwe["ciphertext"]));
  const tag = b64ToBytes(String(jwe["tag"]));
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);
  const aeadAad = new TextEncoder().encode(`${String(jwe["protected"])}.${String(jwe["aad"])}`);
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(String(jwe["iv"])), additionalData: aeadAad },
    cek,
    sealed,
  );
  return { plaintext: new Uint8Array(plaintext), sharedSha256: sha256Digest(shared) };
}

test("fixture: the retained reader key opens the first sealed entry", async () => {
  const c = lifecycleCase("first_decrypt_with_retained_reader_key");
  const expected = c["expected"] as JsonObject;
  const result = await firstDecrypt(c);
  assert.equal(bytesToB64(result.plaintext), expected["plaintext_b64"]);
  assert.equal(result.sharedSha256, expected["shared_secret_sha256"]);
});

test("fixture: a wrong private key cannot open the first sealed entry", async () => {
  const c = lifecycleCase("first_decrypt_wrong_private_key");
  await assert.rejects(() => firstDecrypt(c));
});

// ── State transitions: consumed challenges + HIBE epochs ───────────

test("fixture: consume_challenge transitions match the frozen table", () => {
  const cases = (fixture("state_transitions.json")["cases"] as JsonObject[]).filter(
    (c) => (c["input"] as JsonObject)["operation"] === "consume_challenge",
  );
  assert.ok(cases.length >= 4);
  for (const c of cases) {
    const input = c["input"] as JsonObject;
    const expected = c["expected"] as JsonObject;
    const prior =
      input["consumed"] === true
        ? input["prior_artifact_digest"] === null
          ? {}
          : { artifactDigest: String(input["prior_artifact_digest"]) }
        : null;
    const run = (): string =>
      evaluateConsumedChallenge(prior, { artifactDigest: String(input["artifact_digest"]) });
    if (expected["accepted"] === true) {
      assert.equal(
        run(),
        expected["idempotent"] === true ? "idempotent" : "fresh",
        String(c["id"]),
      );
    } else {
      assert.equal(reasonOf(run), expected["reason"], String(c["id"]));
    }
  }
});

test("fixture: install_hibe_assertion epoch transitions match the frozen table", () => {
  const cases = (fixture("state_transitions.json")["cases"] as JsonObject[]).filter(
    (c) => (c["input"] as JsonObject)["operation"] === "install_hibe_assertion",
  );
  assert.ok(cases.length >= 4);
  for (const c of cases) {
    const input = c["input"] as JsonObject;
    const expected = c["expected"] as JsonObject;
    const keystoreDir = mkdtempSync(join(tmpdir(), "tn-hibe-pin-"));
    const base = {
      authorityDid: String(input["authority_did"]),
      ceremonyId: "trust-fixture-ceremony-2026-07-11",
      group: "default",
      maxDepth: 3,
      idPath: "org/fraud/case-17",
    };
    pinHibeAuthority(keystoreDir, "default", {
      ...base,
      mpkSha256: String(input["current_mpk_sha256"]),
      pathEpoch: Number(input["current_epoch"]),
      assertionDigest: "sha256:" + "a".repeat(64),
    });
    const incoming = {
      ...base,
      mpkSha256: String(input["incoming_mpk_sha256"]),
      pathEpoch: Number(input["incoming_epoch"]),
      assertionDigest:
        expected["idempotent"] === true ? "sha256:" + "a".repeat(64) : "sha256:" + "b".repeat(64),
    };
    if (expected["accepted"] === true) {
      pinHibeAuthority(keystoreDir, "default", incoming);
      const pinned = loadPinnedHibeAuthority(keystoreDir, "default");
      assert.equal(pinned?.pathEpoch, expected["next_epoch"], String(c["id"]));
    } else {
      assert.equal(
        reasonOf(() => pinHibeAuthority(keystoreDir, "default", incoming)),
        expected["reason"],
        String(c["id"]),
      );
    }
  }
});

// ── Producer invariants ─────────────────────────────────────────────

test("the reader key is created once and reused byte-for-byte", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-reader-key-"));
  const first = ensureJweReaderKey(dir, "default");
  const privBytes = new Uint8Array(readFileSync(join(dir, "default.jwe.mykey")));
  assert.equal(privBytes.length, 32);
  const second = ensureJweReaderKey(dir, "default");
  assert.deepEqual(second, first);
  assert.deepEqual(new Uint8Array(readFileSync(join(dir, "default.jwe.mykey"))), privBytes);
  assert.notDeepEqual(ensureJweReaderKey(dir, "other"), first);
});

test("a challenged offer binds the exact challenge digest and verifies end to end", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const { ceremony, store, dir } = makeStore(publisher);
  store.preauthorize(reader.did, "default");
  const challenge = store.issueChallenge(reader.did, "default", 5 * 60_000);

  const built = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: join(dir, "rk"),
    publisherDid: publisher.did,
    ceremonyId: ceremony.ceremonyId,
    group: "default",
    challenge,
    now: challenge.issued_at,
  });
  assert.equal(built.proof.binding["challenge_digest"], enrollmentChallengeDigest(challenge));

  // The challenge signature must have been verified by the producer: a
  // mutated challenge is rejected before any proof is signed.
  const forged = { ...challenge, signature_b64: bytesToB64(new Uint8Array(64)) };
  assert.equal(
    reasonOf(() =>
      buildJweOfferArtifact({
        readerKey: reader,
        readerKeystoreDir: join(dir, "rk2"),
        publisherDid: publisher.did,
        ceremonyId: ceremony.ceremonyId,
        group: "default",
        challenge: forged,
        now: challenge.issued_at,
      }),
    ),
    "signature_invalid",
  );
});

test("stage rejects an offer whose payload key differs from the signed binding", () => {
  const publisher = DeviceKey.generate();
  const reader = DeviceKey.generate();
  const { ceremony, store, dir } = makeStore(publisher);
  const built = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: join(dir, "rk"),
    publisherDid: publisher.did,
    ceremonyId: ceremony.ceremonyId,
    group: "default",
    challenge: null,
    now: NOW,
    unsignedPayloadPublicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()),
  });
  assert.equal(
    reasonOf(() => store.stageOffer(built.artifact, publisher.did, NOW)),
    "binding_invalid",
  );
});

test("a proof with a digest for an unretained challenge is challenge_missing", () => {
  const publisher = deviceFor("publisher");
  const reader = deviceFor("reader");
  const home = makeStore(publisher, { ceremonyId: "trust-fixture-ceremony-2026-07-11" });
  // Bind to the canonical fixture challenge, but never retain it.
  const challenge = fixtureChallenge();
  const built = buildJweOfferArtifact({
    readerKey: reader,
    readerKeystoreDir: join(home.dir, "rk"),
    publisherDid: publisher.did,
    ceremonyId: "trust-fixture-ceremony-2026-07-11",
    group: "default",
    challenge,
    now: challenge.issued_at,
    skipChallengeVerification: true,
  });
  assert.equal(
    reasonOf(() => home.store.stageOffer(built.artifact, publisher.did, challenge.issued_at)),
    "challenge_missing",
  );
});

test("signKeyBindingProof refuses a signer that is not the subject", () => {
  const publisher = deviceFor("publisher");
  const c = statementCase("valid_jwe_reader_proof");
  const proof = {
    ...parseKeyBindingProof((c["input"] as JsonObject)["statement"]),
    signature_b64: "",
  };
  assert.equal(
    reasonOf(() => signKeyBindingProof(proof, publisher)),
    "did_signer_mismatch",
  );
});
