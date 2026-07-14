// Shared trusted-principal statement vectors (Workstream A, Track TS).
//
// Loads the frozen fixtures at tests/fixtures/trust/v1, independently
// canonicalizes every accepted statement, and asserts exact wire bytes and
// stable machine-readable reasons. Mirrors python/tests/test_trusted_principals.py
// and python/tests/test_key_binding_wire.py over the same fixture files.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { canonicalize } from "../src/core/canonical.js";
import { b64ToBytes, bytesToB64 } from "../src/core/encoding.js";
import { DeviceKey } from "../src/core/signing.js";
import {
  TrustError,
  createHibeReaderProof,
  enrollmentChallengeSigningBytes,
  enrollmentResponseSigningBytes,
  keyBindingProofDigest,
  keyBindingProofSigningBytes,
  parseEd25519DidKey,
  parseEnrollmentChallenge,
  parseEnrollmentResponse,
  parseKeyBindingProof,
  sha256Digest,
  signEnrollmentChallenge,
  signEnrollmentResponse,
  signKeyBindingProof,
  verifyEd25519DidSignature,
  verifyEnrollmentChallenge,
  verifyEnrollmentResponse,
  verifyJweKeyBinding,
  verifyKeyBindingProof,
  type EnrollmentChallengeV1,
  type KeyBindingProofV1,
  type TrustReason,
} from "../src/core/trust.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "tests", "fixtures", "trust", "v1");

type JsonObject = Record<string, unknown>;

function fixture(name: string): JsonObject {
  return JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as JsonObject;
}

function statementCase(caseId: string): JsonObject {
  const cases = fixture("signed_statements.json")["cases"] as JsonObject[];
  const found = cases.find((c) => c["id"] === caseId);
  assert.ok(found, `signed_statements case ${caseId} missing`);
  return found;
}

function caseStatement(c: JsonObject): JsonObject {
  return (c["input"] as JsonObject)["statement"] as JsonObject;
}

function caseValidation(c: JsonObject): JsonObject {
  return (c["input"] as JsonObject)["validation"] as JsonObject;
}

function deviceFor(role: "publisher" | "reader" | "authority"): DeviceKey {
  const cases = fixture("did_key_vectors.json")["cases"] as JsonObject[];
  const c = cases.find((x) => x["id"] === `${role}_ed25519_did_key`);
  assert.ok(c, `${role} did key vector missing`);
  const seed = b64ToBytes(String((c["input"] as JsonObject)["seed_b64"]));
  return DeviceKey.fromSeed(seed);
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

/** Mirror of Python's `_verify_proof_fixture` harness over one fixture case. */
function verifyProofFixture(c: JsonObject): void {
  const statement = caseStatement(c);
  const validation = caseValidation(c);
  const proof = parseKeyBindingProof(statement);

  if (proof.subject_did !== validation["expected_signer_did"]) {
    throw new TrustError("did_signer_mismatch", "proof subject does not match the expected signer");
  }

  const challenge = challengeForProof(proof);
  const principal = verifyKeyBindingProof(proof, {
    purpose: String(validation["expected_purpose"]) as KeyBindingProofV1["purpose"],
    audienceDid: String(validation["expected_audience_did"]),
    ceremonyId: String(validation["expected_ceremony_id"]),
    group: String(validation["expected_group"]),
    now: String(validation["now"]),
    ...(challenge === null ? {} : { challenge }),
  });
  assert.equal(principal.did, proof.subject_did);

  if (proof.purpose === "jwe-reader") {
    const binding = verifyJweKeyBinding(proof, {
      audienceDid: String(validation["expected_audience_did"]),
      ceremonyId: String(validation["expected_ceremony_id"]),
      group: String(validation["expected_group"]),
      now: String(validation["now"]),
      ...(challenge === null ? {} : { challenge }),
    });
    if (binding.publicKeySha256 !== validation["expected_public_key_sha256"]) {
      throw new TrustError("binding_invalid", "X25519 public key digest does not match the expected binding");
    }
  } else if (proof.purpose === "hibe-authority") {
    const mpk = b64ToBytes(String(validation["expected_mpk_b64"]));
    const expectedDigest = sha256Digest(mpk);
    if (mpk.length !== 96 || (proof.binding as JsonObject)["mpk_sha256"] !== expectedDigest) {
      throw new TrustError("binding_invalid", "HIBE MPK does not match the authority proof binding");
    }
  }
}

function challengeForProof(proof: KeyBindingProofV1): EnrollmentChallengeV1 | null {
  if (proof.purpose === "hibe-authority") return null;
  const caseId =
    proof.purpose === "jwe-reader" ? "valid_enrollment_challenge" : "valid_hibe_reader_challenge";
  return parseEnrollmentChallenge(caseStatement(statementCase(caseId)));
}

// ── DID vectors ─────────────────────────────────────────────────────

test("strict Ed25519 did:key vectors parse or fail with did_invalid", () => {
  const cases = fixture("did_key_vectors.json")["cases"] as JsonObject[];
  let executed = 0;
  for (const c of cases) {
    if (c["kind"] !== "ed25519-did-key") continue;
    executed += 1;
    const did = String((c["input"] as JsonObject)["did"]);
    const expected = c["expected"] as JsonObject;
    if (expected["valid"] === true) {
      const pub = parseEd25519DidKey(did);
      assert.equal(bytesToB64(pub), expected["public_key_b64"]);
    } else {
      assert.equal(reasonOf(() => parseEd25519DidKey(did)), "did_invalid");
    }
  }
  assert.ok(executed >= 5, "expected at least five Ed25519 did:key vectors");
});

test("parseEd25519DidKey rejects non-canonical base58 and foreign inputs", () => {
  const reader = deviceFor("reader");
  // A leading "1" prepends a zero byte: decodes differently, and the
  // canonical re-encode check must reject the padded spelling.
  const padded = "did:key:z1" + reader.did.slice("did:key:z".length);
  assert.equal(reasonOf(() => parseEd25519DidKey(padded)), "did_invalid");
  assert.equal(reasonOf(() => parseEd25519DidKey("did:web:example.com")), "did_invalid");
  assert.equal(reasonOf(() => parseEd25519DidKey("did:key:z")), "did_invalid");
  assert.equal(reasonOf(() => parseEd25519DidKey("did:key:z0OIl")), "did_invalid");
});

test("verifyEd25519DidSignature is strict about lengths and key binding", () => {
  const reader = deviceFor("reader");
  const message = new TextEncoder().encode("strict DID-bound verification");
  const signature = reader.sign(message);
  verifyEd25519DidSignature(reader.did, message, signature);

  assert.equal(
    reasonOf(() => verifyEd25519DidSignature(reader.did, message, signature.slice(0, 63))),
    "signature_invalid",
  );
  const publisher = deviceFor("publisher");
  assert.equal(
    reasonOf(() => verifyEd25519DidSignature(publisher.did, message, signature)),
    "signature_invalid",
  );
  assert.equal(
    reasonOf(() => verifyEd25519DidSignature("did:key:zNotADid", message, signature)),
    "did_invalid",
  );
});

// ── Accepted statement vectors: exact wire bytes + verification ────

test("accepted challenge vectors have exact signing bytes and verify", () => {
  for (const caseId of ["valid_enrollment_challenge", "valid_hibe_reader_challenge"]) {
    const c = statementCase(caseId);
    const statement = caseStatement(c);
    const challenge = parseEnrollmentChallenge(statement);

    const expectedBytes = b64ToBytes(String(c["canonical_b64"]));
    assert.deepEqual(enrollmentChallengeSigningBytes(challenge), expectedBytes);
    // Independent canonicalization of the raw fixture JSON minus signature.
    const unsigned: JsonObject = { ...statement };
    delete unsigned["signature_b64"];
    assert.deepEqual(canonicalize(unsigned), expectedBytes);

    const validation = caseValidation(c);
    verifyEnrollmentChallenge(challenge, {
      publisherDid: String(validation["expected_publisher_did"]),
      readerDid: String(validation["expected_reader_did"]),
      ceremonyId: String(validation["expected_ceremony_id"]),
      group: String(validation["expected_group"]),
      now: String(validation["now"]),
    });
  }
});

test("rejected challenge vectors map to stable reasons", () => {
  const expectations: Array<[string, TrustReason]> = [
    ["challenge_unknown_field", "statement_invalid"],
    ["challenge_unsupported_version", "statement_invalid"],
    ["challenge_expired_statement", "statement_expired"],
    ["challenge_signature_mutated", "signature_invalid"],
  ];
  for (const [caseId, reason] of expectations) {
    const c = statementCase(caseId);
    const validation = caseValidation(c);
    const got = reasonOf(() => {
      const challenge = parseEnrollmentChallenge(caseStatement(c));
      verifyEnrollmentChallenge(challenge, {
        publisherDid: String(validation["expected_publisher_did"]),
        readerDid: String(validation["expected_reader_did"]),
        ceremonyId: String(validation["expected_ceremony_id"]),
        group: String(validation["expected_group"]),
        now: String(validation["now"]),
      });
    });
    assert.equal(got, reason, caseId);
  }
});

test("accepted proof vectors have exact signing bytes and verify", () => {
  for (const caseId of ["valid_jwe_reader_proof", "valid_hibe_reader_proof", "valid_hibe_authority_proof"]) {
    const c = statementCase(caseId);
    const proof = parseKeyBindingProof(caseStatement(c));
    assert.deepEqual(keyBindingProofSigningBytes(proof), b64ToBytes(String(c["canonical_b64"])), caseId);
    verifyProofFixture(c);
  }
});

test("rejected proof vectors map to stable reasons", () => {
  const expectations: Array<[string, TrustReason]> = [
    ["jwe_proof_signer_did_mismatch", "did_signer_mismatch"],
    ["jwe_proof_wrong_recipient", "wrong_recipient"],
    ["jwe_proof_scope_mismatch", "scope_mismatch"],
    ["jwe_proof_binding_mismatch", "binding_invalid"],
  ];
  for (const [caseId, reason] of expectations) {
    assert.equal(reasonOf(() => verifyProofFixture(statementCase(caseId))), reason, caseId);
  }
});

test("hibe authority proof binds the expected MPK bytes", () => {
  const c = JSON.parse(JSON.stringify(statementCase("valid_hibe_authority_proof"))) as JsonObject;
  (caseValidation(c) as JsonObject)["expected_mpk_b64"] = bytesToB64(new Uint8Array(96));
  assert.equal(reasonOf(() => verifyProofFixture(c)), "binding_invalid");
});

test("valid enrollment response has exact signing bytes and verifies", () => {
  const c = statementCase("valid_enrollment_response");
  const response = parseEnrollmentResponse(caseStatement(c));
  assert.deepEqual(enrollmentResponseSigningBytes(response), b64ToBytes(String(c["canonical_b64"])));

  const validation = caseValidation(c);
  verifyEnrollmentResponse(response, {
    publisherDid: String(validation["expected_publisher_did"]),
    readerDid: String(validation["expected_reader_did"]),
    ceremonyId: String(validation["expected_ceremony_id"]),
    group: String(validation["expected_group"]),
    offerDigest: String(validation["expected_offer_digest"]),
    publicKeySha256: String(validation["expected_public_key_sha256"]),
    now: String(validation["now"]),
  });
});

test("response mismatches have stable reasons", () => {
  const c = statementCase("valid_enrollment_response");
  const response = parseEnrollmentResponse(caseStatement(c));
  const validation = caseValidation(c);
  const common = {
    publisherDid: String(validation["expected_publisher_did"]),
    readerDid: String(validation["expected_reader_did"]),
    ceremonyId: String(validation["expected_ceremony_id"]),
    group: String(validation["expected_group"]),
    offerDigest: String(validation["expected_offer_digest"]),
    publicKeySha256: String(validation["expected_public_key_sha256"]),
    now: String(validation["now"]),
  };
  verifyEnrollmentResponse(response, common);

  const authority = deviceFor("authority");
  assert.equal(
    reasonOf(() => verifyEnrollmentResponse(response, { ...common, readerDid: authority.did })),
    "wrong_recipient",
  );
  assert.equal(
    reasonOf(() =>
      verifyEnrollmentResponse(response, { ...common, publicKeySha256: "sha256:" + "0".repeat(64) }),
    ),
    "binding_invalid",
  );
  assert.equal(
    reasonOf(() => verifyEnrollmentResponse(response, { ...common, offerDigest: "sha256:" + "1".repeat(64) })),
    "binding_invalid",
  );
});

// ── Strict parsing: unknown fields, versions, and bindings ─────────

test("statement parsers reject unknown fields and unsupported versions", () => {
  const parsers: Array<[string, (value: unknown) => unknown]> = [
    ["valid_enrollment_challenge", parseEnrollmentChallenge],
    ["valid_jwe_reader_proof", parseKeyBindingProof],
    ["valid_enrollment_response", parseEnrollmentResponse],
  ];
  for (const [caseId, parser] of parsers) {
    const statement = { ...caseStatement(statementCase(caseId)) };
    (statement as JsonObject)["unexpected"] = true;
    assert.equal(reasonOf(() => parser(statement)), "statement_invalid", `${caseId} unknown field`);

    delete (statement as JsonObject)["unexpected"];
    (statement as JsonObject)["version"] = 2;
    assert.equal(reasonOf(() => parser(statement)), "statement_invalid", `${caseId} version`);
  }
});

test("proof parser rejects purpose-specific binding errors", () => {
  const mutations: Array<[string, JsonObject]> = [
    ["valid_jwe_reader_proof", { algorithm: "Ed25519-did-key" }],
    ["valid_jwe_reader_proof", { public_key_b64: bytesToB64(new Uint8Array(31)) }],
    ["valid_hibe_reader_proof", { delivery: "plaintext" }],
    ["valid_hibe_authority_proof", { max_depth: 0 }],
  ];
  for (const [caseId, mutation] of mutations) {
    const statement = { ...caseStatement(statementCase(caseId)) };
    statement["binding"] = { ...(statement["binding"] as JsonObject), ...mutation };
    assert.equal(reasonOf(() => parseKeyBindingProof(statement)), "binding_invalid", caseId);
  }

  const extra = { ...caseStatement(statementCase("valid_jwe_reader_proof")) };
  extra["binding"] = { ...(extra["binding"] as JsonObject), extra: true };
  assert.equal(reasonOf(() => parseKeyBindingProof(extra)), "binding_invalid");
});

test("timestamps must be canonical UTC and ordered", () => {
  const statement = { ...caseStatement(statementCase("valid_enrollment_challenge")) };
  statement["expires_at"] = statement["issued_at"];
  assert.equal(reasonOf(() => parseEnrollmentChallenge(statement)), "statement_invalid");

  const nonCanonical = { ...caseStatement(statementCase("valid_enrollment_challenge")) };
  nonCanonical["issued_at"] = "2026-07-11T14:00:00+00:00";
  assert.equal(reasonOf(() => parseEnrollmentChallenge(nonCanonical)), "statement_invalid");

  const shortFraction = { ...caseStatement(statementCase("valid_enrollment_challenge")) };
  shortFraction["issued_at"] = "2026-07-11T14:00:00.5Z";
  assert.equal(reasonOf(() => parseEnrollmentChallenge(shortFraction)), "statement_invalid");

  const challenge = parseEnrollmentChallenge(caseStatement(statementCase("valid_enrollment_challenge")));
  const expected = {
    publisherDid: challenge.publisher_did,
    readerDid: challenge.expected_reader_did,
    ceremonyId: challenge.ceremony_id,
    group: challenge.group,
  };
  assert.equal(
    reasonOf(() => verifyEnrollmentChallenge(challenge, { ...expected, now: "2026-07-11T13:59:59Z" })),
    "statement_invalid",
  );
  assert.equal(
    reasonOf(() => verifyEnrollmentChallenge(challenge, { ...expected, now: "2026-07-11T14:10:00Z" })),
    "statement_expired",
  );
});

// ── Signing helpers ─────────────────────────────────────────────────

test("sign methods reproduce the fixture signatures and enforce the signer DID", () => {
  const publisher = deviceFor("publisher");
  const reader = deviceFor("reader");

  const challenge = parseEnrollmentChallenge(caseStatement(statementCase("valid_enrollment_challenge")));
  const resignedChallenge = signEnrollmentChallenge({ ...challenge, signature_b64: "" }, publisher);
  assert.equal(resignedChallenge.signature_b64, challenge.signature_b64);
  assert.equal(
    reasonOf(() => signEnrollmentChallenge({ ...challenge, signature_b64: "" }, reader)),
    "did_signer_mismatch",
  );

  const proof = parseKeyBindingProof(caseStatement(statementCase("valid_jwe_reader_proof")));
  const resignedProof = signKeyBindingProof({ ...proof, signature_b64: "" }, reader);
  assert.equal(resignedProof.signature_b64, proof.signature_b64);

  const response = parseEnrollmentResponse(caseStatement(statementCase("valid_enrollment_response")));
  const resignedResponse = signEnrollmentResponse({ ...response, signature_b64: "" }, publisher);
  assert.equal(resignedResponse.signature_b64, response.signature_b64);
});

// ── Challenge/proof coupling ────────────────────────────────────────

test("a reader proof with a bound digest requires the named challenge", () => {
  const c = statementCase("valid_jwe_reader_proof");
  const proof = parseKeyBindingProof(caseStatement(c));
  const validation = caseValidation(c);
  assert.equal(
    reasonOf(() =>
      verifyKeyBindingProof(proof, {
        purpose: "jwe-reader",
        audienceDid: String(validation["expected_audience_did"]),
        ceremonyId: String(validation["expected_ceremony_id"]),
        group: String(validation["expected_group"]),
        now: String(validation["now"]),
      }),
    ),
    "challenge_missing",
  );
});

test("an unsolicited proof with a null digest verifies without a challenge", () => {
  const reader = deviceFor("reader");
  const c = statementCase("valid_jwe_reader_proof");
  const original = parseKeyBindingProof(caseStatement(c));
  const unsolicited = signKeyBindingProof(
    {
      ...original,
      binding: { ...original.binding, challenge_digest: null },
      signature_b64: "",
    },
    reader,
  );
  const validation = caseValidation(c);
  const binding = verifyJweKeyBinding(unsolicited, {
    audienceDid: String(validation["expected_audience_did"]),
    ceremonyId: String(validation["expected_ceremony_id"]),
    group: String(validation["expected_group"]),
    now: String(validation["now"]),
  });
  assert.equal(binding.challengeDigest, null);
  assert.equal(binding.principal.did, reader.did);

  // Supplying a challenge against a null digest is a binding failure.
  const challenge = parseEnrollmentChallenge(caseStatement(statementCase("valid_enrollment_challenge")));
  assert.equal(
    reasonOf(() =>
      verifyKeyBindingProof(unsolicited, {
        purpose: "jwe-reader",
        audienceDid: String(validation["expected_audience_did"]),
        ceremonyId: String(validation["expected_ceremony_id"]),
        group: String(validation["expected_group"]),
        now: String(validation["now"]),
        challenge,
      }),
    ),
    "binding_invalid",
  );
});

test("the challenge signature is checked before a reader proof is accepted", () => {
  const c = statementCase("valid_jwe_reader_proof");
  const proof = parseKeyBindingProof(caseStatement(c));
  const challengeStatement = { ...caseStatement(statementCase("valid_enrollment_challenge")) };
  challengeStatement["signature_b64"] = bytesToB64(new Uint8Array(64));
  const challenge = parseEnrollmentChallenge(challengeStatement);
  const validation = caseValidation(c);

  assert.equal(
    reasonOf(() =>
      verifyKeyBindingProof(proof, {
        purpose: "jwe-reader",
        audienceDid: String(validation["expected_audience_did"]),
        ceremonyId: String(validation["expected_ceremony_id"]),
        group: String(validation["expected_group"]),
        now: String(validation["now"]),
        challenge,
      }),
    ),
    "signature_invalid",
  );
});

test("verifyJweKeyBinding returns the verified key and digests", () => {
  const c = statementCase("valid_jwe_reader_proof");
  const proof = parseKeyBindingProof(caseStatement(c));
  const challenge = parseEnrollmentChallenge(caseStatement(statementCase("valid_enrollment_challenge")));
  const validation = caseValidation(c);
  const binding = verifyJweKeyBinding(proof, {
    audienceDid: String(validation["expected_audience_did"]),
    ceremonyId: String(validation["expected_ceremony_id"]),
    group: String(validation["expected_group"]),
    now: String(validation["now"]),
    challenge,
  });
  assert.equal(binding.publicKey.length, 32);
  assert.equal(binding.publicKeySha256, validation["expected_public_key_sha256"]);
  assert.equal(binding.proofDigest, keyBindingProofDigest(proof));
  assert.equal(binding.challengeDigest, validation["challenge_digest"]);
});

// ── HIBE reader proof creation ──────────────────────────────────────

test("createHibeReaderProof answers a hibe reader challenge verifiably", async () => {
  const c = statementCase("valid_hibe_reader_challenge");
  const challenge = parseEnrollmentChallenge(caseStatement(c));
  const reader = deviceFor("reader");
  const now = String(caseValidation(c)["now"]);

  const proof = await createHibeReaderProof(challenge, reader, { now });
  assert.equal(proof.purpose, "hibe-reader");
  assert.equal(proof.subject_did, reader.did);
  assert.equal(proof.audience_did, challenge.publisher_did);
  const principal = verifyKeyBindingProof(proof, {
    purpose: "hibe-reader",
    audienceDid: challenge.publisher_did,
    ceremonyId: challenge.ceremony_id,
    group: challenge.group,
    now,
    challenge,
  });
  assert.equal(principal.did, reader.did);

  const publisher = deviceFor("publisher");
  await assert.rejects(
    () => createHibeReaderProof(challenge, publisher, { now }),
    (err: unknown) => err instanceof TrustError && err.reason === "wrong_recipient",
  );
});
