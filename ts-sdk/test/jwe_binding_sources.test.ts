import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { canonicalize } from "../src/core/canonical.js";
import {
  extractX25519KeyAgreement,
  jweRecipientFromAuthenticatedDidDocument,
  jweRecipientFromDidResolution,
  jweRecipientFromFingerprintPin,
} from "../src/core/jwe_binding.js";
import { sha256Digest, TrustError } from "../src/core/trust.js";

const DID = "did:example:reader";
const METHOD = `${DID}#jwe-1`;
const SCOPE = {
  audienceDid: "did:example:publisher",
  ceremonyId: "ceremony-1",
  group: "partners",
  now: "2027-01-15T08:00:00Z",
  ttlMs: 10 * 60_000,
};

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58(value: Uint8Array): string {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) zeros += 1;
  const digits: number[] = [];
  for (let i = zeros; i < value.length; i += 1) {
    let carry = value[i]!;
    for (let j = 0; j < digits.length; j += 1) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(zeros) +
    digits
      .reverse()
      .map((digit) => B58[digit])
      .join("")
  );
}

function multibase(key: Uint8Array): string {
  return `z${base58(new Uint8Array([0xec, 0x01, ...key]))}`;
}

test("authenticated DID document JWK extraction normalizes with resolver evidence", () => {
  const key = new Uint8Array(32).fill(0x52);
  const document = {
    id: DID,
    verificationMethod: [
      {
        id: METHOD,
        type: "JsonWebKey2020",
        controller: DID,
        publicKeyJwk: {
          kty: "OKP",
          crv: "X25519",
          x: Buffer.from(key).toString("base64url"),
        },
      },
    ],
    keyAgreement: [METHOD],
  };
  const documentDigest = sha256Digest(canonicalize(document));
  const resolved = extractX25519KeyAgreement(document, DID, METHOD);
  assert.deepEqual(resolved.publicKey, key);

  const binding = jweRecipientFromAuthenticatedDidDocument({
    document,
    expectedDid: DID,
    verificationMethodId: METHOD,
    scope: SCOPE,
    evidence: {
      resolver: "did:example resolver with method verification",
      resolutionDigest: sha256Digest(new TextEncoder().encode("resolution-result")),
      documentDigest,
    },
  });
  assert.equal(binding.readerDid, DID);
  assert.equal(binding.publicKeySha256, sha256Digest(key));
  assert.equal(binding.evidence.kind, "did-document");
  assert.ok(binding.bindingDigest.startsWith("sha256:"));
});

test("multibase keyAgreement works and ambiguous or unauthenticated documents fail closed", () => {
  const first = new Uint8Array(32).fill(0x41);
  const second = new Uint8Array(32).fill(0x42);
  const method = (id: string, key: Uint8Array) => ({
    id,
    type: "Multikey",
    controller: DID,
    publicKeyMultibase: multibase(key),
  });
  const document = {
    id: DID,
    keyAgreement: [method(METHOD, first), method(`${DID}#jwe-2`, second)],
  };
  assert.throws(() => extractX25519KeyAgreement(document, DID), /ambiguous/);
  assert.deepEqual(extractX25519KeyAgreement(document, DID, METHOD).publicKey, first);

  const documentDigest = sha256Digest(canonicalize(document));
  assert.throws(
    () =>
      jweRecipientFromAuthenticatedDidDocument({
        document,
        expectedDid: DID,
        verificationMethodId: METHOD,
        scope: SCOPE,
        evidence: {
          resolver: "",
          resolutionDigest: sha256Digest(new TextEncoder().encode("resolution-result")),
          documentDigest,
        },
      }),
    (error: unknown) => error instanceof TrustError && error.reason === "binding_invalid",
  );
  assert.throws(
    () =>
      jweRecipientFromAuthenticatedDidDocument({
        document,
        expectedDid: DID,
        verificationMethodId: METHOD,
        scope: SCOPE,
        evidence: {
          resolver: "authenticated resolver",
          resolutionDigest: sha256Digest(new TextEncoder().encode("resolution-result")),
          documentDigest: sha256Digest(new TextEncoder().encode("different document")),
        },
      }),
    /document_digest.*exact DID document/,
  );
});

test("fingerprint pin requires an exact key digest and retains evidence by digest", () => {
  const key = new Uint8Array(32).fill(0x43);
  const evidence = "ticket-1234";
  const binding = jweRecipientFromFingerprintPin({
    readerDid: DID,
    publicKey: key,
    scope: SCOPE,
    pin: {
      expectedFingerprint: sha256Digest(key),
      verifiedBy: "operator:alice",
      verificationMethod: "voice call plus QR comparison",
      evidence,
    },
  });
  assert.equal(binding.evidence.kind, "fingerprint-pin");
  if (binding.evidence.kind === "fingerprint-pin") {
    assert.equal(binding.evidence.evidenceDigest, sha256Digest(new TextEncoder().encode(evidence)));
    assert.equal("evidence" in binding.evidence, false);
  }

  assert.throws(
    () =>
      jweRecipientFromFingerprintPin({
        readerDid: DID,
        publicKey: key,
        scope: SCOPE,
        pin: {
          expectedFingerprint: sha256Digest(new Uint8Array(32).fill(0x44)),
          verifiedBy: "operator:alice",
          verificationMethod: "voice call",
          evidence,
        },
      }),
    /pinned fingerprint does not match/,
  );
});

test("a forged resolved key cannot claim a verification method from another DID", () => {
  const key = new Uint8Array(32).fill(0x45);
  assert.throws(
    () =>
      jweRecipientFromDidResolution(
        {
          did: DID,
          verificationMethodId: "did:example:attacker#jwe-1",
          publicKey: key,
          publicKeySha256: sha256Digest(key),
        },
        SCOPE,
        {
          resolver: "authenticated resolver",
          resolutionDigest: sha256Digest(new TextEncoder().encode("resolution-result")),
          documentDigest: sha256Digest(new TextEncoder().encode("document")),
        },
      ),
    /verification method does not belong to the resolved DID/,
  );
});
