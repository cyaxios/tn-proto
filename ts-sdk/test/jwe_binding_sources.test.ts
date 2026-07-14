import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { canonicalize } from "../src/core/canonical.js";
import {
  extractX25519KeyAgreement,
  jweRecipientFromExternallyAuthenticatedDidDocument,
  jweRecipientFromExternallyAuthenticatedDidResolution,
  jweRecipientFromFingerprintPin,
  validateVerifiedJweRecipient,
} from "../src/core/jwe_binding.js";
import { didKeyToX25519Pub } from "../src/core/recipient_seal.js";
import { DeviceKey } from "../src/core/signing.js";
import { sha256Digest, TrustError } from "../src/core/trust.js";

const READER = DeviceKey.fromSeed(new Uint8Array(32).fill(0x31));
const PUBLISHER = DeviceKey.fromSeed(new Uint8Array(32).fill(0x32));
const DID = READER.did;
const METHOD = `${DID}#jwe-1`;
const SCOPE = {
  audienceDid: PUBLISHER.did,
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
  const key = didKeyToX25519Pub(DID);
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

  const binding = jweRecipientFromExternallyAuthenticatedDidDocument({
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
  if (binding.evidence.kind === "did-document") {
    assert.throws(
      () =>
        validateVerifiedJweRecipient({
          ...binding,
          evidence: {
            ...binding.evidence,
            verificationMethodId: "did:example:attacker#jwe-1",
          },
        }),
      /verification method is outside the reader DID/,
    );
  }
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
      jweRecipientFromExternallyAuthenticatedDidDocument({
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
      jweRecipientFromExternallyAuthenticatedDidDocument({
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

test("DID extraction skips a well-formed non-X25519 keyAgreement method", () => {
  const key = new Uint8Array(32).fill(0x46);
  const document = {
    id: DID,
    keyAgreement: [
      {
        id: `${DID}#ed25519-1`,
        type: "JsonWebKey2020",
        controller: DID,
        publicKeyJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: Buffer.from(new Uint8Array(32).fill(0x47)).toString("base64url"),
        },
      },
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
  };
  assert.deepEqual(extractX25519KeyAgreement(document, DID).publicKey, key);
});

test("explicit DID method selection ignores unrelated malformed methods but rejects duplicates", () => {
  const key = didKeyToX25519Pub(DID);
  const selected = {
    id: METHOD,
    type: "JsonWebKey2020",
    controller: DID,
    publicKeyJwk: {
      kty: "OKP",
      crv: "X25519",
      x: Buffer.from(key).toString("base64url"),
    },
  };
  const unrelated = {
    id: `${DID}#broken-x25519`,
    type: "JsonWebKey2020",
    controller: DID,
    publicKeyJwk: { kty: "OKP", crv: "X25519", x: "not-base64url!" },
  };
  const document = { id: DID, keyAgreement: [unrelated, selected] };
  assert.deepEqual(extractX25519KeyAgreement(document, DID, METHOD).publicKey, key);
  assert.throws(
    () => extractX25519KeyAgreement({ id: DID, keyAgreement: [selected, selected] }, DID, METHOD),
    /duplicate keyAgreement verification method/,
  );
});

test("X25519KeyAgreementKey2019 accepts canonical raw publicKeyBase58", () => {
  const key = didKeyToX25519Pub(DID);
  const document = {
    id: DID,
    keyAgreement: [
      {
        id: METHOD,
        type: "X25519KeyAgreementKey2019",
        controller: DID,
        publicKeyBase58: base58(key),
      },
    ],
  };
  assert.deepEqual(extractX25519KeyAgreement(document, DID, METHOD).publicKey, key);
  assert.throws(
    () =>
      extractX25519KeyAgreement(
        {
          id: DID,
          keyAgreement: [{ ...document.keyAgreement[0], publicKeyBase58: `z${base58(key)}` }],
        },
        DID,
        METHOD,
      ),
    /must not use a multibase prefix/,
  );
});

test("DID-document normalization rejects an arbitrary X25519 key", () => {
  const arbitrary = new Uint8Array(32).fill(0x55);
  const document = {
    id: DID,
    keyAgreement: [
      {
        id: METHOD,
        type: "JsonWebKey2020",
        controller: DID,
        publicKeyJwk: {
          kty: "OKP",
          crv: "X25519",
          x: Buffer.from(arbitrary).toString("base64url"),
        },
      },
    ],
  };
  assert.throws(
    () =>
      jweRecipientFromExternallyAuthenticatedDidDocument({
        document,
        expectedDid: DID,
        verificationMethodId: METHOD,
        scope: SCOPE,
        evidence: {
          resolver: "caller-owned authenticated DID method",
          resolutionDigest: sha256Digest(new TextEncoder().encode("authenticated result")),
          documentDigest: sha256Digest(canonicalize(document)),
        },
      }),
    /not derived from the asserted Ed25519 did:key/,
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
    assert.throws(
      () =>
        validateVerifiedJweRecipient({
          ...binding,
          evidence: {
            ...binding.evidence,
            expectedFingerprint: sha256Digest(new Uint8Array(32).fill(0x48)),
          },
        }),
      /fingerprint evidence does not match/,
    );
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

  const lowOrder = new Uint8Array(32);
  lowOrder[0] = 1;
  assert.throws(
    () =>
      jweRecipientFromFingerprintPin({
        readerDid: DID,
        publicKey: lowOrder,
        scope: SCOPE,
        pin: {
          expectedFingerprint: sha256Digest(lowOrder),
          verifiedBy: "operator:alice",
          verificationMethod: "voice call",
          evidence,
        },
      }),
    /must not be low order/,
  );
});

test("a forged resolved key cannot claim a verification method from another DID", () => {
  const key = didKeyToX25519Pub(DID);
  assert.throws(
    () =>
      jweRecipientFromExternallyAuthenticatedDidResolution(
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
