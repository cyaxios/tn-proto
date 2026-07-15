import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { AdminNamespace } from "../src/admin/index.js";
import { jweDecrypt, jweSeal, okpPrivateJwk } from "../src/core/jwe.js";
import {
  evaluateJwksTrust,
  jwksDocumentFingerprint,
  jwksEncryptionRecipient,
  jwksKeySelectedEvent,
  jwksKeyFingerprint,
  parseTnJwks,
  selectActiveJwksEncryptionKey,
  TN_JWKS_KEY_SELECTED_EVENT,
  trustedJwksEncryptionRecipient,
  type TnJwksDocument,
  verifiedJweRecipientFromTrustedJwks,
} from "../src/core/jwks.js";
import { DeviceKey } from "../src/core/signing.js";
import { formatTrustTimestamp, sha256Digest } from "../src/core/trust.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";

const signingX = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const encX = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const retiringEncX = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);

function b64u(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function validJwks(): unknown {
  return {
    issuer: "did:key:zVaultExample",
    issued_at: "2026-07-14T00:00:00Z",
    expires_at: "2026-08-14T00:00:00Z",
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        kid: "vault-signing-2026-07",
        use: "sig",
        alg: "EdDSA",
        x: signingX,
        tn_status: "active",
      },
      {
        kty: "OKP",
        crv: "X25519",
        kid: "vault-enc-2026-07",
        use: "enc",
        alg: "ECDH-ES+A256KW",
        x: encX,
        tn_status: "active",
      },
      {
        kty: "OKP",
        crv: "X25519",
        kid: "vault-enc-2026-06",
        use: "enc",
        alg: "ECDH-ES+A256KW",
        x: retiringEncX,
        tn_status: "retiring",
      },
    ],
  };
}

test("jwks: parses TN key set and selects active encryption key", () => {
  const jwks = parseTnJwks(validJwks());
  const selected = selectActiveJwksEncryptionKey(jwks);

  assert.equal(jwks.issuer, "did:key:zVaultExample");
  assert.equal(selected.kid, "vault-enc-2026-07");
  assert.equal(selected.jwk.alg, "ECDH-ES+A256KW");
  assert.match(selected.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(selected.fingerprint, jwksKeyFingerprint(selected.jwk));
});

test("jwks: rejects mismatched algorithm and key role", () => {
  const value = validJwks() as TnJwksDocument;
  value.keys[1] = {
    kty: "OKP",
    crv: "Ed25519",
    kid: "vault-enc-bad",
    use: "enc",
    alg: "ECDH-ES+A256KW",
    x: encX,
  };

  assert.throws(() => parseTnJwks(value), /encryption keys must use X25519/);
});

test("jwks: rejects duplicate kids and invalid key bytes", () => {
  const duplicate = validJwks() as TnJwksDocument;
  duplicate.keys[2] = {
    kty: "OKP",
    crv: "X25519",
    kid: "vault-enc-2026-07",
    use: "enc",
    alg: "ECDH-ES+A256KW",
    x: retiringEncX,
  };
  assert.throws(() => parseTnJwks(duplicate), /duplicate kid/);

  const shortKey = validJwks() as TnJwksDocument;
  shortKey.keys[1] = {
    kty: "OKP",
    crv: "X25519",
    kid: "vault-enc-short",
    use: "enc",
    alg: "ECDH-ES+A256KW",
    x: "AQID",
  };
  assert.throws(() => parseTnJwks(shortKey), /32 raw public-key bytes/);
});

test("jwks: rejects ambiguous active encryption keys", () => {
  const value = validJwks() as TnJwksDocument;
  value.keys[2] = {
    kty: "OKP",
    crv: "X25519",
    kid: "vault-enc-2026-08",
    use: "enc",
    alg: "ECDH-ES+A256KW",
    x: retiringEncX,
    tn_status: "active",
  };

  const jwks = parseTnJwks(value);
  assert.throws(() => selectActiveJwksEncryptionKey(jwks), /multiple active encryption keys/);
});

test("jwks: validates declared key fingerprints", () => {
  const parsed = parseTnJwks(validJwks());
  const selected = selectActiveJwksEncryptionKey(parsed);
  const withFingerprint = validJwks() as TnJwksDocument;
  withFingerprint.keys[1] = {
    ...selected.jwk,
    tn_fingerprint: selected.fingerprint,
  };

  assert.equal(selectActiveJwksEncryptionKey(parseTnJwks(withFingerprint)).fingerprint, selected.fingerprint);

  const badFingerprint = validJwks() as TnJwksDocument;
  badFingerprint.keys[1] = {
    ...selected.jwk,
    tn_fingerprint: "sha256:" + "0".repeat(64),
  };
  assert.throws(() => parseTnJwks(badFingerprint), /tn_fingerprint does not match/);
});

test("jwks: selected encryption key converts to a JWE recipient with kid", () => {
  const selected = selectActiveJwksEncryptionKey(parseTnJwks(validJwks()));
  const recipient = jwksEncryptionRecipient(selected);

  assert.equal(recipient.kid, "vault-enc-2026-07");
  assert.equal(recipient.publicKey.length, 32);
});

test("jwks: tofu trust creates a reusable pin", () => {
  const jwks = parseTnJwks(validJwks());
  const decision = evaluateJwksTrust(jwks, { policy: "tofu" });

  assert.equal(decision.trusted, true);
  assert.equal(decision.reason, "pin-created");
  assert.deepEqual(decision.pin, {
    issuer: "did:key:zVaultExample",
    jwksFingerprint: jwksDocumentFingerprint(jwks),
  });
});

test("jwks: pinned trust accepts exact issuer and fingerprint", () => {
  const jwks = parseTnJwks(validJwks());
  const first = evaluateJwksTrust(jwks, { policy: "tofu" });
  assert.ok(first.pin);

  const decision = evaluateJwksTrust(jwks, { policy: "pinned", pinned: first.pin });
  assert.equal(decision.trusted, true);
  assert.equal(decision.reason, "pin-match");
});

test("jwks: pinned trust rejects missing pin, issuer mismatch, and fingerprint mismatch", () => {
  const jwks = parseTnJwks(validJwks());

  assert.equal(evaluateJwksTrust(jwks, { policy: "pinned" }).reason, "pin-missing");
  assert.equal(
    evaluateJwksTrust(jwks, {
      policy: "pinned",
      pinned: { issuer: "did:key:zOtherVault", jwksFingerprint: jwksDocumentFingerprint(jwks) },
    }).reason,
    "issuer-mismatch",
  );
  assert.equal(
    evaluateJwksTrust(jwks, {
      policy: "pinned",
      pinned: { issuer: jwks.issuer, jwksFingerprint: "sha256:" + "0".repeat(64) },
    }).reason,
    "fingerprint-mismatch",
  );
});

test("jwks: hosted and did-bound policies are explicit placeholders", () => {
  const jwks = parseTnJwks(validJwks());

  for (const policy of ["hosted", "did_bound"] as const) {
    const decision = evaluateJwksTrust(jwks, { policy });
    assert.equal(decision.trusted, false);
    assert.equal(decision.policy, policy);
    assert.equal(decision.reason, "policy-unsupported");
  }
});

test("jwks: composed helper rejects unsupported trust policies clearly", () => {
  assert.throws(
    () => trustedJwksEncryptionRecipient(validJwks(), { policy: "hosted" }),
    /key set is not trusted \(policy-unsupported\)/,
  );
});

test("jwks: trusted encryption recipient composes parse, trust, selection, and recipient", () => {
  const first = trustedJwksEncryptionRecipient(validJwks(), { policy: "tofu" });
  assert.equal(first.issuer, "did:key:zVaultExample");
  assert.equal(first.kid, "vault-enc-2026-07");
  assert.equal(first.publicKey.length, 32);
  assert.match(first.keyFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.match(first.jwksFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.ok(first.trust.pin);

  const pinned = trustedJwksEncryptionRecipient(validJwks(), {
    policy: "pinned",
    pinned: first.trust.pin,
  });
  assert.equal(pinned.trust.reason, "pin-match");
  assert.equal(pinned.kid, first.kid);
});

test("jwks: trusted encryption recipient rejects untrusted pins before selection", () => {
  assert.throws(
    () =>
      trustedJwksEncryptionRecipient(validJwks(), {
        policy: "pinned",
        pinned: {
          issuer: "did:key:zVaultExample",
          jwksFingerprint: "sha256:" + "0".repeat(64),
        },
      }),
    /key set is not trusted \(fingerprint-mismatch\)/,
  );
});

test("jwks: trusted encryption recipient seals JWE with kid and decrypts", async () => {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  const value = validJwks() as TnJwksDocument;
  value.keys[1] = {
    kty: "OKP",
    crv: "X25519",
    kid: "vault-enc-live",
    use: "enc",
    alg: "ECDH-ES+A256KW",
    x: b64u(publicKey),
    tn_status: "active",
  };

  const recipient = trustedJwksEncryptionRecipient(value, { policy: "tofu" });
  const plaintext = enc('{"ok":true}');
  const blob = await jweSeal([recipient], plaintext);
  const parsed = JSON.parse(dec(blob)) as {
    recipients: Array<{ header?: { kid?: string } }>;
  };

  assert.equal(parsed.recipients[0]?.header?.kid, "vault-enc-live");
  assert.deepEqual(await jweDecrypt(okpPrivateJwk(publicKey, privateKey), blob), plaintext);
});

test("jwks: key-selected event payload is stable and audit friendly", () => {
  const recipient = trustedJwksEncryptionRecipient(validJwks(), { policy: "tofu" });
  const event = jwksKeySelectedEvent(recipient, {
    selectedAt: "2026-07-14T00:00:00.000Z",
    jwksUrl: "https://vault.example/.well-known/tn/jwks.json",
    signingKid: "vault-signing-2026-07",
    signingKeyFingerprint: "sha256:" + "1".repeat(64),
  });

  assert.deepEqual(event, {
    issuer: "did:key:zVaultExample",
    encryption_kid: "vault-enc-2026-07",
    encryption_key_fingerprint: recipient.keyFingerprint,
    jwks_fingerprint: recipient.jwksFingerprint,
    trust_policy: "tofu",
    trust_reason: "pin-created",
    selected_at: "2026-07-14T00:00:00.000Z",
    jwks_url: "https://vault.example/.well-known/tn/jwks.json",
    signing_kid: "vault-signing-2026-07",
    signing_key_fingerprint: "sha256:" + "1".repeat(64),
  });
});

test("jwks: key-selected event type is stable", () => {
  assert.equal(TN_JWKS_KEY_SELECTED_EVENT, "tn.jwks.key_selected");
});

test("jwks: trusted recipient can become a verified JWE fingerprint binding", () => {
  const reader = DeviceKey.fromSeed(new Uint8Array(32).fill(0x41));
  const publisher = DeviceKey.fromSeed(new Uint8Array(32).fill(0x42));
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  const jwks: TnJwksDocument = {
    issuer: reader.did,
    keys: [
      {
        kty: "OKP",
        crv: "X25519",
        kid: "partners-jwe-current",
        use: "enc",
        alg: "ECDH-ES+A256KW",
        x: b64u(publicKey),
        tn_status: "active",
      },
    ],
  };

  const trusted = trustedJwksEncryptionRecipient(jwks, { policy: "tofu" });
  const binding = verifiedJweRecipientFromTrustedJwks(trusted, {
    scope: {
      audienceDid: publisher.did,
      ceremonyId: "ceremony-jwks",
      group: "partners",
      now: formatTrustTimestamp(Date.now() * 1000),
      ttlMs: 10 * 60_000,
    },
    evidence: "operator pinned the JWKS document fingerprint out-of-band",
  });

  assert.equal(binding.readerDid, reader.did);
  assert.equal(binding.audienceDid, publisher.did);
  assert.equal(binding.ceremonyId, "ceremony-jwks");
  assert.equal(binding.group, "partners");
  assert.equal(binding.publicKeySha256, sha256Digest(publicKey));
  assert.equal(binding.evidence.kind, "fingerprint-pin");
  if (binding.evidence.kind === "fingerprint-pin") {
    assert.equal(binding.evidence.expectedFingerprint, sha256Digest(publicKey));
    assert.equal(binding.evidence.verificationMethod, "jwks-document-fingerprint");
  }
});

test("jwks: verified recipient plugs into jwe admin registration", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-jwks-admin-"));
  const publisher = NodeRuntime.init(join(dir, "tn.yaml"), { cipher: "jwe" });
  const reader = DeviceKey.fromSeed(new Uint8Array(32).fill(0x43));
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  const jwks: TnJwksDocument = {
    issuer: reader.did,
    keys: [
      {
        kty: "OKP",
        crv: "X25519",
        kid: "default-jwe-current",
        use: "enc",
        alg: "ECDH-ES+A256KW",
        x: b64u(publicKey),
        tn_status: "active",
      },
    ],
  };
  const trusted = trustedJwksEncryptionRecipient(jwks, { policy: "tofu" });
  const verifiedRecipient = verifiedJweRecipientFromTrustedJwks(trusted, {
    scope: {
      audienceDid: publisher.did,
      ceremonyId: publisher.config.ceremonyId,
      group: "default",
      now: formatTrustTimestamp(Date.now() * 1000),
      ttlMs: 10 * 60_000,
    },
  });

  const added = await new AdminNamespace(publisher).addRecipient("default", {
    verifiedRecipient,
  });

  assert.equal(added.verified, true);
  assert.equal(added.recipientDid, reader.did);
  assert.equal(added.publicKeySha256, sha256Digest(publicKey));
  assert.equal(added.bindingDigest, verifiedRecipient.bindingDigest);

  const trust = JSON.parse(
    readFileSync(join(publisher.config.keystorePath, "trust", "jwe_recipients.v1.json"), "utf8"),
  ) as Record<string, unknown>;
  const recipients = trust["recipients"] as Record<string, Record<string, Record<string, unknown>>>;
  const record = recipients["default"]![reader.did]!;
  assert.equal(record["verified"], true);
  assert.equal(record["binding_digest"], verifiedRecipient.bindingDigest);
  assert.equal(record["evidence_kind"], "fingerprint-pin");

  publisher.close();
});
