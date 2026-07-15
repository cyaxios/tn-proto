import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";

import { x25519 } from "@noble/curves/ed25519";

import { jweDecrypt, okpPrivateJwk } from "../src/core/jwe.js";
import {
  jwksDocumentFingerprint,
  parseTnJwks,
  TN_JWKS_KEY_SELECTED_EVENT,
  type TnJwksDocument,
} from "../src/core/jwks.js";
import {
  checkVaultJwksPinAgainstAdminState,
  inspectVaultJwks,
  jwksPinnedEventFields,
  jwksRotatedEventFields,
  pinnedTrustFromVaultJwksConfig,
  sealForTrustedVaultJwks,
  trustedVaultJwksRecipient,
} from "../src/vault/jwks.js";
import { VaultNamespace } from "../src/vault/index.js";
import type { VaultJwksConfig } from "../src/runtime/config.js";
import type { AdminJwksPinState } from "../src/core/types.js";

function b64u(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function buildJwks(publicKey: Uint8Array): TnJwksDocument {
  return parseTnJwks({
    issuer: "did:key:zVaultExample",
    issued_at: "2026-07-14T00:00:00Z",
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        kid: "vault-signing-2026-07",
        use: "sig",
        alg: "EdDSA",
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        tn_status: "active",
      },
      {
        kty: "OKP",
        crv: "X25519",
        kid: "vault-enc-2026-07",
        use: "enc",
        alg: "ECDH-ES+A256KW",
        x: b64u(publicKey),
        tn_status: "active",
      },
    ],
  });
}

function fetchJson(value: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(value), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as typeof fetch;
}

function writeMinimalYaml(): string {
  const dir = mkdtempSync(join(tmpdir(), "tn-vault-jwks-ns-"));
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(
    yamlPath,
    `ceremony:
  id: jwks_ns
  cipher: btn
keystore:
  path: ./keys
device:
  device_identity: did:key:zDevice
groups:
  default:
    cipher: btn
`,
    "utf8",
  );
  return yamlPath;
}

test("vault jwks: config pin converts to pinned trust input", () => {
  const jwks: VaultJwksConfig = {
    issuer: "did:key:zVaultExample",
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: "sha256:" + "a".repeat(64),
  };

  assert.deepEqual(pinnedTrustFromVaultJwksConfig(jwks), {
    issuer: "did:key:zVaultExample",
    jwksFingerprint: "sha256:" + "a".repeat(64),
  });
});

test("vault jwks: admin event builders use stable signed field names", () => {
  const jwks: VaultJwksConfig = {
    issuer: "did:key:zVaultExample",
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: "sha256:" + "a".repeat(64),
    pinnedAt: "2026-07-14T00:00:00Z",
  };

  assert.deepEqual(jwksPinnedEventFields(jwks), {
    issuer: "did:key:zVaultExample",
    jwks_url: "https://vault.example/.well-known/tn/jwks.json",
    jwks_fingerprint: "sha256:" + "a".repeat(64),
    pinned_at: "2026-07-14T00:00:00Z",
  });
  assert.deepEqual(
    jwksRotatedEventFields(jwks, "sha256:" + "b".repeat(64), {
      rotatedAt: "2026-07-15T00:00:00Z",
    }),
    {
      issuer: "did:key:zVaultExample",
      jwks_url: "https://vault.example/.well-known/tn/jwks.json",
      previous_jwks_fingerprint: "sha256:" + "b".repeat(64),
      jwks_fingerprint: "sha256:" + "a".repeat(64),
      rotated_at: "2026-07-15T00:00:00Z",
    },
  );
});

test("vault jwks: YAML cache can be checked against signed admin state", () => {
  const yaml: VaultJwksConfig = {
    issuer: "did:key:zVaultExample",
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: "sha256:" + "a".repeat(64),
  };
  const admin: AdminJwksPinState = {
    issuer: yaml.issuer,
    jwksUrl: yaml.url,
    jwksFingerprint: yaml.fingerprint,
    pinnedAt: "2026-07-14T00:00:00Z",
    rotatedAt: null,
    previousJwksFingerprint: null,
    signingKid: null,
    signingKeyFingerprint: null,
  };

  assert.equal(checkVaultJwksPinAgainstAdminState(undefined, { jwksPins: [] }).status, "unconfigured");
  assert.equal(checkVaultJwksPinAgainstAdminState(yaml, { jwksPins: [] }).status, "admin-missing");
  assert.equal(checkVaultJwksPinAgainstAdminState(undefined, { jwksPins: [admin] }).status, "yaml-missing");
  assert.equal(checkVaultJwksPinAgainstAdminState(yaml, { jwksPins: [admin] }).status, "match");
  assert.equal(
    checkVaultJwksPinAgainstAdminState(
      { ...yaml, fingerprint: "sha256:" + "c".repeat(64) },
      { jwksPins: [admin] },
    ).status,
    "mismatch",
  );
});

test("vault namespace: pinJwks writes YAML and emits pinned event", async () => {
  const yamlPath = writeMinimalYaml();
  const emits: Array<{ level: string; eventType: string; fields: Record<string, unknown> }> = [];
  const rt = {
    config: { yamlPath },
    emit(level: string, eventType: string, fields: Record<string, unknown>) {
      emits.push({ level, eventType, fields });
      return { eventId: "evt-pin", rowHash: "sha256:" + "1".repeat(64), sequence: 1 };
    },
  } as never;
  const ns = new VaultNamespace(rt);

  const result = await ns.pinJwks({
    issuer: "did:key:zVaultExample",
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: "sha256:" + "a".repeat(64),
    pinnedAt: "2026-07-14T00:00:00Z",
  });

  const doc = parseYaml(readFileSync(result.targetYamlPath, "utf8")) as {
    vault?: { jwks?: Record<string, unknown> };
  };
  assert.equal(doc.vault?.jwks?.issuer, "did:key:zVaultExample");
  assert.equal(doc.vault?.jwks?.fingerprint, "sha256:" + "a".repeat(64));
  assert.equal(emits[0]?.eventType, "tn.jwks.pinned");
  assert.equal(emits[0]?.fields.jwks_fingerprint, "sha256:" + "a".repeat(64));
});

test("vault namespace: rotateJwks writes YAML and emits rotated event", async () => {
  const yamlPath = writeMinimalYaml();
  const emits: Array<{ level: string; eventType: string; fields: Record<string, unknown> }> = [];
  const rt = {
    config: { yamlPath },
    emit(level: string, eventType: string, fields: Record<string, unknown>) {
      emits.push({ level, eventType, fields });
      return { eventId: "evt-rotate", rowHash: "sha256:" + "2".repeat(64), sequence: 2 };
    },
  } as never;
  const ns = new VaultNamespace(rt);

  const result = await ns.rotateJwks(
    {
      issuer: "did:key:zVaultExample",
      url: "https://vault.example/.well-known/tn/jwks.json",
      fingerprint: "sha256:" + "b".repeat(64),
    },
    "sha256:" + "a".repeat(64),
    { rotatedAt: "2026-07-15T00:00:00Z" },
  );

  const doc = parseYaml(readFileSync(result.targetYamlPath, "utf8")) as {
    vault?: { jwks?: Record<string, unknown> };
  };
  assert.equal(doc.vault?.jwks?.fingerprint, "sha256:" + "b".repeat(64));
  assert.equal(emits[0]?.eventType, "tn.jwks.rotated");
  assert.equal(emits[0]?.fields.previous_jwks_fingerprint, "sha256:" + "a".repeat(64));
});

test("vault jwks: inspect fetches without trusting and reports fingerprints", async () => {
  const privateKey = x25519.utils.randomPrivateKey();
  const jwks = buildJwks(x25519.getPublicKey(privateKey));

  const result = await inspectVaultJwks({
    url: "https://vault.example/.well-known/tn/jwks.json",
    fetchImpl: fetchJson(jwks),
  });

  assert.equal(result.issuer, "did:key:zVaultExample");
  assert.equal(result.jwksFingerprint, jwksDocumentFingerprint(jwks));
  assert.equal(result.activeEncryptionKid, "vault-enc-2026-07");
  assert.match(result.activeEncryptionKeyFingerprint, /^sha256:[0-9a-f]{64}$/);
});

test("vault jwks: fetches pinned JWKS and selects trusted encryption recipient", async () => {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  const jwks = buildJwks(publicKey);
  const cfg: VaultJwksConfig = {
    issuer: jwks.issuer,
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: jwksDocumentFingerprint(jwks),
  };

  const result = await trustedVaultJwksRecipient({
    jwks: cfg,
    fetchImpl: fetchJson(jwks),
  });

  assert.equal(result.recipient.issuer, "did:key:zVaultExample");
  assert.equal(result.recipient.kid, "vault-enc-2026-07");
  assert.equal(result.event.jwks_url, cfg.url);
  assert.equal(result.event.trust_policy, "pinned");
  assert.equal(result.event.trust_reason, "pin-match");
});

test("vault jwks: rejects fetched JWKS when pin does not match", async () => {
  const privateKey = x25519.utils.randomPrivateKey();
  const jwks = buildJwks(x25519.getPublicKey(privateKey));

  await assert.rejects(
    () =>
      trustedVaultJwksRecipient({
        jwks: {
          issuer: jwks.issuer,
          url: "https://vault.example/.well-known/tn/jwks.json",
          fingerprint: "sha256:" + "0".repeat(64),
        },
        fetchImpl: fetchJson(jwks),
      }),
    /key set is not trusted \(fingerprint-mismatch\)/,
  );
});

test("vault jwks: seal helper emits key-selected audit fields and decrypts", async () => {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  const jwks = buildJwks(publicKey);
  const cfg: VaultJwksConfig = {
    issuer: jwks.issuer,
    url: "https://vault.example/.well-known/tn/jwks.json",
    fingerprint: jwksDocumentFingerprint(jwks),
  };
  const emitted: Array<{ eventType: string; fields: Record<string, unknown> }> = [];

  const result = await sealForTrustedVaultJwks(utf8('{"secret":true}'), {
    jwks: cfg,
    fetchImpl: fetchJson(jwks),
    selectedAt: "2026-07-14T00:00:00.000Z",
    recorder: {
      async infoAsync(eventType, fields = {}) {
        emitted.push({ eventType, fields });
      },
    },
  });

  assert.equal(result.event.encryption_kid, "vault-enc-2026-07");
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0]?.eventType, TN_JWKS_KEY_SELECTED_EVENT);
  assert.equal(emitted[0]?.fields.encryption_kid, "vault-enc-2026-07");

  const jwe = JSON.parse(text(result.ciphertext)) as {
    recipients: Array<{ header?: { kid?: string } }>;
  };
  assert.equal(jwe.recipients[0]?.header?.kid, "vault-enc-2026-07");
  assert.deepEqual(
    await jweDecrypt(okpPrivateJwk(publicKey, privateKey), result.ciphertext),
    utf8('{"secret":true}'),
  );
});
