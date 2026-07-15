import { strict as assert } from "node:assert";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { vaultCmd } from "../src/cli/vault.js";
import { jwksDocumentFingerprint, parseTnJwks, type TnJwksDocument } from "../src/core/jwks.js";
import type { VaultJwksConfig } from "../src/runtime/config.js";

function b64u(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function buildJwks(publicKey: Uint8Array): TnJwksDocument {
  return parseTnJwks({
    issuer: "did:key:zVaultCliExample",
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

function sink(): { text: () => string; writer: Pick<typeof process.stdout, "write"> } {
  let captured = "";
  return {
    text: () => captured,
    writer: {
      write(chunk: string | Uint8Array): boolean {
        captured += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
        return true;
      },
    },
  };
}

function fetchJson(value: unknown, events?: string[]): typeof fetch {
  return (async (url: string | URL | Request) => {
    events?.push(`fetch:${String(url)}`);
    return new Response(JSON.stringify(value), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
}

test("vault cli jwks inspect fetches and prints fingerprints without opening Tn", async () => {
  const jwks = buildJwks(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
  const out = sink();
  let opened = false;

  const code = await vaultCmd(
    ["node", "tn-js", "vault", "jwks", "inspect", "--url", "https://vault.example/jwks.json"],
    {
      fetchImpl: fetchJson(jwks),
      stdout: out.writer,
      openTn: async () => {
        opened = true;
        throw new Error("inspect must not open Tn");
      },
    },
  );

  assert.equal(code, 0);
  assert.equal(opened, false);
  assert.deepEqual(JSON.parse(out.text()), {
    ok: true,
    verb: "vault.jwks.inspect",
    issuer: "did:key:zVaultCliExample",
    jwks_url: "https://vault.example/jwks.json",
    jwks_fingerprint: jwksDocumentFingerprint(jwks),
    active_encryption_kid: "vault-enc-2026-07",
    active_encryption_key_fingerprint: /^sha256:[0-9a-f]{64}$/.test(
      JSON.parse(out.text()).active_encryption_key_fingerprint,
    )
      ? JSON.parse(out.text()).active_encryption_key_fingerprint
      : "",
  });
});

test("vault cli jwks pin verifies fetched JWKS before opening and recording trust", async () => {
  const jwks = buildJwks(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
  const fingerprint = jwksDocumentFingerprint(jwks);
  const out = sink();
  const events: string[] = [];
  const pinned: VaultJwksConfig[] = [];

  const code = await vaultCmd(
    [
      "node",
      "tn-js",
      "vault",
      "jwks",
      "pin",
      "--yaml",
      "demo.yaml",
      "--issuer",
      jwks.issuer,
      "--url",
      "https://vault.example/jwks.json",
      "--fingerprint",
      fingerprint,
    ],
    {
      fetchImpl: fetchJson(jwks, events),
      stdout: out.writer,
      openTn: async (yamlPath) => {
        events.push(`open:${yamlPath}`);
        return {
          close() {
            events.push("close");
          },
          vault: {
            link() {
              throw new Error("not used");
            },
            unlink() {
              throw new Error("not used");
            },
            pinJwks(config: VaultJwksConfig) {
              events.push("pin");
              pinned.push(config);
              return {
                receipt: { eventId: "evt-pin", rowHash: "sha256:" + "1".repeat(64) },
                targetYamlPath: "demo.yaml",
                jwks: config,
              };
            },
            rotateJwks() {
              throw new Error("not used");
            },
          },
        };
      },
    },
  );

  assert.equal(code, 0);
  assert.deepEqual(events, ["fetch:https://vault.example/jwks.json", "open:demo.yaml", "pin", "close"]);
  assert.equal(pinned[0]?.fingerprint, fingerprint);
  assert.equal(JSON.parse(out.text()).verb, "vault.jwks.pin");
});

test("vault cli jwks rotate verifies fetched JWKS before opening and recording rotation", async () => {
  const jwks = buildJwks(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
  const fingerprint = jwksDocumentFingerprint(jwks);
  const previous = "sha256:" + "a".repeat(64);
  const out = sink();
  const events: string[] = [];
  const rotations: Array<{ jwks: VaultJwksConfig; previous: string; rotatedAt?: string }> = [];

  const code = await vaultCmd(
    [
      "node",
      "tn-js",
      "vault",
      "jwks",
      "rotate",
      "--yaml",
      "demo.yaml",
      "--issuer",
      jwks.issuer,
      "--url",
      "https://vault.example/jwks.json",
      "--fingerprint",
      fingerprint,
      "--previous",
      previous,
      "--rotated-at",
      "2026-07-15T00:00:00Z",
    ],
    {
      fetchImpl: fetchJson(jwks, events),
      stdout: out.writer,
      openTn: async (yamlPath) => {
        events.push(`open:${yamlPath}`);
        return {
          close() {
            events.push("close");
          },
          vault: {
            link() {
              throw new Error("not used");
            },
            unlink() {
              throw new Error("not used");
            },
            pinJwks() {
              throw new Error("not used");
            },
            rotateJwks(
              config: VaultJwksConfig,
              previousJwksFingerprint: string,
              opts?: { rotatedAt?: string },
            ) {
              events.push("rotate");
              rotations.push({
                jwks: config,
                previous: previousJwksFingerprint,
                ...(opts?.rotatedAt === undefined ? {} : { rotatedAt: opts.rotatedAt }),
              });
              return {
                receipt: { eventId: "evt-rotate", rowHash: "sha256:" + "2".repeat(64) },
                targetYamlPath: "demo.yaml",
                jwks: config,
              };
            },
          },
        };
      },
    },
  );

  assert.equal(code, 0);
  assert.deepEqual(events, ["fetch:https://vault.example/jwks.json", "open:demo.yaml", "rotate", "close"]);
  assert.equal(rotations[0]?.jwks.fingerprint, fingerprint);
  assert.equal(rotations[0]?.previous, previous);
  assert.equal(rotations[0]?.rotatedAt, "2026-07-15T00:00:00Z");
  assert.equal(JSON.parse(out.text()).verb, "vault.jwks.rotate");
});

test("vault cli jwks pin rejects mismatched fingerprints before opening Tn", async () => {
  const jwks = buildJwks(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
  const events: string[] = [];

  await assert.rejects(
    () =>
      vaultCmd(
        [
          "node",
          "tn-js",
          "vault",
          "jwks",
          "pin",
          "--yaml",
          "demo.yaml",
          "--issuer",
          jwks.issuer,
          "--url",
          "https://vault.example/jwks.json",
          "--fingerprint",
          "sha256:" + "0".repeat(64),
        ],
        {
          fetchImpl: fetchJson(jwks, events),
          openTn: async () => {
            events.push("open");
            throw new Error("pin mismatch must not open Tn");
          },
        },
      ),
    /key set is not trusted \(fingerprint-mismatch\)/,
  );

  assert.deepEqual(events, ["fetch:https://vault.example/jwks.json"]);
});
