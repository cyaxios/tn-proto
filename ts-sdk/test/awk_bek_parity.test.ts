// Cross-impl parity for the AWK/BEK whole-body vault crypto.
//
// The vectors in fixtures/awk_bek_vectors.json are produced by the real
// Python `cryptography` stack (PBKDF2-SHA256 + AES-256-GCM) with the same
// AAD strings the browser/Python use. If TS unwraps them byte-identically,
// a TS CLI restore is wire-compatible with what the browser wrote and what
// Python reads — which is the whole point of porting on the supported
// model instead of the deprecated per-file sealing.

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { deriveBekFromMaterial, decryptBody, encryptBody } from "../src/vault/awk_bek.js";
import { bytesToB64 } from "../src/core/encoding.js";

const _dir = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(_dir, "fixtures/awk_bek_vectors.json"), "utf-8"));

test("TS derives the same BEK Python wrapped (passphrase -> credKey -> AWK -> BEK)", async () => {
  const bek = await deriveBekFromMaterial(V.passphrase, V.cred, V.wrapped_key);
  assert.equal(bytesToB64(bek), V.expected_bek_b64, "BEK must match the Python-wrapped value");
});

test("TS decrypts a body Python encrypted under the BEK (AAD tn-vault-body-v1)", async () => {
  const bek = await deriveBekFromMaterial(V.passphrase, V.cred, V.wrapped_key);
  const body = await decryptBody(bek, V.body_blob);
  assert.equal(bytesToB64(body), V.expected_body_b64, "decrypted body must match Python plaintext");
});

test("a wrong passphrase fails to unwrap the AWK (no silent garbage)", async () => {
  await assert.rejects(
    () => deriveBekFromMaterial("not the passphrase", V.cred, V.wrapped_key),
    /unwrap AWK failed/,
  );
});

test("encryptBody round-trips through decryptBody under the same BEK", async () => {
  const bek = await deriveBekFromMaterial(V.passphrase, V.cred, V.wrapped_key);
  const pt = new TextEncoder().encode("PK round-trip body bytes");
  const blob = await encryptBody(bek, pt);
  const back = await decryptBody(bek, blob);
  assert.equal(bytesToB64(back), bytesToB64(pt));
});
