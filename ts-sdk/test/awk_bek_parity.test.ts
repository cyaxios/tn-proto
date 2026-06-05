// Cross-impl parity for the AWK/BEK wrap chain.
//
// The vectors in fixtures/awk_bek_vectors.json are produced by the real
// Python `cryptography` stack (PBKDF2-SHA256 + AES-256-GCM) with the same
// AAD strings Python/browser use for the two WRAP layers. If TS unwraps
// them byte-identically, a TS CLI's passphrase derivation is wire-
// compatible with what the browser wrote and what Python reads.
//
// The two WRAP layers (AWK under credential key, BEK under AWK) are the
// load-bearing AAD-pinned crypto. The project BODY is a plain no-AAD
// `nonce||ct` frame (decryptBlobWithBek), mirroring Python — exercised
// by the live plumbing test, not here.

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { deriveBekFromMaterial } from "../src/vault/awk_bek.js";
import { bytesToB64 } from "../src/core/encoding.js";

const _dir = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(_dir, "fixtures/awk_bek_vectors.json"), "utf-8"));

test("TS derives the same BEK Python wrapped (passphrase -> credKey -> AWK -> BEK)", async () => {
  const bek = await deriveBekFromMaterial(V.passphrase, V.cred, V.wrapped_key);
  assert.equal(bytesToB64(bek), V.expected_bek_b64, "BEK must match the Python-wrapped value");
});

test("a wrong passphrase fails to unwrap the AWK (no silent garbage)", async () => {
  await assert.rejects(
    () => deriveBekFromMaterial("not the passphrase", V.cred, V.wrapped_key),
    /unwrap AWK failed/,
  );
});
