// RFC 7516 JWE cipher (src/core/jwe.ts) — TS<->TS round-trips and the
// cross-impl gate: a record sealed by the Python SDK (real JWEGroupCipher
// output, checked in as a fixture) must open here by standard conformance.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { jweDecrypt, jweSeal, okpPrivateJwk } from "../src/core/jwe.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

function keypair(): { priv: Uint8Array; pub: Uint8Array } {
  const priv = x25519.utils.randomPrivateKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

test("jwe: seal/open round-trips, with and without a marker", async () => {
  const r = keypair();
  const jwk = okpPrivateJwk(r.pub, r.priv);
  const pt = enc(JSON.stringify({ x: 1, note: "hello jwe" }));

  // plain seal (no marker) — no aad member
  const plain = await jweSeal([r.pub], pt);
  assert.equal("aad" in JSON.parse(dec(plain)), false);
  assert.deepEqual(await jweDecrypt(jwk, plain), pt);

  // marker seal — bound as the JWE aad member
  const aad = enc("policy=finra-oba");
  const gov = await jweSeal([r.pub], pt, aad);
  assert.equal("aad" in JSON.parse(dec(gov)), true);
  assert.deepEqual(await jweDecrypt(jwk, gov, aad), pt);
  // wrong / absent marker fails closed (null, never plaintext)
  assert.equal(await jweDecrypt(jwk, gov, enc("policy=wrong")), null);
  assert.equal(await jweDecrypt(jwk, gov), null);
});

test("jwe: multi-recipient — each opens, a non-recipient does not", async () => {
  const a = keypair();
  const b = keypair();
  const stranger = keypair();
  const pt = enc('{"v":42}');
  const blob = await jweSeal([a.pub, b.pub], pt);
  assert.equal(JSON.parse(dec(blob)).recipients.length, 2);
  assert.deepEqual(await jweDecrypt(okpPrivateJwk(a.pub, a.priv), blob), pt);
  assert.deepEqual(await jweDecrypt(okpPrivateJwk(b.pub, b.priv), blob), pt);
  assert.equal(await jweDecrypt(okpPrivateJwk(stranger.pub, stranger.priv), blob), null);
});

test("jwe: opens a record sealed by the Python SDK (cross-impl gate)", async () => {
  const fx = JSON.parse(readFileSync(join(HERE, "fixtures", "jwe_from_python.json"), "utf8"));
  const blob = enc(JSON.stringify(fx.jwe));
  const out = await jweDecrypt(fx.reader_jwk, blob, fx.aad ? enc(fx.aad) : undefined);
  assert.ok(out, "python-sealed record did not open");
  assert.equal(dec(out!), fx.plaintext);
  // the marker is bound: opening with no/other aad fails
  assert.equal(await jweDecrypt(fx.reader_jwk, blob), null);
});

test("jwe: garbage and non-recipient inputs fail closed, never throw", async () => {
  const r = keypair();
  const jwk = okpPrivateJwk(r.pub, r.priv);
  assert.equal(await jweDecrypt(jwk, enc("not json")), null);
  assert.equal(await jweDecrypt(jwk, enc('{"recipients":[]}')), null);
});
