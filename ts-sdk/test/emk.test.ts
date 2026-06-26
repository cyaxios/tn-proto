import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  importEmk,
  deriveEmkFromPassphrase,
  emkFromPrfOutput,
  makeVerifier,
  checkVerifier,
  wrapKeystoreSecret,
  unwrapKeystoreSecret,
  wrapBytes,
  unwrapBytes,
} from "../src/core/emk.js";
import { randomBytes } from "../src/core/encoding.js";

test("importEmk + makeVerifier + checkVerifier round-trip", async () => {
  const emk = await importEmk(randomBytes(32));
  const verifier = await makeVerifier(emk);
  const ok = await checkVerifier(emk, verifier);
  assert.equal(ok, true);
});

test("checkVerifier returns false for wrong EMK", async () => {
  const emk1 = await importEmk(randomBytes(32));
  const emk2 = await importEmk(randomBytes(32));
  const verifier = await makeVerifier(emk1);
  const ok = await checkVerifier(emk2, verifier);
  assert.equal(ok, false);
});

test("wrapKeystoreSecret + unwrapKeystoreSecret round-trip", async () => {
  const emk = await importEmk(randomBytes(32));
  const secret = "ceremonial-passphrase-42";
  const wrapped = await wrapKeystoreSecret(emk, secret);
  const recovered = await unwrapKeystoreSecret(emk, wrapped);
  assert.equal(recovered, secret);
});

test("deriveEmkFromPassphrase + checkVerifier round-trip", async () => {
  const salt = randomBytes(16);
  const emkA = await deriveEmkFromPassphrase("pass-1", salt, 100_000);
  const emkB = await deriveEmkFromPassphrase("pass-1", salt, 100_000);
  const verifier = await makeVerifier(emkA);
  // Same passphrase + same salt + same iterations → same key → checkVerifier passes.
  const ok = await checkVerifier(emkB, verifier);
  assert.equal(ok, true);
});

test("emkFromPrfOutput produces a usable EMK", async () => {
  const prfOutput = randomBytes(32);
  const emk = await emkFromPrfOutput(prfOutput);
  const verifier = await makeVerifier(emk);
  const ok = await checkVerifier(emk, verifier);
  assert.equal(ok, true);
});

test("wrap/unwrap with custom AAD round-trips", async () => {
  const emk = await importEmk(randomBytes(32));
  const aad = new TextEncoder().encode("tn-vault-body-v1");
  const secret = "ceremonial-passphrase-with-aad";
  const wrapped = await wrapKeystoreSecret(emk, secret, aad);
  const recovered = await unwrapKeystoreSecret(emk, wrapped, aad);
  assert.equal(recovered, secret);
});

test("unwrap fails when AAD doesn't match", async () => {
  const emk = await importEmk(randomBytes(32));
  const aad1 = new TextEncoder().encode("tn-vault-body-v1");
  const aad2 = new TextEncoder().encode("tn-vault-body-v2");
  const wrapped = await wrapKeystoreSecret(emk, "secret", aad1);
  await assert.rejects(() => unwrapKeystoreSecret(emk, wrapped, aad2));
});

test("wrapBytes/unwrapBytes round-trips arbitrary binary payloads", async () => {
  const emk = await importEmk(randomBytes(32));
  const plaintext = new Uint8Array([0, 1, 2, 0xff, 0xfe, 0xfd, 42]);
  const wrapped = await wrapBytes(emk, plaintext);
  const recovered = await unwrapBytes(emk, wrapped);
  assert.deepEqual(Array.from(recovered), Array.from(plaintext));
});

test("wrapBytes/unwrapBytes with custom AAD round-trips", async () => {
  const emk = await importEmk(randomBytes(32));
  const aad = new TextEncoder().encode("tn-vault-body-v1");
  const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
  const wrapped = await wrapBytes(emk, plaintext, aad);
  const recovered = await unwrapBytes(emk, wrapped, aad);
  assert.deepEqual(Array.from(recovered), Array.from(plaintext));
});

test("unwrapBytes throws on AAD mismatch", async () => {
  const emk = await importEmk(randomBytes(32));
  const aad1 = new TextEncoder().encode("aad-1");
  const aad2 = new TextEncoder().encode("aad-2");
  const wrapped = await wrapBytes(emk, new Uint8Array([1, 2, 3]), aad1);
  await assert.rejects(() => unwrapBytes(emk, wrapped, aad2));
});
