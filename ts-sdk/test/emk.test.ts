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
