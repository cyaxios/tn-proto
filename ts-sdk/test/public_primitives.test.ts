import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  AuthenticationFailedError,
  LimitExceededError,
  MalformedError,
  NotEntitledError,
  btn,
  extractX25519KeyAgreement,
  jweActivationReferenceDigest,
  jweRecipientFromAuthenticatedDidDocument,
  jweRecipientFromFingerprintPin,
  jwe,
  validateVerifiedJweRecipient,
  verifyJweEnrollmentSource,
} from "../src/index.js";
import {
  btn as browserBtn,
  extractX25519KeyAgreement as extractBrowserX25519KeyAgreement,
  jweActivationReferenceDigest as browserJweActivationReferenceDigest,
  jwe as browserJwe,
  verifyJweEnrollmentSource as verifyBrowserJweEnrollmentSource,
} from "../src/index.browser.js";

test("package roots expose BTN and JWE as sibling namespaces", () => {
  assert.equal(typeof btn.setup, "function");
  assert.equal(typeof jwe.keygen, "function");
  assert.equal(typeof browserBtn.setup, "function");
  assert.equal(typeof browserJwe.keygen, "function");
});

test("package root exposes stable primitive error classes", () => {
  for (const ErrorClass of [
    NotEntitledError,
    MalformedError,
    AuthenticationFailedError,
    LimitExceededError,
  ]) {
    assert.equal(typeof ErrorClass, "function");
  }
});

test("node and browser roots expose the authenticated JWE enrollment adapter", () => {
  assert.equal(typeof verifyJweEnrollmentSource, "function");
  assert.equal(typeof verifyBrowserJweEnrollmentSource, "function");
  assert.equal(typeof extractX25519KeyAgreement, "function");
  assert.equal(typeof extractBrowserX25519KeyAgreement, "function");
  assert.equal(typeof jweRecipientFromAuthenticatedDidDocument, "function");
  assert.equal(typeof jweRecipientFromFingerprintPin, "function");
  assert.equal(typeof validateVerifiedJweRecipient, "function");
  assert.equal(typeof jweActivationReferenceDigest, "function");
  assert.equal(typeof browserJweActivationReferenceDigest, "function");
});

test("package metadata exposes direct BTN and JWE subpaths", () => {
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.exports["./btn"].import, "./dist/btn.js");
  assert.equal(packageJson.exports["./btn"].types, "./dist/btn.d.ts");
  assert.equal(packageJson.exports["./jwe"].import, "./dist/jwe.js");
  assert.equal(packageJson.exports["./jwe"].types, "./dist/jwe.d.ts");
});
