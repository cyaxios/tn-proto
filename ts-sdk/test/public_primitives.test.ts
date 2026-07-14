import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  AuthenticationFailedError,
  LimitExceededError,
  MalformedError,
  NotEntitledError,
  btn,
  jwe,
} from "../src/index.js";
import { btn as browserBtn, jwe as browserJwe } from "../src/index.browser.js";

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

test("package metadata exposes direct BTN and JWE subpaths", () => {
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.exports["./btn"].import, "./dist/btn.js");
  assert.equal(packageJson.exports["./btn"].types, "./dist/btn.d.ts");
  assert.equal(packageJson.exports["./jwe"].import, "./dist/jwe.js");
  assert.equal(packageJson.exports["./jwe"].types, "./dist/jwe.d.ts");
});
