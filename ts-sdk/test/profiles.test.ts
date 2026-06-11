/**
 * Profile catalog tests — mirrors python/tests/test_profiles.py.
 *
 * Pins the catalog shape so a change that silently flips a property
 * fails in CI before it lands. Any intentional change here MUST
 * update the docstring in src/profiles.ts AND the Python catalog
 * in lockstep.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
  DEFAULT_PROFILE,
  allProfileNames,
  getProfile,
  hasReplaySurface,
  isKnownProfile,
} from "../src/profiles.js";

test("all profile names are listed", () => {
  assert.deepEqual(new Set(allProfileNames()), new Set([
    "transaction",
    "audit",
    "secure_log",
    "telemetry",
  ]));
});

test("default profile is transaction", () => {
  assert.equal(DEFAULT_PROFILE, "transaction");
});

test("every profile encrypts (the floor)", () => {
  for (const name of allProfileNames()) {
    assert.equal(getProfile(name).encrypts, true,
      `${name} must encrypt — encryption is the unconditional floor`);
  }
});

test("transaction profile properties", () => {
  const p = getProfile("transaction");
  assert.equal(p.signs, true);
  assert.equal(p.chains, true);
  assert.equal(p.flush, "fsync");
  assert.equal(p.default_sink, "file_rotating");
  assert.equal(hasReplaySurface(p), true);
});

test("audit profile properties", () => {
  const p = getProfile("audit");
  assert.equal(p.signs, true);
  assert.equal(p.chains, true);
  assert.equal(p.flush, "buffered");
  assert.equal(p.default_sink, "file_rotating");
  assert.equal(hasReplaySurface(p), true);
});

test("secure_log profile properties", () => {
  const p = getProfile("secure_log");
  assert.equal(p.signs, true);
  assert.equal(p.chains, false); // entries stand alone
  assert.equal(p.flush, "buffered");
  assert.equal(p.default_sink, "file_rotating");
  assert.equal(hasReplaySurface(p), true);
});

test("telemetry profile properties", () => {
  // Fast-as-stdlib-logger profile: drop signing for speed,
  // encryption stays on (floor).
  const p = getProfile("telemetry");
  assert.equal(p.signs, false);
  assert.equal(p.chains, false);
  assert.equal(p.flush, "async");
  assert.equal(p.default_sink, "stdout");
});

test("telemetry has no replay surface", () => {
  assert.equal(hasReplaySurface("telemetry"), false);
});

test("unknown profile throws with catalog list", () => {
  assert.throws(
    () => getProfile("not_a_real_profile"),
    /unknown profile/,
  );
});

test("isKnownProfile narrows correctly", () => {
  assert.equal(isKnownProfile("transaction"), true);
  assert.equal(isKnownProfile("not_a_real_profile"), false);
});
