// Profile-immutability conflict policy (TS side), mirroring the Python
// contract in python/tests/test_multi_ceremony.py::TestConflictPolicy.
//
// Profile is creation-time. When code passes a profile that disagrees
// with an existing on-disk ceremony yaml, the on-disk value wins and a
// warning is logged (operator authority) — logging never fails. An
// unknown profile name is misconfig at the call site and throws.
//
// See docs/spec-next/profiles.md.

import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { checkProfileConflict } from "../src/multi.js";

function withYaml(profile: string): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-profile-conflict-"));
  const path = join(dir, "tn.yaml");
  // Minimal shape: checkProfileConflict only reads ceremony.profile via
  // a line regex, so a two-line ceremony block is enough.
  writeFileSync(path, `ceremony:\n  profile: ${profile}\n`, "utf8");
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function captureWarn<T>(fn: () => T): { result: T; warnings: string[] } {
  const warnings: string[] = [];
  const orig = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };
  try {
    return { result: fn(), warnings };
  } finally {
    console.warn = orig;
  }
}

test("profile conflict: known mismatch warns (operator wins), does not throw", () => {
  const { path, cleanup } = withYaml("audit");
  try {
    const { warnings } = captureWarn(() => checkProfileConflict(path, "transaction"));
    assert.equal(warnings.length, 1, "expected exactly one warning");
    const w = warnings[0] as string;
    // Same operator-authority phrasing as the Python warning.
    assert.match(w, /profile conflict for/i);
    assert.match(w, /Operator authority/i);
    assert.match(w, /yaml wins/i);
    assert.match(w, /"transaction"/);
    assert.match(w, /"audit"/);
  } finally {
    cleanup();
  }
});

test("profile conflict: matching profile is silent", () => {
  const { path, cleanup } = withYaml("audit");
  try {
    const { warnings } = captureWarn(() => checkProfileConflict(path, "audit"));
    assert.equal(warnings.length, 0);
  } finally {
    cleanup();
  }
});

test("profile conflict: unknown profile name throws (misconfig, not a conflict)", () => {
  const { path, cleanup } = withYaml("audit");
  try {
    assert.throws(() => checkProfileConflict(path, "not_a_real_profile"), /unknown profile/);
  } finally {
    cleanup();
  }
});

test("profile conflict: no on-disk yaml is a no-op", () => {
  const missing = join(tmpdir(), "tn-profile-conflict-does-not-exist", "tn.yaml");
  const { warnings } = captureWarn(() => checkProfileConflict(missing, "transaction"));
  assert.equal(warnings.length, 0);
});
