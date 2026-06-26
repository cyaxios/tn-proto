// usingRust() truthfulness — Finding 2.
//
// `Tn.usingRust()` reports whether this ceremony's emit path is serviced
// by the attached Rust/WASM core. The wasm companion attaches lazily on
// the first emit, so the flag is false on a brand-new instance and flips
// true once anything has been emitted. Mirrors Python's `using_rust`.
//
// The module-level `tn.usingRust()` delegates to the default singleton
// and therefore throws before `tn.init()`. `usingRust` is a diagnostic
// verb, not an emit or read verb, so it keeps the pure `_requireDefault`
// throw form rather than auto-initing. (The emit verbs auto-mint and the
// read/watch verbs auto-load — see test/module_autoinit.test.ts.)

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as tn from "../src/index.js";
import { Tn } from "../src/tn.js";

test("module-level tn.usingRust() throws before tn.init()", () => {
  // This runs first in the file's process, where the default singleton
  // is still null. `usingRust` keeps the `_requireDefault` throw form
  // (it does not auto-init), so the call must be rejected.
  assert.throws(() => tn.usingRust(), /called before tn\.init\(\)/);
});

test("instance usingRust() is false before the first emit, true after", async () => {
  const t = await Tn.ephemeral({ stdout: false });
  try {
    assert.equal(t.usingRust(), false, "wasm should not be attached pre-emit");
    t.info("smoke.first", { ok: 1 });
    assert.equal(t.usingRust(), true, "wasm should be attached after one emit");
  } finally {
    await t.close();
  }
});

test("module-level tn.usingRust() is true after tn.init() + an emit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-usingrust-"));
  try {
    await tn.init(join(dir, "tn.yaml"), { stdout: false });
    // init alone does not attach wasm (no agent policy => no constructor
    // emit on a fresh ceremony), so the flag is still false here.
    assert.equal(tn.usingRust(), false, "no emit yet => pure-TS");
    tn.info("smoke.module", { ok: 1 });
    assert.equal(tn.usingRust(), true, "wasm attached after the first module-level emit");
  } finally {
    await tn.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
