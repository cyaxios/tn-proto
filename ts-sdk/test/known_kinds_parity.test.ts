// KNOWN_KINDS is a hand-maintained TS constant (browser-safe: no top-level
// wasm call at import). This pins it in lockstep with the Rust core's
// manifestKnownKinds() so the TS list and the Rust list can never drift.
// Runs in Node, where the nodejs-target wasm self-initializes on import.

import { test } from "node:test";
import assert from "node:assert/strict";

import { KNOWN_KINDS } from "../src/core/tnpkg.js";
import { manifestKnownKinds } from "../src/raw.js";

test("KNOWN_KINDS matches the Rust core's manifestKnownKinds()", () => {
  const fromWasm = (manifestKnownKinds() as string[]).slice().sort();
  const fromTs = [...KNOWN_KINDS].sort();
  assert.deepEqual(
    fromTs,
    fromWasm,
    "KNOWN_KINDS drifted from the Rust core — update src/core/tnpkg.ts to match",
  );
});
