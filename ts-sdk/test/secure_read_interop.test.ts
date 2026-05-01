// Cross-language byte-compare tests for `client.secureRead()` flat output
// and `tn.agents` pre-encryption canonical bytes.
//
// Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
// section 5.4.
//
// Each language commits two fixtures (`secure_read_canonical.json` +
// `tn_agents_pre_encryption.json`). This module:
//
//   1. Builds the same two outputs locally from the canonical scenario
//      (via the helpers in `fixtures/secure_read_canonical_scenario.ts`).
//   2. Loads the OTHER two languages' fixtures.
//   3. Asserts byte-identity for both.
//
// If a fixture is missing, the cross-consume tests skip rather than fail
// — the fixtures are built explicitly via each language's builder.

import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildAdminEventsCanonical,
  buildSecureReadCanonical,
  buildTnAgentsPreEncryption,
  canonicalJsonBytes,
} from "./fixtures/secure_read_canonical_scenario.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Repo layout: tn-protocol/ts-sdk/test/secure_read_interop.test.ts
// Repo root for fixtures = tn-protocol/.
const PROTO_ROOT = resolve(__dirname, "..", "..");

const SECURE_READ_NAME = "secure_read_canonical.json";
const PRE_ENC_NAME = "tn_agents_pre_encryption.json";
const ADMIN_NAME = "admin_events_canonical.json";

const PYTHON_FIXTURE_DIR = resolve(PROTO_ROOT, "python", "tests", "fixtures");
const RUST_FIXTURE_DIR = resolve(
  PROTO_ROOT,
  "crypto",
  "tn-core",
  "tests",
  "fixtures",
);
const TS_FIXTURE_DIR = resolve(__dirname, "fixtures");

function bufferEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function readBytes(path: string): Uint8Array {
  // readFileSync returns Buffer; coerce to Uint8Array view of the same bytes.
  const buf = readFileSync(path);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

// --------------------------------------------------------------------------
// Sentinel: fail loud if any cross-language fixture is missing or empty.
// The byte-compare tests below skip individually when a sibling-language
// fixture is absent. This sentinel ensures the full set exists on a
// healthy `main` so a rename, move, or zero-byte fixture surfaces as a
// hard failure rather than silent no-op.
// --------------------------------------------------------------------------

test("required byte-compare fixtures present", () => {
  const expected: string[] = [
    // Python-produced fixtures.
    resolve(PYTHON_FIXTURE_DIR, "python_admin_snapshot.tnpkg"),
    resolve(PYTHON_FIXTURE_DIR, SECURE_READ_NAME),
    resolve(PYTHON_FIXTURE_DIR, PRE_ENC_NAME),
    resolve(PYTHON_FIXTURE_DIR, ADMIN_NAME),
    // Rust-produced fixtures.
    resolve(RUST_FIXTURE_DIR, "rust_admin_snapshot.tnpkg"),
    resolve(RUST_FIXTURE_DIR, SECURE_READ_NAME),
    resolve(RUST_FIXTURE_DIR, PRE_ENC_NAME),
    resolve(RUST_FIXTURE_DIR, ADMIN_NAME),
    // TS-produced fixtures.
    resolve(TS_FIXTURE_DIR, "ts_admin_snapshot.tnpkg"),
    resolve(TS_FIXTURE_DIR, SECURE_READ_NAME),
    resolve(TS_FIXTURE_DIR, PRE_ENC_NAME),
    resolve(TS_FIXTURE_DIR, ADMIN_NAME),
  ];
  const missing: string[] = [];
  const empty: string[] = [];
  for (const p of expected) {
    if (!existsSync(p)) {
      missing.push(p);
      continue;
    }
    const buf = readFileSync(p);
    if (buf.length === 0) empty.push(p);
  }
  assert.deepEqual(
    missing,
    [],
    `missing byte-compare fixtures: ${JSON.stringify(missing)}`,
  );
  assert.deepEqual(
    empty,
    [],
    `empty byte-compare fixtures (zero bytes): ${JSON.stringify(empty)}`,
  );
});

// --------------------------------------------------------------------------
// Local sanity: building from the same scenario reproduces the committed
// TS fixture byte-for-byte. Catches drift in the projection function.
// --------------------------------------------------------------------------

test("TS local secureRead matches committed fixture", () => {
  const tsPath = resolve(TS_FIXTURE_DIR, SECURE_READ_NAME);
  if (!existsSync(tsPath)) {
    console.warn(`(skipping — TS fixture not built: ${tsPath})`);
    return;
  }
  const local = canonicalJsonBytes(buildSecureReadCanonical());
  const onDisk = readBytes(tsPath);
  assert.ok(
    bufferEq(local, onDisk),
    "TS's local secureRead output drifted from the committed fixture. " +
      "Re-run `node --import tsx test/fixtures/build_secure_read_fixtures.ts`.",
  );
});

test("TS local tn.agents pre_encryption matches committed fixture", () => {
  const tsPath = resolve(TS_FIXTURE_DIR, PRE_ENC_NAME);
  if (!existsSync(tsPath)) {
    console.warn(`(skipping — TS fixture not built: ${tsPath})`);
    return;
  }
  const local = canonicalJsonBytes(buildTnAgentsPreEncryption());
  const onDisk = readBytes(tsPath);
  assert.ok(
    bufferEq(local, onDisk),
    "TS's local tn.agents pre-encryption output drifted from the committed " +
      "fixture.",
  );
});

// --------------------------------------------------------------------------
// Cross-language byte-compare: load the Python + Rust fixtures and assert
// byte-identity against the TS-produced output.
// --------------------------------------------------------------------------

test("Python secureRead byte-compare", () => {
  const p = resolve(PYTHON_FIXTURE_DIR, SECURE_READ_NAME);
  if (!existsSync(p)) {
    console.warn(`(skipping — Python fixture missing: ${p})`);
    return;
  }
  const py = readBytes(p);
  const ts = canonicalJsonBytes(buildSecureReadCanonical());
  assert.ok(
    bufferEq(ts, py),
    "Python-produced secureRead fixture differs from TS output. " +
      "This is a cross-language wire drift; identify and fix the divergence.",
  );
});

test("Rust secureRead byte-compare", () => {
  const p = resolve(RUST_FIXTURE_DIR, SECURE_READ_NAME);
  if (!existsSync(p)) {
    console.warn(`(skipping — Rust fixture missing: ${p})`);
    return;
  }
  const rust = readBytes(p);
  const ts = canonicalJsonBytes(buildSecureReadCanonical());
  assert.ok(
    bufferEq(ts, rust),
    "Rust-produced secureRead fixture differs from TS output. " +
      "This is a cross-language wire drift; identify and fix the divergence.",
  );
});

test("Python tn.agents pre_encryption byte-compare", () => {
  const p = resolve(PYTHON_FIXTURE_DIR, PRE_ENC_NAME);
  if (!existsSync(p)) {
    console.warn(`(skipping — Python fixture missing: ${p})`);
    return;
  }
  const py = readBytes(p);
  const ts = canonicalJsonBytes(buildTnAgentsPreEncryption());
  assert.ok(
    bufferEq(ts, py),
    "Python-produced tn.agents pre-encryption fixture differs from TS " +
      "output. This is a cross-language wire drift; identify and fix the " +
      "divergence.",
  );
});

test("Rust tn.agents pre_encryption byte-compare", () => {
  const p = resolve(RUST_FIXTURE_DIR, PRE_ENC_NAME);
  if (!existsSync(p)) {
    console.warn(`(skipping — Rust fixture missing: ${p})`);
    return;
  }
  const rust = readBytes(p);
  const ts = canonicalJsonBytes(buildTnAgentsPreEncryption());
  assert.ok(
    bufferEq(ts, rust),
    "Rust-produced tn.agents pre-encryption fixture differs from TS " +
      "output. This is a cross-language wire drift; identify and fix the " +
      "divergence.",
  );
});

// --------------------------------------------------------------------------
// Per-admin-event canonical-bytes byte-compare. One entry per admin
// event_type in the catalog. Pins the canonical encoding for every admin
// event shape across Python / Rust / TS — would have caught any drift on
// `tn.agents.policy_published` (list-valued + multiline string fields)
// before it shipped.
// --------------------------------------------------------------------------

test("TS local admin_events matches committed fixture", () => {
  const tsPath = resolve(TS_FIXTURE_DIR, ADMIN_NAME);
  if (!existsSync(tsPath)) {
    console.warn(`(skipping — TS fixture not built: ${tsPath})`);
    return;
  }
  const local = canonicalJsonBytes(buildAdminEventsCanonical());
  const onDisk = readBytes(tsPath);
  assert.ok(
    bufferEq(local, onDisk),
    "TS's local admin_events output drifted from the committed fixture. " +
      "Re-run `node --import tsx test/fixtures/build_secure_read_fixtures.ts`.",
  );
});

test("Python admin_events byte-compare", () => {
  const p = resolve(PYTHON_FIXTURE_DIR, ADMIN_NAME);
  if (!existsSync(p)) {
    console.warn(`(skipping — Python fixture missing: ${p})`);
    return;
  }
  const py = readBytes(p);
  const ts = canonicalJsonBytes(buildAdminEventsCanonical());
  assert.ok(
    bufferEq(ts, py),
    "Python-produced admin_events fixture differs from TS output. " +
      "One of the catalog event types canonicalizes differently between " +
      "the two SDKs — diff the fixtures field by field to find which " +
      "event_type drifted.",
  );
});

test("Rust admin_events byte-compare", () => {
  const p = resolve(RUST_FIXTURE_DIR, ADMIN_NAME);
  if (!existsSync(p)) {
    console.warn(`(skipping — Rust fixture missing: ${p})`);
    return;
  }
  const rust = readBytes(p);
  const ts = canonicalJsonBytes(buildAdminEventsCanonical());
  assert.ok(
    bufferEq(ts, rust),
    "Rust-produced admin_events fixture differs from TS output. " +
      "One of the catalog event types canonicalizes differently between " +
      "the two SDKs — diff the fixtures field by field to find which " +
      "event_type drifted.",
  );
});
