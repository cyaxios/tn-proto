// Phase A + B smoke test. Loads the wasm-pack Node bundle, exercises the
// full exported surface with deterministic inputs, and writes outputs to
// `js_out.json` so the Python side can diff them against the tn_core
// (PyO3) reducer and the pure-Python `tn` module primitives.
//
// Usage:
//   node test/node_smoke.mjs
//   # then:
//   python test/py_cross_check.py
// or call the driver:
//   bash test/run_interop.sh

import { readFileSync, writeFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  adminReduce,
  adminCatalogKinds,
  adminValidateEmit,
  canonicalBytes,
  canonicalJson,
  deriveDidKey,
  deviceKeyFromSeed,
  signMessage,
  verifyDid,
  signatureB64,
  deriveGroupIndexKey,
  indexToken,
  zeroHash,
  computeRowHash,
  buildEnvelope,
} from "../pkg/tn_wasm.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(readFileSync(join(here, "fixtures.json"), "utf8"));

const b64 = (buf) => Buffer.from(buf).toString("base64");
const hex = (buf) => Buffer.from(buf).toString("hex");

const report = { admin: [], crypto: {} };
let passed = 0;
let failed = 0;

function assertEq(name, actual, expected) {
  if (actual === expected) {
    console.log(`[ok]   ${name}`);
    passed += 1;
  } else {
    console.log(`[fail] ${name}`);
    console.log(`       expected: ${expected}`);
    console.log(`       actual:   ${actual}`);
    failed += 1;
  }
}

// ---------------------------------------------------------------------------
// Admin catalog (Phase A)
// ---------------------------------------------------------------------------

for (const { name, envelope } of fixtures) {
  try {
    const delta = adminReduce(envelope);
    report.admin.push({ name, ok: true, delta });
    console.log(`[ok]   admin.${name}  kind=${delta.kind}`);
    passed += 1;
  } catch (e) {
    report.admin.push({ name, ok: false, error: String(e) });
    console.log(`[fail] admin.${name}  error=${e}`);
    failed += 1;
  }
}

const kinds = adminCatalogKinds();
if (Array.isArray(kinds) && kinds.length >= 10) {
  console.log(`[ok]   adminCatalogKinds returned ${kinds.length} entries`);
  passed += 1;
} else {
  console.log(`[fail] adminCatalogKinds returned ${kinds?.length}`);
  failed += 1;
}

try {
  adminValidateEmit("tn.ceremony.init", {
    ceremony_id: "x",
    cipher: "btn",
    device_did: "did:key:z6Mk...",
    created_at: "2026-04-23T12:00:00Z",
  });
  console.log("[ok]   adminValidateEmit accepted valid ceremony_init");
  passed += 1;
} catch (e) {
  console.log(`[fail] adminValidateEmit threw unexpectedly: ${e}`);
  failed += 1;
}

try {
  adminValidateEmit("tn.ceremony.init", { ceremony_id: "x" });
  console.log("[fail] adminValidateEmit should have thrown on missing fields");
  failed += 1;
} catch {
  console.log("[ok]   adminValidateEmit rejected missing fields");
  passed += 1;
}

// ---------------------------------------------------------------------------
// Canonical JSON (Phase B)
// ---------------------------------------------------------------------------

const canonicalCases = [
  { input: { b: 2, a: 1 }, expected: '{"a":1,"b":2}' },
  { input: { nested: { z: 1, y: 2 }, a: [3, 1, 2] }, expected: '{"a":[3,1,2],"nested":{"y":2,"z":1}}' },
  { input: { unicode: "ünïcödé" }, expected: '{"unicode":"ünïcödé"}' },
  { input: { null_val: null, bool_t: true, bool_f: false }, expected: '{"bool_f":false,"bool_t":true,"null_val":null}' },
  { input: { quote: 'he said "hi"\ttab' }, expected: '{"quote":"he said \\"hi\\"\\ttab"}' },
];

report.crypto.canonical = [];
for (const { input, expected } of canonicalCases) {
  const actual = canonicalJson(input);
  report.crypto.canonical.push({ input, output: actual });
  assertEq(`canonicalJson ${JSON.stringify(input)}`, actual, expected);
}

// ---------------------------------------------------------------------------
// Signing: deterministic seeds
// ---------------------------------------------------------------------------

// Two deterministic seeds: 32 zero bytes and a 0..31 ramp.
const seedZero = new Uint8Array(32);
const seedRamp = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) seedRamp[i] = i;

const dkZero = deviceKeyFromSeed(seedZero);
const dkRamp = deviceKeyFromSeed(seedRamp);

report.crypto.signing = [];
for (const [name, seed, dk] of [
  ["zero_seed", seedZero, dkZero],
  ["ramp_seed", seedRamp, dkRamp],
]) {
  const pkBytes = Buffer.from(dk.public_key_b64, "base64");
  const derivedDid = deriveDidKey(pkBytes);
  assertEq(`deriveDidKey matches ${name}`, derivedDid, dk.did);

  const message = Buffer.from(`hello ${name}`);
  const sig = signMessage(seed, message);
  const ok = verifyDid(dk.did, message, sig);
  assertEq(`sign+verify ${name}`, ok, true);

  const bad = Buffer.from(`not hello ${name}`);
  const notOk = verifyDid(dk.did, bad, sig);
  assertEq(`verify rejects tampered ${name}`, notOk, false);

  report.crypto.signing.push({
    name,
    seed_b64: b64(seed),
    public_key_b64: dk.public_key_b64,
    did: dk.did,
    message_b64: b64(message),
    signature_b64_raw: b64(sig),
    signature_b64url: signatureB64(sig),
  });
}

// ---------------------------------------------------------------------------
// Indexing
// ---------------------------------------------------------------------------

const master = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) master[i] = (i * 7) & 0xff;

const groupKey = deriveGroupIndexKey(master, "ceremony-abc", "default", 0n);
if (groupKey.length !== 32) {
  console.log(`[fail] deriveGroupIndexKey returned ${groupKey.length} bytes, expected 32`);
  failed += 1;
} else {
  console.log("[ok]   deriveGroupIndexKey length 32");
  passed += 1;
}

const tokenA = indexToken(groupKey, "order_id", "ORD-1");
const tokenB = indexToken(groupKey, "order_id", "ORD-1");
assertEq("indexToken deterministic", tokenA, tokenB);

const tokenC = indexToken(groupKey, "order_id", "ORD-2");
if (tokenA !== tokenC) {
  console.log("[ok]   indexToken sensitive to value");
  passed += 1;
} else {
  console.log("[fail] indexToken returned same for different values");
  failed += 1;
}

report.crypto.indexing = {
  master_b64: b64(master),
  ceremony_id: "ceremony-abc",
  group_name: "default",
  epoch: 0,
  group_key_hex: hex(groupKey),
  tokens: [
    { field: "order_id", value: "ORD-1", token: tokenA },
    { field: "order_id", value: "ORD-2", token: tokenC },
    { field: "amount", value: 100, token: indexToken(groupKey, "amount", 100) },
  ],
};

// ---------------------------------------------------------------------------
// Row hash + envelope
// ---------------------------------------------------------------------------

const rhInput = {
  did: dkZero.did,
  timestamp: "2026-04-23T12:00:00Z",
  event_id: "11111111-2222-3333-4444-555555555555",
  event_type: "order.created",
  level: "info",
  prev_hash: zeroHash(),
  public_fields: { amount: 100, status: "paid" },
  groups: {},
};

const rowHash = computeRowHash(rhInput);
if (/^sha256:[0-9a-f]{64}$/.test(rowHash)) {
  console.log(`[ok]   computeRowHash shape ${rowHash.slice(0, 20)}...`);
  passed += 1;
} else {
  console.log(`[fail] computeRowHash bad shape: ${rowHash}`);
  failed += 1;
}
report.crypto.rowHash = { input: rhInput, output: rowHash };

// Build envelope: sign over row_hash bytes (matches Python logger).
const sigOverRow = signMessage(seedZero, Buffer.from(rowHash, "utf8"));
const envelopeLine = buildEnvelope({
  did: dkZero.did,
  timestamp: rhInput.timestamp,
  event_id: rhInput.event_id,
  event_type: rhInput.event_type,
  level: rhInput.level,
  sequence: 1,
  prev_hash: rhInput.prev_hash,
  row_hash: rowHash,
  signature_b64: signatureB64(sigOverRow),
  public_fields: rhInput.public_fields,
  group_payloads: {},
});

if (envelopeLine.endsWith("\n") && envelopeLine.includes(rowHash)) {
  console.log(`[ok]   buildEnvelope (${envelopeLine.length} bytes)`);
  passed += 1;
} else {
  console.log(`[fail] buildEnvelope unexpected output: ${envelopeLine}`);
  failed += 1;
}

report.crypto.envelope = {
  input: {
    did: dkZero.did,
    timestamp: rhInput.timestamp,
    event_id: rhInput.event_id,
    event_type: rhInput.event_type,
    level: rhInput.level,
    sequence: 1,
    prev_hash: rhInput.prev_hash,
    row_hash: rowHash,
    signature_b64: signatureB64(sigOverRow),
    public_fields: rhInput.public_fields,
    group_payloads: {},
  },
  signing_seed_b64: b64(seedZero),
  output: envelopeLine,
};

// ---------------------------------------------------------------------------

writeFileSync(join(here, "js_out.json"), JSON.stringify(report, null, 2) + "\n");

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
