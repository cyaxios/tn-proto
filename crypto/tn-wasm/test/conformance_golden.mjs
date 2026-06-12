// Cross-implementation conformance runner (wasm / TS side).
//
// Loads the SAME golden vectors as the Rust *_golden tests and the
// Python tests/test_conformance_vectors.py, and asserts the wasm exports
// (which the TS SDK delegates to) reproduce them byte-for-byte. All three
// implementations reading the identical vectors is the conformance gate.
//
// Run from crypto/tn-wasm (after `wasm-pack build --target nodejs`):
//   node test/conformance_golden.mjs
// Exits non-zero on any mismatch.

import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  canonicalBytes,
  deviceKeyFromSeed,
  signMessage,
  signatureB64,
  verifyDid,
  deriveGroupIndexKey,
  indexToken,
  computeRowHash,
  buildEnvelope,
} from "../pkg/tn_wasm.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIX = join(here, "..", "..", "tn-core", "tests", "fixtures");
const load = (n) => JSON.parse(readFileSync(join(FIX, n), "utf8"));
const hex = (u8) => Buffer.from(u8).toString("hex");
const hexToB64 = (h) => Buffer.from(h, "hex").toString("base64");

let passed = 0;
let failed = 0;
function check(name, actual, expected) {
  if (actual === expected) {
    passed += 1;
  } else {
    failed += 1;
    console.log(`[fail] ${name}`);
    console.log(`       expected: ${expected}`);
    console.log(`       actual:   ${actual}`);
  }
}

// ---- canonical bytes ----
for (const c of load("canonical_vectors.json")) {
  check(`canonical/${c.name}`, hex(canonicalBytes(c.input_json)), c.output_hex);
}

// ---- signing ----
for (const e of load("signing_vectors.json")) {
  const seed = Buffer.from(e.seed_hex, "hex");
  const dk = deviceKeyFromSeed(seed);
  check(`signing/did/${e.did.slice(0, 12)}`, dk.did, e.did);
  e.cases.forEach((cs, i) => {
    const msg = Buffer.from(cs.message_hex, "hex");
    const sig = signMessage(seed, msg);
    check(`signing/sig/${e.did.slice(0, 12)}#${i}`, signatureB64(sig), cs.signature_b64url_nopad);
    check(`signing/verify/${e.did.slice(0, 12)}#${i}`, verifyDid(e.did, msg, sig), true);
  });
}

// ---- index tokens ----
for (const c of load("index_token_vectors.json")) {
  const master = Buffer.from(c.master_hex, "hex");
  const gk = deriveGroupIndexKey(master, c.ceremony, c.group, BigInt(c.epoch));
  check(`index/key/${c.group}-${c.field}`, hex(gk), c.derived_key_hex);
  check(`index/token/${c.group}-${c.field}`, indexToken(gk, c.field, c.value), c.expected_token);
}

// ---- row hash ----
for (const c of load("row_hash_vectors.json")) {
  const inp = c.inputs;
  const groups = {};
  for (const [gn, g] of Object.entries(inp.groups)) {
    groups[gn] = { ciphertext_b64: hexToB64(g.ciphertext_hex), field_hashes: g.field_hashes };
  }
  const got = computeRowHash({
    device_identity: inp.did,
    timestamp: inp.timestamp,
    event_id: inp.event_id,
    event_type: inp.event_type,
    level: inp.level,
    prev_hash: inp.prev_hash,
    public_fields: inp.public_fields,
    groups,
  });
  check(`row_hash/${c.name}`, got, c.expected_row_hash);
}

// ---- envelope (full pipeline -> NDJSON line) ----
for (const c of load("envelope_vectors.json")) {
  const inp = c.inputs;
  const tag = inp.event_id.slice(-4);
  if (inp.cipher !== "identity") {
    console.log(`[skip] envelope/${tag} cipher=${inp.cipher}`);
    continue;
  }
  const seed = Buffer.from(inp.seed_hex, "hex");
  const dk = deviceKeyFromSeed(seed);
  const gk = deriveGroupIndexKey(
    Buffer.from(inp.master_index_key_hex, "hex"),
    inp.ceremony_id,
    inp.group,
    BigInt(inp.epoch),
  );
  const field_hashes = {};
  for (const k of Object.keys(inp.private_fields).sort()) {
    field_hashes[k] = indexToken(gk, k, inp.private_fields[k]);
  }
  check(
    `envelope/field_hashes/${tag}`,
    JSON.stringify(field_hashes),
    JSON.stringify(c.expected_field_hashes),
  );

  const ct = canonicalBytes(inp.private_fields); // identity cipher
  check(`envelope/ciphertext/${tag}`, hex(ct), c.expected_ciphertext_hex);
  const ctB64 = Buffer.from(ct).toString("base64");

  const rowHash = computeRowHash({
    device_identity: dk.did,
    timestamp: inp.timestamp,
    event_id: inp.event_id,
    event_type: inp.event_type,
    level: inp.level,
    prev_hash: inp.prev_hash,
    public_fields: inp.public_fields,
    groups: { [inp.group]: { ciphertext_b64: ctB64, field_hashes } },
  });
  check(`envelope/row_hash/${tag}`, rowHash, c.expected_row_hash);

  const sig = signMessage(seed, Buffer.from(rowHash, "utf8"));
  check(`envelope/signature/${tag}`, signatureB64(sig), c.expected_signature_b64url);

  const line = buildEnvelope({
    device_identity: dk.did,
    timestamp: inp.timestamp,
    event_id: inp.event_id,
    event_type: inp.event_type,
    level: inp.level,
    sequence: inp.sequence,
    prev_hash: inp.prev_hash,
    row_hash: rowHash,
    signature_b64: signatureB64(sig),
    public_fields: inp.public_fields,
    group_payloads: { [inp.group]: { ciphertext: ctB64, field_hashes } },
  });
  check(`envelope/ndjson/${tag}`, line, c.expected_envelope_ndjson);
}

console.log(`\nconformance (wasm): ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
