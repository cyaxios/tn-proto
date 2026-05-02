// Browser-contract smoke test for @tnproto/sdk/core (Layer 1).
//
// This test imports from the Layer 1 entry point and exercises the
// surface the Chrome extension at extensions/tn-decrypt/ depends on.
// It runs in Node, but every import path here is the same one the
// extension uses — so if Layer 1 ever grows a node:* dep, this test
// fails to import (the static check at test/core_no_node_imports.test.ts
// catches it earlier; this test verifies dynamic-load equivalence).
//
// The point: prove the layering contract holds at runtime, not just
// at lint time. New verbs the extension might want (decryptGroup,
// AdminStateReducer, parseTnpkg, EMK helpers) MUST be reachable
// from this entry point.

import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
  // Crypto primitives
  canonicalize,
  canonicalizeToString,
  rowHash,
  ZERO_HASH,
  sha256Hex,
  sha256HexBytes,
  verify,
  signatureB64,
  signatureFromB64,
  deriveGroupKey,
  indexTokenFor,
  buildEnvelopeLine,
  // Read-shape projection
  flattenRawEntry,
  invalidReasonsFromValid,
  attachInstructions,
  // Decrypt
  decryptGroup,
  decryptAllGroups,
  // Admin state derivation
  AdminStateReducer,
  emptyState,
  // Manifest helpers
  newManifest,
  signManifest,
  verifyManifest,
  manifestSigningBytes,
  isManifestSignatureValid,
  KNOWN_KINDS,
  MANIFEST_VERSION,
  // Archive
  packTnpkg,
  parseTnpkg,
  // Agents policy
  parsePolicyText,
  policyPathFor,
  POLICY_RELATIVE_PATH,
  REQUIRED_FIELDS,
  // Errors
  VerificationError,
  ChainConflictError,
  RotationConflictError,
  LeafReuseError,
  SameCoordinateForkError,
  // Branded types + helpers
  asDid,
  asRowHash,
  asSignatureB64,
  // Encoding (used by EMK + the extension's wrapper)
  bytesToB64,
  b64ToBytes,
  randomBytes,
  // EMK (the audited single-source for browser-extension keystore work)
  importEmk,
  deriveEmkFromPassphrase,
  emkFromPrfOutput,
  makeVerifier,
  checkVerifier,
  wrapKeystoreSecret,
  unwrapKeystoreSecret,
} from "../src/core/index.js";

test("Layer 1 verb surface is reachable at runtime", () => {
  // If any of these imports failed, the test file wouldn't have loaded.
  // This explicit check guards against accidental tree-shaking or a
  // dist/ vs src/ divergence that strips one of them.
  for (const fn of [
    canonicalize, canonicalizeToString, rowHash, sha256Hex, sha256HexBytes,
    verify, signatureB64, signatureFromB64, deriveGroupKey, indexTokenFor,
    buildEnvelopeLine, flattenRawEntry, invalidReasonsFromValid, attachInstructions,
    decryptGroup, decryptAllGroups, emptyState,
    newManifest, signManifest, verifyManifest, manifestSigningBytes, isManifestSignatureValid,
    packTnpkg, parseTnpkg,
    parsePolicyText, policyPathFor,
    asDid, asRowHash, asSignatureB64,
    bytesToB64, b64ToBytes, randomBytes,
    importEmk, deriveEmkFromPassphrase, emkFromPrfOutput,
    makeVerifier, checkVerifier, wrapKeystoreSecret, unwrapKeystoreSecret,
  ]) {
    assert.equal(typeof fn, "function", `expected function, got ${typeof fn} for ${fn?.name ?? "<unnamed>"}`);
  }
  // ZERO_HASH is now a function (lazy getter) — check it returns the right string
  assert.equal(typeof ZERO_HASH, "function");
  assert.equal(typeof ZERO_HASH(), "string");
  assert.equal(ZERO_HASH().length, 71);  // "sha256:" + 64 hex chars
  assert.ok(typeof MANIFEST_VERSION === "number" || typeof MANIFEST_VERSION === "string");
  assert.equal(typeof POLICY_RELATIVE_PATH, "string");
  assert.ok(Array.isArray(REQUIRED_FIELDS) || REQUIRED_FIELDS instanceof Set);
  assert.ok(Array.isArray(KNOWN_KINDS) || KNOWN_KINDS instanceof Set);
  // Classes — the Error subclasses + AdminStateReducer
  assert.equal(typeof AdminStateReducer, "function");
  assert.equal(typeof VerificationError, "function");
  assert.equal(typeof ChainConflictError, "function");
  assert.equal(typeof RotationConflictError, "function");
  assert.equal(typeof LeafReuseError, "function");
  assert.equal(typeof SameCoordinateForkError, "function");
});

test("canonicalize produces stable bytes for a fixed input", () => {
  // The wire-canonicalization contract: same input → same bytes,
  // every time, on every consumer. The Chrome extension and the
  // Python SDK both rely on this for envelope hashing.
  const input = { event_type: "test.fixture", value: 42, nested: { a: 1, b: 2 } };
  const a = canonicalize(input);
  const b = canonicalize(input);
  assert.deepEqual(Array.from(a), Array.from(b), "canonicalize is non-deterministic");
  // Sanity: output is non-empty bytes.
  assert.ok(a.byteLength > 0);
});

test("rowHash + ZERO_HASH have the expected shapes", () => {
  // ZERO_HASH() is "sha256:" + 64 zeros (the standard zero-hash form).
  assert.match(ZERO_HASH(), /^sha256:[0-9a-f]{64}$/);
  // rowHash takes a structured input and returns "sha256:..."
  const h = rowHash({
    did: asDid("did:key:zNobody"),
    timestamp: "2026-05-01T00:00:00.000Z",
    eventId: "00000000-0000-0000-0000-000000000000",
    eventType: "test.fixture",
    level: "info",
    prevHash: ZERO_HASH(),
  });
  assert.match(h, /^sha256:[0-9a-f]{64}$/);
});

test("sha256Hex round-trips a known input", () => {
  // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  const hash = sha256Hex("");
  assert.equal(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("EMK round-trip via @noble/hashes-backed encoding helpers", async () => {
  // Browser-safe end-to-end: mint key, wrap secret, unwrap, verify.
  // The exact Web Crypto path the extension's unlock.js takes today.
  const key = await importEmk(randomBytes(32));
  const wrapped = await wrapKeystoreSecret(key, "passphrase-fixture");
  const recovered = await unwrapKeystoreSecret(key, wrapped);
  assert.equal(recovered, "passphrase-fixture");
});

test("Layer 1 errors are real Error subclasses (instanceof works)", () => {
  const v = new VerificationError({ event_type: "x", sequence: 1 } as never, ["signature"]);
  assert.ok(v instanceof Error);
  const c = new ChainConflictError("g", "a".repeat(64), "b".repeat(64));
  assert.ok(c instanceof Error);
  const r = new RotationConflictError("g", 1, 2);
  assert.ok(r instanceof Error);
  const l = new LeafReuseError("g", 0, null, null);
  assert.ok(l instanceof Error);
  const f = new SameCoordinateForkError("g", "1.0");
  assert.ok(f instanceof Error);
});

test("AdminStateReducer can be constructed and starts empty", () => {
  const r = new AdminStateReducer();
  assert.deepEqual(r.state.groups, []);
  assert.deepEqual(r.state.recipients, []);
  assert.deepEqual(r.conflicts, []);
});

test("packTnpkg + parseTnpkg round-trip a single-entry archive", () => {
  const entry = {
    name: "manifest.json",
    data: new TextEncoder().encode('{"hello":"world"}'),
  };
  const packed = packTnpkg([entry]);
  assert.ok(packed.byteLength > entry.data.byteLength, "packed archive should be at least as large as its input");
  const parsed = parseTnpkg(packed);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]!.name, "manifest.json");
  assert.deepEqual(Array.from(parsed[0]!.data), Array.from(entry.data));
});
