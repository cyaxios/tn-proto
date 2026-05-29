import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Identity } from "../src/identity.js";
import { DeviceKey } from "../src/core/signing.js";

// The machine-global device identity underpins warm-attach: every ceremony
// minted by `tn-js init` is seeded from this one device key, so they share a
// single DID. `account connect` stamps linked_account_id here so future
// inits attach automatically.

test("loadOrMint mints a fresh identity and persists it", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-id-"));
  const path = join(dir, "identity.json");

  const id = Identity.loadOrMint(path);
  assert.ok(id.did.startsWith("did:key:"), `expected did:key, got ${id.did}`);
  assert.equal(id.seed.length, 32);
  assert.ok(existsSync(path), "identity.json should be written");

  // The DID is derived from the persisted seed.
  assert.equal(DeviceKey.fromSeed(id.seed).did, id.did);
});

test("loadOrMint is stable — second call returns the same DID + seed", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-id-"));
  const path = join(dir, "identity.json");

  const a = Identity.loadOrMint(path);
  const b = Identity.loadOrMint(path);
  assert.equal(a.did, b.did, "DID must be stable across loads");
  assert.deepEqual([...a.seed], [...b.seed], "seed must be stable across loads");
});

test("linked_account_id + linked_vault round-trip through save/load", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-id-"));
  const path = join(dir, "identity.json");

  const id = Identity.loadOrMint(path);
  assert.equal(id.linkedAccountId, null);
  assert.equal(id.linkedVault, null);

  id.linkedAccountId = "01ACCOUNT0000000000000000";
  id.linkedVault = "http://localhost:38790";
  id.save();

  const reloaded = Identity.load(path);
  assert.equal(reloaded.linkedAccountId, "01ACCOUNT0000000000000000");
  assert.equal(reloaded.linkedVault, "http://localhost:38790");
  assert.equal(reloaded.did, id.did, "DID unchanged by the link stamp");
});

test("save preserves unknown fields (Python-written identity.json)", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-id-"));
  const path = join(dir, "identity.json");

  // Mint, then re-load and re-save — a field the Python writer adds
  // (mnemonic_stored) must survive a TS round-trip.
  const id = Identity.loadOrMint(path);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  doc.mnemonic_stored = true;
  doc.prefs = { default_new_ceremony_mode: "stream" };
  writeFileSync(path, JSON.stringify(doc), "utf8");

  const reloaded = Identity.load(path);
  reloaded.linkedAccountId = "01ACCT";
  reloaded.save();

  const after = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(after.mnemonic_stored, true, "unknown field must be preserved");
  assert.deepEqual(after.prefs, { default_new_ceremony_mode: "stream" });
  assert.equal(after.linked_account_id, "01ACCT");
});
