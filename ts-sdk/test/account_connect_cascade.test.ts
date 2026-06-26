// Regression test for the account-connect key-source CASCADE (PARITY-connection
// rows 1-2). The bug: Python signed the redeem with the MACHINE-GLOBAL identity
// key, TS signed with the PER-CEREMONY keystore key, so the same operator bound
// a DIFFERENT DID depending on which CLI ran. The fix is a single shared
// resolver (`resolveSigningIdentity` here / `resolve_signing_identity` in Python)
// whose cascade is:  supplied(2) > machine(1) > ceremony(3).
//
// These tests pin each tier's resolution and the cross-CLI same-DID property:
// given the SAME machine identity.json, the cascade resolves the SAME DID
// regardless of which ceremony keystore is present (that's what makes Python
// and TS bind the same principal on one machine).

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";

import { DeviceKey } from "../src/core/signing.js";
import { Identity } from "../src/identity.js";
import {
  resolveSigningIdentity,
  SigningIdentityError,
} from "../src/account/signing_identity.ts";

/** Write a machine-global identity.json from a known seed; return its DID. */
function writeIdentity(path: string, seed: Uint8Array): string {
  const dk = DeviceKey.fromSeed(seed);
  const privB64 = Buffer.from(seed).toString("base64url");
  const doc = {
    version: 1,
    did: dk.did,
    device_pub_b64: Buffer.from(dk.publicKey).toString("base64url"),
    device_priv_b64_enc: privB64,
    device_priv_enc_method: "none",
    seed_b64: privB64,
    linked_vault: null,
    linked_account_id: null,
  };
  writeFileSync(path, JSON.stringify(doc, null, 2), "utf8");
  return dk.did;
}

/** Write a minimal ceremony keystore (local.private + index_master.key);
 *  return its DID. */
function writeKeystore(dir: string, seed: Uint8Array): string {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "local.private"), Buffer.from(seed));
  writeFileSync(join(dir, "index_master.key"), Buffer.from(new Uint8Array(32).fill(9)));
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(dir, "local.public"), dk.did, "utf8");
  return dk.did;
}

test("cascade tier 1 — machine identity wins over the ceremony keystore (default)", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cascade-machine-"));
  try {
    const idPath = join(tmp, "identity.json");
    const ksDir = join(tmp, "keys");
    const machineDid = writeIdentity(idPath, new Uint8Array(32).fill(1));
    const ceremonyDid = writeKeystore(ksDir, new Uint8Array(32).fill(2));
    assert.notEqual(machineDid, ceremonyDid, "fixtures must differ to be meaningful");

    const r = resolveSigningIdentity({
      machineIdentityPath: idPath,
      keystorePath: ksDir,
    });
    assert.equal(r.tier, "machine");
    assert.equal(r.did, machineDid, "machine identity must win when present");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("cascade tier 3 — falls back to the ceremony keystore when no machine identity", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cascade-ceremony-"));
  try {
    const idPath = join(tmp, "identity.json"); // intentionally NOT written
    const ksDir = join(tmp, "keys");
    const ceremonyDid = writeKeystore(ksDir, new Uint8Array(32).fill(3));

    const r = resolveSigningIdentity({
      machineIdentityPath: idPath,
      keystorePath: ksDir,
    });
    assert.equal(r.tier, "ceremony");
    assert.equal(r.did, ceremonyDid, "headless case must fall back to keystore DID");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("cascade tier 2 — supplied --identity overrides everything", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cascade-supplied-"));
  try {
    const machinePath = join(tmp, "identity.json");
    const suppliedPath = join(tmp, "supplied.json");
    const ksDir = join(tmp, "keys");
    writeIdentity(machinePath, new Uint8Array(32).fill(4));
    const suppliedDid = writeIdentity(suppliedPath, new Uint8Array(32).fill(5));
    writeKeystore(ksDir, new Uint8Array(32).fill(6));

    const r = resolveSigningIdentity({
      suppliedIdentityPath: suppliedPath,
      machineIdentityPath: machinePath,
      keystorePath: ksDir,
    });
    assert.equal(r.tier, "supplied");
    assert.equal(r.did, suppliedDid, "supplied identity must win outright");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("cross-CLI same-DID — shared machine identity resolves the same DID for any ceremony", () => {
  // Two distinct ceremonies on ONE machine. Pre-fix, TS would bind each
  // ceremony's own keystore DID (two different principals). Post-fix, both
  // resolve to the shared machine identity DID — the property that makes the
  // Python wheel and the TS CLI bind the SAME DID on the same machine.
  const tmp = mkdtempSync(join(tmpdir(), "cascade-xcli-"));
  try {
    const idPath = join(tmp, "identity.json");
    const machineDid = writeIdentity(idPath, new Uint8Array(32).fill(7));
    const ksA = join(tmp, "a", "keys");
    const ksB = join(tmp, "b", "keys");
    writeKeystore(ksA, new Uint8Array(32).fill(8));
    writeKeystore(ksB, new Uint8Array(32).fill(9));

    const ra = resolveSigningIdentity({ machineIdentityPath: idPath, keystorePath: ksA });
    const rb = resolveSigningIdentity({ machineIdentityPath: idPath, keystorePath: ksB });
    assert.equal(ra.did, machineDid);
    assert.equal(rb.did, machineDid);
    assert.equal(ra.did, rb.did, "same machine => same bound DID across ceremonies");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("cascade exhausts — no machine identity and no keystore raises SigningIdentityError", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cascade-empty-"));
  try {
    assert.throws(
      () =>
        resolveSigningIdentity({
          machineIdentityPath: join(tmp, "identity.json"),
          keystorePath: join(tmp, "nope"),
        }),
      SigningIdentityError,
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("Identity round-trips through the resolver (machine tier signs as the loaded DID)", () => {
  // Guards the deviceKey<->did coupling: the resolved deviceKey must produce
  // the resolved DID (so the signature verifies under the bound principal).
  const tmp = mkdtempSync(join(tmpdir(), "cascade-sign-"));
  try {
    const idPath = join(tmp, "identity.json");
    const did = writeIdentity(idPath, new Uint8Array(32).fill(11));
    const r = resolveSigningIdentity({ machineIdentityPath: idPath, keystorePath: null });
    assert.equal(r.did, did);
    assert.equal(r.deviceKey.did, r.did, "deviceKey DID must equal the bound DID");
    // And the loaded identity exposes the same DID.
    assert.equal(Identity.load(idPath).did, did);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
