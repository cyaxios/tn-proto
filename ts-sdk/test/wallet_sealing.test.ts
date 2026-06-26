import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  seal,
  unseal,
  sealedBlobFromBytes,
  sealedBlobToBytes,
  SealingError,
} from "../src/wallet/sealing.js";
import { restoreCeremony } from "../src/wallet/restore.js";

// Values + golden blob produced by python/tn/sealing.py::_seal — the legacy
// per-file vault sealing the mnemonic restore reads. Cross-impl parity anchor.
const WRAP = Buffer.from(
  "6baf248b05977124dece8c46cc34824adf822ee417d0f640fca5d0094abd814b",
  "hex",
);
const DID = "did:key:z6MkrLS6RRwz2XtkyngSFbV88ds7ce1mSaehMrcuigrSVAAk";
const CID = "local_test01";
const FNAME = "tn.yaml";
const PLAINTEXT = '{"hello":"world","n":42}';
const PY_GOLDEN =
  '{"v":1,"nonce":"CZY5ypSsXpD8ayBX","ct":"el2n6F-WN3thFWftlBRnSdwOvDtxg0MTSlzkYRZN9owOo4JUbTAApg",' +
  '"aad":"did:key:z6MkrLS6RRwz2XtkyngSFbV88ds7ce1mSaehMrcuigrSVAAk/local_test01/tn.yaml"}';

test("unseal decrypts a Python-sealed golden blob (cross-impl parity)", () => {
  const blob = sealedBlobFromBytes(new Uint8Array(Buffer.from(PY_GOLDEN, "utf8")));
  const pt = unseal(blob, {
    wrapKey: new Uint8Array(WRAP),
    expectedDid: DID,
    expectedCeremonyId: CID,
    expectedFileName: FNAME,
  });
  assert.equal(Buffer.from(pt).toString("utf8"), PLAINTEXT);
});

test("seal -> unseal round-trips in the Python wire shape", () => {
  const blob = seal(new Uint8Array(Buffer.from(PLAINTEXT, "utf8")), {
    wrapKey: new Uint8Array(WRAP),
    did: DID,
    ceremonyId: CID,
    fileName: FNAME,
  });
  const reparsed = sealedBlobFromBytes(sealedBlobToBytes(blob));
  assert.equal(reparsed.v, 1);
  assert.equal(reparsed.nonce.length, 12);
  assert.equal(reparsed.aad, `${DID}/${CID}/${FNAME}`);
  const pt = unseal(reparsed, {
    wrapKey: new Uint8Array(WRAP),
    expectedDid: DID,
    expectedCeremonyId: CID,
    expectedFileName: FNAME,
  });
  assert.equal(Buffer.from(pt).toString("utf8"), PLAINTEXT);
});

test("unseal rejects a wrong logical path (AAD mismatch)", () => {
  const blob = sealedBlobFromBytes(new Uint8Array(Buffer.from(PY_GOLDEN, "utf8")));
  assert.throws(
    () =>
      unseal(blob, {
        wrapKey: new Uint8Array(WRAP),
        expectedDid: DID,
        expectedCeremonyId: CID,
        expectedFileName: "other.file",
      }),
    /AAD mismatch/,
  );
});

test("unseal rejects a wrong wrap key", () => {
  const blob = sealedBlobFromBytes(new Uint8Array(Buffer.from(PY_GOLDEN, "utf8")));
  assert.throws(() => unseal(blob, { wrapKey: new Uint8Array(32) }), SealingError);
});

test("restoreCeremony pulls + unseals a project's files (manifest flow)", async () => {
  const cid = "local_flow01";
  const wrap = new Uint8Array(WRAP);
  const yamlText = `ceremony:\n  id: ${cid}\ncipher: btn\n`;
  const keyText = "BTN-STATE-BYTES";
  // The vault stores files as the wire JSON of a sealed blob.
  const sealedYaml = sealedBlobToBytes(
    seal(new Uint8Array(Buffer.from(yamlText, "utf8")), { wrapKey: wrap, did: DID, ceremonyId: cid, fileName: "tn.yaml" }),
  );
  const sealedKey = sealedBlobToBytes(
    seal(new Uint8Array(Buffer.from(keyText, "utf8")), { wrapKey: wrap, did: DID, ceremonyId: cid, fileName: "default.btn.state" }),
  );
  const blobs: Record<string, Uint8Array> = { "tn.yaml": sealedYaml, "default.btn.state": sealedKey };

  // Minimal fake VaultClient: just the two methods restoreCeremony calls.
  const fakeClient = {
    async restoreManifest() {
      return { files: [{ name: "tn.yaml" }, { name: "default.btn.state" }] };
    },
    async downloadSealed(_projectId: string, name: string) {
      return blobs[name]!;
    },
  } as unknown as import("../src/vault/client.js").VaultClient;

  const out = mkdtempSync(join(tmpdir(), "ts-restore-flow-"));
  try {
    const res = await restoreCeremony(fakeClient, "proj_1", { outDir: out, wrapKey: wrap, did: DID });
    assert.deepEqual(res.filesWritten.slice().sort(), ["default.btn.state", "tn.yaml"]);
    assert.equal(res.notes.length, 0, `unexpected notes: ${res.notes.join("; ")}`);
    assert.equal(readFileSync(join(out, "tn.yaml"), "utf8"), yamlText);
    assert.equal(readFileSync(join(out, ".tn", "keys", "default.btn.state"), "utf8"), keyText);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
