// Tests for src/wallet/restore.ts — the D-20 multi-device-restore port.
//
// Most tests are unit-level: build a fake encrypted blob with Node's
// crypto, run it through our decrypt + unpack, assert the round-trip.
// One integration test wires a mock fetch so we exercise the full
// restoreWithBek without a live vault.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { createCipheriv, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { zipSync, type Zippable } from "fflate";

import {
  RestoreError,
  decryptBlobWithBek,
  restoreWithBek,
  tryUnpackExportFrame,
  _internals,
} from "../src/wallet/restore.ts";

// ── Helpers ──────────────────────────────────────────────────────────

/** AES-256-GCM seal: returns [12-byte nonce ++ ciphertext ++ 16-byte tag]
 *  matching Python's `_decrypt_blob_with_bek` shape. */
function sealWithBek(plaintext: Uint8Array, bek: Uint8Array): Uint8Array {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(bek), nonce);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(Buffer.concat([nonce, ct, tag]));
}

/** Build the LEGACY-COMPAT-2026-04-29 uint32 frame:
 *  uint32_be count [ uint32_be name_len, name, uint32_be data_len, data ] *count */
function buildLegacyFrame(members: [string, Uint8Array][]): Uint8Array {
  const chunks: Buffer[] = [];
  const count = Buffer.alloc(4);
  count.writeUInt32BE(members.length);
  chunks.push(count);
  for (const [name, data] of members) {
    const nameBuf = Buffer.from(name, "utf-8");
    const nameLen = Buffer.alloc(4);
    nameLen.writeUInt32BE(nameBuf.length);
    const dataLen = Buffer.alloc(4);
    dataLen.writeUInt32BE(data.length);
    chunks.push(nameLen, nameBuf, dataLen, Buffer.from(data));
  }
  return new Uint8Array(Buffer.concat(chunks));
}

function buildStoredZip(members: [string, Uint8Array][]): Uint8Array {
  const files: Zippable = {};
  for (const [name, data] of members) {
    files[name] = [data, { level: 0 }];
  }
  return zipSync(files, { level: 0 });
}

// ── b64 helpers ─────────────────────────────────────────────────────

test("_b64decodeLoose — handles url-safe + missing padding", () => {
  // Standard alphabet, padded.
  const a = _internals.b64decodeLoose(Buffer.from([1, 2, 3]).toString("base64"));
  assert.deepEqual(Array.from(a), [1, 2, 3]);

  // url-safe, unpadded.
  const b = _internals.b64decodeLoose(
    Buffer.from([255, 0, 128, 64]).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"),
  );
  assert.deepEqual(Array.from(b), [255, 0, 128, 64]);
});

// ── decryptBlobWithBek ──────────────────────────────────────────────

test("decryptBlobWithBek — round-trip with a known BEK", () => {
  const bek = randomBytes(32);
  const plaintext = new TextEncoder().encode("hello tn-proto restore");
  const blob = sealWithBek(plaintext, bek);
  const recovered = decryptBlobWithBek(blob, new Uint8Array(bek));
  assert.deepEqual(Array.from(recovered), Array.from(plaintext));
});

test("decryptBlobWithBek — wrong BEK throws RestoreError", () => {
  const bek = randomBytes(32);
  const plaintext = new TextEncoder().encode("payload");
  const blob = sealWithBek(plaintext, bek);
  const wrongBek = randomBytes(32);
  assert.throws(() => decryptBlobWithBek(blob, new Uint8Array(wrongBek)), RestoreError);
});

test("decryptBlobWithBek — short blob rejected", () => {
  assert.throws(() => decryptBlobWithBek(new Uint8Array(10), new Uint8Array(32)), RestoreError);
});

test("decryptBlobWithBek — non-32-byte BEK rejected", () => {
  const bek = randomBytes(32);
  const blob = sealWithBek(new Uint8Array([1, 2, 3]), bek);
  assert.throws(() => decryptBlobWithBek(blob, new Uint8Array(16)), /BEK must be 32 bytes/);
});

// ── tryUnpackExportFrame ────────────────────────────────────────────

test("tryUnpackExportFrame — STORED zip path", () => {
  const zip = buildStoredZip([
    ["a.tnpkg", new TextEncoder().encode("aaaa")],
    ["manifest.json", new TextEncoder().encode("{\"x\":1}")],
  ]);
  const members = tryUnpackExportFrame(zip);
  assert.ok(members, "must unpack as zip");
  assert.equal(members!.size, 2);
  assert.equal(new TextDecoder().decode(members!.get("a.tnpkg")!), "aaaa");
  assert.equal(new TextDecoder().decode(members!.get("manifest.json")!), "{\"x\":1}");
});

test("tryUnpackExportFrame — legacy uint32 frame", () => {
  const frame = buildLegacyFrame([
    ["alpha", new TextEncoder().encode("11111")],
    ["beta", new TextEncoder().encode("22")],
  ]);
  const members = tryUnpackExportFrame(frame);
  assert.ok(members, "must unpack legacy frame");
  assert.equal(members!.size, 2);
  assert.equal(new TextDecoder().decode(members!.get("alpha")!), "11111");
  assert.equal(new TextDecoder().decode(members!.get("beta")!), "22");
});

test("tryUnpackExportFrame — opaque bytes return null", () => {
  const opaque = new Uint8Array([0, 0, 0, 0, 0x55, 0xaa]); // not a zip + count=0
  assert.equal(tryUnpackExportFrame(opaque), null);
});

// ── restoreWithBek (integration with mocked fetch) ──────────────────

test("restoreWithBek — full path: fetch -> decrypt -> unpack zip -> write files", async () => {
  const bek = randomBytes(32);
  const zipBytes = buildStoredZip([
    ["manifest.json", new TextEncoder().encode("{\"v\":1}")],
    ["payload.tnpkg", new TextEncoder().encode("BINARY-BYTES-HERE")],
  ]);
  const blob = sealWithBek(zipBytes, bek);
  const blobB64 = Buffer.from(blob).toString("base64");

  // Mock fetch: only the encrypted-blob route matters.
  const mockFetch = async (_url: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const url = String(_url);
    if (url.includes("/encrypted-blob")) {
      return new Response(JSON.stringify({ ciphertext_b64: blobB64 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  };

  const tmp = mkdtempSync(join(tmpdir(), "wallet-restore-test-"));
  try {
    const result = await restoreWithBek({
      vaultUrl: "http://vault.test",
      projectId: "proj-restore-001",
      bearer: "fake-bearer",
      bek: new Uint8Array(bek),
      outDir: tmp,
      fetchImpl: mockFetch,
    });

    assert.equal(result.projectId, "proj-restore-001");
    assert.equal(result.filesWritten.length, 2);
    assert.equal(result.rawBlobPath, null);

    const manifest = readFileSync(join(tmp, "manifest.json"), "utf-8");
    assert.equal(manifest, "{\"v\":1}");
    const payload = readFileSync(join(tmp, "payload.tnpkg"), "utf-8");
    assert.equal(payload, "BINARY-BYTES-HERE");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("restoreWithBek — opaque plaintext writes <project>.tnpkg + note", async () => {
  const bek = randomBytes(32);
  const opaque = new TextEncoder().encode("raw tnpkg bytes not a zip");
  const blob = sealWithBek(opaque, bek);
  const blobB64 = Buffer.from(blob).toString("base64");

  const mockFetch = async (): Promise<Response> =>
    new Response(JSON.stringify({ ciphertext_b64: blobB64 }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  const tmp = mkdtempSync(join(tmpdir(), "wallet-restore-opaque-"));
  try {
    const result = await restoreWithBek({
      vaultUrl: "http://vault.test",
      projectId: "proj-op-001",
      bearer: "x",
      bek: new Uint8Array(bek),
      outDir: tmp,
      fetchImpl: mockFetch,
    });
    assert.equal(result.filesWritten.length, 1);
    assert.ok(result.filesWritten[0]!.endsWith("proj-op-001.tnpkg"));
    assert.match(result.notes.join(" "), /opaque tnpkg/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("restoreWithBek — vault 404 throws RestoreError with helpful message", async () => {
  const mockFetch = async (): Promise<Response> => new Response("nope", { status: 404 });
  await assert.rejects(
    restoreWithBek({
      vaultUrl: "http://vault.test",
      projectId: "missing",
      bearer: "x",
      bek: new Uint8Array(32),
      outDir: tmpdir(),
      fetchImpl: mockFetch,
    }),
    /encrypted blob not found/,
  );
});

test("restoreWithBek — missing ciphertext field surfaces clean error", async () => {
  const mockFetch = async (): Promise<Response> =>
    new Response(JSON.stringify({ no_ciphertext: "here" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  await assert.rejects(
    restoreWithBek({
      vaultUrl: "http://vault.test",
      projectId: "p",
      bearer: "x",
      bek: new Uint8Array(32),
      outDir: tmpdir(),
      fetchImpl: mockFetch,
    }),
    /missing ciphertext field/,
  );
});
