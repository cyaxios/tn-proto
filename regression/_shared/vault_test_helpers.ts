/**
 * TS-side helpers mirroring `_shared/vault_test_helpers.py`.
 *
 * Used by C8-TS for the restore-on-new-machine flow. C7-TS does NOT
 * use these — the TS SDK has no vault auto-backup today (see
 * critic log, C7 TS section). Only the restore half is testable.
 *
 * Three operations, same shape as the Python helpers:
 *
 * 1. `devAuthLogin(baseUrl, handle)` — POST `/api/v1/dev/login`,
 *    return `{ token, account_id, ... }`. Requires `TN_DEV_AUTH_BYPASS=1`
 *    on the target vault.
 *
 * 2. `fetchPendingClaim(baseUrl, vaultId, token)` — GET
 *    `/api/v1/pending-claims/{vault_id}` with the bearer JWT; returns
 *    the encrypted .tnpkg bytes.
 *
 * 3. `restoreKeystoreTo(targetDir, ciphertextTnpkg, bek)` — decrypts
 *    the inner `body/encrypted.bin` (AES-256-GCM via Node `crypto`),
 *    parses the resulting STORED-zip plaintext, and writes:
 *      - `body/tn.yaml`                          -> `<target>/tn.yaml`
 *      - `body/WARNING_CONTAINS_PRIVATE_KEYS`    -> same name at root
 *      - `body/<anything-else>`                  -> `<target>/keys/<basename>`
 *    Returns the absolute path to the laid-out `tn.yaml`.
 *
 * Plus `parseClaimUrl(url)` which splits the URL into
 * `{ vaultId, bek }` (BEK base64url-decoded to 32 bytes).
 *
 * `deletePendingClaim` is a best-effort cleanup helper for the
 * vault_cleanup pattern in the Python side. Same shape; never throws.
 */
import { createDecipheriv } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import * as zlib from "node:zlib";

// ---------------------------------------------------------------------------
// dev-auth
// ---------------------------------------------------------------------------

export interface DevAuthLoginResponse {
  token: string;
  account_id: string;
  expires_at: string;
  created?: boolean;
  handle?: string | null;
  passphrase?: string | null;
}

export async function devAuthLogin(
  baseUrl: string,
  handle = "alice",
): Promise<DevAuthLoginResponse> {
  const res = await fetch(`${baseUrl}/api/v1/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "<unreadable>");
    throw new Error(
      `devAuthLogin: vault returned ${res.status} ${res.statusText}. ` +
        `Is TN_DEV_AUTH_BYPASS=1 set on ${baseUrl}? body=${body.slice(0, 300)}`,
    );
  }
  return (await res.json()) as DevAuthLoginResponse;
}

// ---------------------------------------------------------------------------
// pending-claim fetch / delete
// ---------------------------------------------------------------------------

export async function fetchPendingClaim(
  baseUrl: string,
  vaultId: string,
  token: string,
): Promise<Uint8Array> {
  const res = await fetch(`${baseUrl}/api/v1/pending-claims/${vaultId}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "<unreadable>");
    throw new Error(
      `fetchPendingClaim: ${res.status} ${res.statusText} for vault_id=${vaultId}. body=${body.slice(0, 300)}`,
    );
  }
  return new Uint8Array(await res.arrayBuffer());
}

/** Best-effort DELETE for the vault_cleanup pattern. Returns true on
 *  204; false on any other status or thrown error. Never raises. */
export async function deletePendingClaim(
  baseUrl: string,
  vaultId: string,
  token: string,
): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}/api/v1/pending-claims/${vaultId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    return res.status === 204;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Claim URL parsing
// ---------------------------------------------------------------------------

export interface ParsedClaimUrl {
  vaultId: string;
  bek: Uint8Array;
}

export function parseClaimUrl(claimUrl: string): ParsedClaimUrl {
  const u = new URL(claimUrl);
  // Path: /claim/<vault_id>
  const m = u.pathname.match(/\/claim\/([^/]+)\/?$/);
  if (m === null) {
    throw new Error(
      `parseClaimUrl: no '/claim/<vault_id>' in path ${JSON.stringify(u.pathname)}`,
    );
  }
  const vaultId = m[1];

  // Fragment: k=<base64url>
  // URL fragment is in u.hash; strip the leading '#'.
  const frag = u.hash.startsWith("#") ? u.hash.slice(1) : u.hash;
  const fragParams = new URLSearchParams(frag);
  const bekB64 = fragParams.get("k");
  if (bekB64 === null) {
    throw new Error(`parseClaimUrl: no 'k=' in fragment ${JSON.stringify(u.hash)}`);
  }
  const bek = base64UrlDecode(bekB64);
  if (bek.length !== 32) {
    throw new Error(`parseClaimUrl: BEK is ${bek.length} bytes; expected 32`);
  }
  return { vaultId, bek };
}

function base64UrlDecode(s: string): Uint8Array {
  // Re-pad and translate to standard base64.
  let std = s.replace(/-/g, "+").replace(/_/g, "/");
  while (std.length % 4 !== 0) std += "=";
  return new Uint8Array(Buffer.from(std, "base64"));
}

// ---------------------------------------------------------------------------
// Decrypt + lay out the keystore
// ---------------------------------------------------------------------------

/** Decrypt `body/encrypted.bin` (AES-256-GCM; 12-byte nonce prefix +
 *  ciphertext+tag) under BEK. Mirrors `tn.export.decrypt_body_blob`
 *  in Python. Returns the inner plaintext `{name: bytes}` dict by
 *  unzipping the STORED-zip plaintext.
 */
export function decryptBodyBlob(blob: Uint8Array, key: Uint8Array): Record<string, Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`decryptBodyBlob: key must be 32 bytes, got ${key.length}`);
  }
  if (blob.length < 12 + 16) {
    throw new Error("decryptBodyBlob: blob too short for AES-GCM nonce+tag");
  }
  const nonce = blob.subarray(0, 12);
  const ciphertextAndTag = blob.subarray(12);
  // AES-GCM in Node: the auth tag is the last 16 bytes; the rest is the
  // ciphertext. createDecipheriv requires both pieces split out.
  const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
  const ct = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);

  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);

  // Plaintext is a STORED zip. We need to parse it. Node doesn't have
  // a built-in zip module, but our tests can use the bytes directly:
  // STORED zip entries are just `local-file-header + raw bytes`. We
  // parse minimally here. (The vault always emits STORED-zip per
  // tn.export._encrypt_body_in_place; if that ever switches to
  // DEFLATE we'll need zlib.inflateRawSync.)
  return parseStoredZip(plaintext);
}

function parseStoredZip(zipBytes: Uint8Array): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  // PK\x03\x04 = local-file-header magic
  // PK\x01\x02 = central-directory header (we walk until we hit this)
  // PK\x05\x06 = end-of-central-dir record
  let pos = 0;
  const dv = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
  while (pos < zipBytes.length) {
    const sig = dv.getUint32(pos, true);
    if (sig === 0x04034b50 /* PK\x03\x04 */) {
      // Local file header layout (little-endian):
      //   0:  signature (4)
      //   4:  version (2)
      //   6:  gp flags (2)
      //   8:  compression method (2)
      //   10: mod time (2)
      //   12: mod date (2)
      //   14: crc32 (4)
      //   18: compressed size (4)
      //   22: uncompressed size (4)
      //   26: name length (2)
      //   28: extra length (2)
      const compressionMethod = dv.getUint16(pos + 8, true);
      const compressedSize = dv.getUint32(pos + 18, true);
      const uncompressedSize = dv.getUint32(pos + 22, true);
      const nameLen = dv.getUint16(pos + 26, true);
      const extraLen = dv.getUint16(pos + 28, true);
      const nameStart = pos + 30;
      const dataStart = nameStart + nameLen + extraLen;
      const name = Buffer.from(
        zipBytes.subarray(nameStart, nameStart + nameLen),
      ).toString("utf-8");
      const dataEnd = dataStart + compressedSize;
      const rawData = zipBytes.subarray(dataStart, dataEnd);
      let data: Uint8Array;
      if (compressionMethod === 0) {
        // STORED — no compression.
        data = rawData;
      } else if (compressionMethod === 8) {
        // DEFLATE — fall through to zlib for future-proofing.
        data = new Uint8Array(zlib.inflateRawSync(Buffer.from(rawData)));
      } else {
        throw new Error(
          `parseStoredZip: unsupported compression method ${compressionMethod} for entry ${name}`,
        );
      }
      // Defensive: the uncompressed size in the header is authoritative
      // for some malformed inputs. Trust it if it differs from data.length
      // ONLY for STORED entries (where they should equal).
      if (compressionMethod === 0 && data.length !== uncompressedSize) {
        // Trust the header — but log via thrown error so it's loud.
        throw new Error(
          `parseStoredZip: STORED entry ${name} data length mismatch: ` +
            `got ${data.length}, header says ${uncompressedSize}`,
        );
      }
      out[name] = data;
      pos = dataEnd;
      continue;
    }
    if (sig === 0x02014b50 /* PK\x01\x02 */ || sig === 0x06054b50 /* PK\x05\x06 */) {
      // Central directory or end-of-central-dir — we've passed all
      // local entries.
      break;
    }
    throw new Error(
      `parseStoredZip: unknown signature ${sig.toString(16)} at offset ${pos}`,
    );
  }
  return out;
}

/** Lay out the decrypted body files into the conventional layout
 *  expected by `Tn.init(yamlPath)`. Returns the path to the laid-out
 *  `tn.yaml`. Same contract as Python's `restore_keystore_to`.
 */
export function restoreKeystoreTo(
  targetDir: string,
  ciphertextTnpkg: Uint8Array,
  bek: Uint8Array,
): string {
  // The outer .tnpkg is a STORED zip too. Parse it to find
  // `body/encrypted.bin`.
  const outerFiles = parseStoredZip(ciphertextTnpkg);
  const encrypted = outerFiles["body/encrypted.bin"];
  if (encrypted === undefined) {
    throw new Error(
      "restoreKeystoreTo: tnpkg has no 'body/encrypted.bin'. Inventory: " +
        JSON.stringify(Object.keys(outerFiles)),
    );
  }
  const plaintextFiles = decryptBodyBlob(encrypted, bek);

  let yamlDst: string | undefined;
  const keysDir = join(targetDir, "keys");

  for (const [name, data] of Object.entries(plaintextFiles)) {
    const rel = name.startsWith("body/") ? name.slice("body/".length) : name;
    if (rel === "tn.yaml") {
      const dst = join(targetDir, "tn.yaml");
      mkdirSync(dirname(dst), { recursive: true });
      writeFileSync(dst, data);
      yamlDst = dst;
    } else if (rel === "WARNING_CONTAINS_PRIVATE_KEYS") {
      const dst = join(targetDir, "WARNING_CONTAINS_PRIVATE_KEYS");
      mkdirSync(dirname(dst), { recursive: true });
      writeFileSync(dst, data);
    } else {
      if (!existsSync(keysDir)) mkdirSync(keysDir, { recursive: true });
      const dst = join(keysDir, basename(rel));
      writeFileSync(dst, data);
    }
  }

  if (yamlDst === undefined) {
    throw new Error(
      "restoreKeystoreTo: decrypted body has no 'body/tn.yaml'. " +
        "Inventory: " +
        JSON.stringify(Object.keys(plaintextFiles)),
    );
  }
  return yamlDst;
}

// Quiet unused-import warning when only some helpers are used.
void readFileSync;
