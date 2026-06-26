// Port of tn_proto/python/tn/wallet_restore.py — multi-device restore
// (account-bound flow).
//
// PHASE 2a (this file): the "given a BEK, fetch + decrypt + unpack"
// core. The full WebAuthn-PRF loopback (TransferToken from
// wallet_restore_loopback.py) is NOT ported here — that lands as a
// follow-up. With this MVP a caller who obtained the BEK out-of-band
// (e.g. via the browser publisher) can hydrate a fresh device.
//
// Wire shape:
//   GET /api/v1/projects/{id}/encrypted-blob -> {ciphertext_b64}
//   The bytes are AES-256-GCM: [12-byte nonce][ciphertext + 16-byte tag]
//   The 32-byte BEK decrypts. No AAD.
//
// Plaintext can be a STORED zip (PK\x03\x04 magic) or the LEGACY-COMPAT
// uint32-framed format. Both are handled to mirror Python.

import { createDecipheriv } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";
import { Buffer } from "node:buffer";
import { unzipSync } from "fflate";

import {
  deriveBekFromMaterial,
  type CredentialWrap,
  type WrappedKeyRow,
} from "../vault/awk_bek.js";
import { VaultClient, vaultIdentityFromDeviceKey } from "../vault/client.js";
import { Identity } from "../identity.js";
import { unseal } from "./sealing.js";
import { parse as parseYaml } from "yaml";
import { USER_AGENT } from "../version.js";

const DEFAULT_HEADERS: Record<string, string> = {
  "User-Agent": USER_AGENT,
  Accept: "application/json, application/octet-stream",
};

export class RestoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RestoreError";
  }
}

export interface RestoreOptions {
  /** Vault base URL — e.g. http://localhost:38790. */
  vaultUrl: string;
  /** Project id whose encrypted blob to fetch. */
  projectId: string;
  /** OAuth bearer token authorizing the read. */
  bearer: string;
  /** 32-byte BEK (Backup Encryption Key) that decrypts the blob. */
  bek: Uint8Array;
  /** Output directory for restored files. Created if missing. */
  outDir: string;
  /** Optional fetch override (tests). */
  fetchImpl?: typeof fetch;
}

export interface RestoreResult {
  outDir: string;
  projectId: string;
  filesWritten: string[];
  rawBlobPath: string | null;
  notes: string[];
}

/** Decode base64 (standard or url-safe, with or without padding). */
function _b64decodeLoose(value: string): Uint8Array {
  if (typeof value !== "string") {
    throw new RestoreError("expected base64 string");
  }
  // Convert url-safe to standard.
  let s = value.replace(/-/g, "+").replace(/_/g, "/");
  // Pad.
  const pad = (-s.length) % 4;
  s += "=".repeat(pad < 0 ? pad + 4 : pad);
  try {
    return new Uint8Array(Buffer.from(s, "base64"));
  } catch (e) {
    throw new RestoreError(`invalid base64: ${(e as Error).message}`);
  }
}

/** GET the encrypted-blob ciphertext bytes for `projectId`. */
async function fetchEncryptedBlob(opts: {
  vaultUrl: string;
  projectId: string;
  bearer: string;
  fetchImpl?: typeof fetch;
}): Promise<Uint8Array> {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const base = opts.vaultUrl.replace(/\/+$/, "");
  const url = `${base}/api/v1/projects/${encodeURIComponent(opts.projectId)}/encrypted-blob`;
  const headers: Record<string, string> = {
    ...DEFAULT_HEADERS,
    Authorization: `Bearer ${opts.bearer}`,
  };
  let resp = await fetchImpl(url, { method: "GET", headers });

  // 404 fallback: try the legacy encrypted-backup endpoint.
  if (resp.status === 404) {
    const legacyUrl = `${base}/api/v1/projects/${encodeURIComponent(opts.projectId)}/encrypted-backup`;
    resp = await fetchImpl(legacyUrl, { method: "GET", headers });
    if (resp.status === 404) {
      throw new RestoreError(
        `encrypted blob not found for project ${opts.projectId} ` +
          `(both /encrypted-blob and /encrypted-backup returned 404)`,
      );
    }
  }

  if (!resp.ok) {
    const snippet = (await resp.text()).slice(0, 200);
    throw new RestoreError(`vault returned HTTP ${resp.status} for encrypted blob: ${snippet}`);
  }

  let doc: unknown;
  try {
    doc = await resp.json();
  } catch (e) {
    throw new RestoreError(`vault returned non-JSON for encrypted blob: ${(e as Error).message}`);
  }
  if (!doc || typeof doc !== "object") {
    throw new RestoreError("encrypted blob response is not a JSON object");
  }
  const d = doc as Record<string, unknown>;
  const ctB64 = (d.ciphertext_b64 ?? d.ciphertext) as unknown;
  if (typeof ctB64 !== "string" || !ctB64) {
    throw new RestoreError("encrypted blob response missing ciphertext field");
  }
  return _b64decodeLoose(ctB64);
}

/**
 * Decrypt `blob` (12-byte nonce ++ ciphertext+tag) under a 32-byte BEK.
 * Mirrors Python `_decrypt_blob_with_bek`. AES-256-GCM, no AAD.
 */
export function decryptBlobWithBek(blob: Uint8Array, bek: Uint8Array): Uint8Array {
  if (!(bek instanceof Uint8Array) || bek.length !== 32) {
    throw new RestoreError("BEK must be 32 bytes");
  }
  if (blob.length < 12 + 16) {
    throw new RestoreError(`ciphertext too short (${blob.length} bytes; need nonce+tag)`);
  }
  const nonce = blob.subarray(0, 12);
  // Last 16 bytes are the GCM auth tag; node's crypto wants ct + tag split.
  const ct = blob.subarray(12, blob.length - 16);
  const tag = blob.subarray(blob.length - 16);
  try {
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(bek), Buffer.from(nonce));
    decipher.setAuthTag(Buffer.from(tag));
    const out = Buffer.concat([decipher.update(Buffer.from(ct)), decipher.final()]);
    return new Uint8Array(out);
  } catch (e) {
    throw new RestoreError(
      `decryption failed (wrong BEK or corrupted blob): ${(e as Error).constructor.name}`,
    );
  }
}

/**
 * Try to parse plaintext as either a STORED zip (PK\x03\x04 magic) OR the
 * LEGACY-COMPAT-2026-04-29 frame. Returns null if neither.
 * For the zip path we use the same browser-safe ZIP reader as the rest of
 * the TypeScript SDK instead of maintaining a second local ZIP parser.
 */
export function tryUnpackExportFrame(plaintext: Uint8Array): Map<string, Uint8Array> | null {
  // ── Path 1: STORED zip (PK\x03\x04) ──────────────────────────
  if (plaintext.length >= 4 && plaintext[0] === 0x50 && plaintext[1] === 0x4b && plaintext[2] === 0x03 && plaintext[3] === 0x04) {
    try {
      return _unpackStoredZip(plaintext);
    } catch {
      return null;
    }
  }

  // ── Path 2: LEGACY-COMPAT-2026-04-29 frame ───────────────────
  // uint32_be count, then for each member: uint32_be name_len + name + uint32_be data_len + data.
  if (plaintext.length < 4) return null;
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  const count = view.getUint32(0, false);
  if (count === 0 || count > 4096) return null;

  const out = new Map<string, Uint8Array>();
  let pos = 4;
  for (let i = 0; i < count; i += 1) {
    if (pos + 4 > plaintext.length) return null;
    const nameLen = view.getUint32(pos, false);
    pos += 4;
    if (nameLen === 0 || nameLen > 1024 || pos + nameLen > plaintext.length) return null;
    let name: string;
    try {
      name = new TextDecoder("utf-8", { fatal: true }).decode(plaintext.subarray(pos, pos + nameLen));
    } catch {
      return null;
    }
    pos += nameLen;

    if (pos + 4 > plaintext.length) return null;
    const dataLen = view.getUint32(pos, false);
    pos += 4;
    if (pos + dataLen > plaintext.length) return null;
    out.set(name, new Uint8Array(plaintext.subarray(pos, pos + dataLen)));
    pos += dataLen;
  }
  if (pos !== plaintext.length) return null;
  return out;
}

function _unpackStoredZip(buf: Uint8Array): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  try {
    for (const [name, data] of Object.entries(unzipSync(buf))) {
      out.set(name, data);
    }
  } catch (err) {
    throw new RestoreError(`invalid zip export frame: ${(err as Error).message}`);
  }
  return out;
}

/** Write decrypted plaintext to disk per the same rules as Python's
 *  `_write_restored_bytes`. Members from a zip/legacy frame get
 *  individual files; otherwise the whole blob lands as `<id>.tnpkg`. */
function writeRestoredBytes(args: {
  plaintext: Uint8Array;
  outDir: string;
  projectId: string;
}): { filesWritten: string[]; rawBlobPath: string | null; notes: string[] } {
  mkdirSync(args.outDir, { recursive: true });
  const filesWritten: string[] = [];
  const notes: string[] = [];

  const members = tryUnpackExportFrame(args.plaintext);
  if (members !== null) {
    for (const [name, data] of [...members.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      // Sanitize against `..` traversal but PRESERVE subpaths — both push
      // sides nest members as `body/keys/<name>` / `body/tn.yaml`, so a
      // flat-only guard (rejecting "/") drops the entire keystore and breaks
      // the Python→TS body restore. Mirror Python's `_write_restored_bytes`:
      // strip `..`, leading slashes, normalize `\`, then mkdir -p the parent.
      const safe = name.replaceAll("..", "").replace(/^\/+/, "").replaceAll("\\", "/");
      if (!safe) {
        notes.push(`skipped member with empty name: ${name}`);
        continue;
      }
      const path = pathResolve(args.outDir, safe);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
      filesWritten.push(path);
    }
    return { filesWritten, rawBlobPath: null, notes };
  }

  // Opaque tnpkg fallback.
  const blobPath = pathResolve(args.outDir, `${args.projectId}.tnpkg`);
  writeFileSync(blobPath, args.plaintext);
  notes.push("plaintext not recognized as export frame; wrote as opaque tnpkg");
  return { filesWritten: [blobPath], rawBlobPath: blobPath, notes };
}

/**
 * Public entry point: fetch encrypted blob, decrypt with BEK, write
 * restored files. Mirrors the Python `_restore_with_token` once the
 * token has already yielded the BEK.
 */
export async function restoreWithBek(opts: RestoreOptions): Promise<RestoreResult> {
  const blob = await fetchEncryptedBlob({
    vaultUrl: opts.vaultUrl,
    projectId: opts.projectId,
    bearer: opts.bearer,
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });
  const plaintext = decryptBlobWithBek(blob, opts.bek);
  const { filesWritten, rawBlobPath, notes } = writeRestoredBytes({
    plaintext,
    outDir: opts.outDir,
    projectId: opts.projectId,
  });
  return {
    outDir: opts.outDir,
    projectId: opts.projectId,
    filesWritten,
    rawBlobPath,
    notes,
  };
}

/**
 * Derive the project BEK from the account passphrase. Mirror of Python
 * `wallet_restore_passphrase._derive_bek_via_passphrase`: GET the
 * credential wrap + the project wrapped-key (via the VaultClient API),
 * then run the PBKDF2 -> unwrap AWK -> unwrap BEK chain (awk_bek). The
 * two wrap layers are AAD-pinned; the body that this BEK later decrypts
 * is NOT (see decryptBlobWithBek).
 */
export async function _deriveBekViaPassphrase(
  client: VaultClient,
  projectId: string,
  passphrase: string,
  opts: { credentialId?: string } = {},
): Promise<Uint8Array> {
  const credOpts: { credentialId?: string } = {};
  if (opts.credentialId !== undefined) credOpts.credentialId = opts.credentialId;
  const cred = (await client.getCredentialWrap(credOpts)) as unknown as CredentialWrap;
  const wrapped = (await client.getWrappedKey(projectId)) as unknown as WrappedKeyRow;
  return deriveBekFromMaterial(passphrase, cred, wrapped);
}

/**
 * Restore a project via the passphrase fallback. Mirror of the
 * Python CLI's `_restore_via_passphrase`: derive the BEK from the
 * passphrase, then fetch + decrypt + write through the existing
 * `restoreWithBek` (frame, no AAD). Headless — no browser needed.
 */
export async function restoreViaPassphrase(
  client: VaultClient,
  opts: { projectId: string; passphrase: string; outDir: string; credentialId?: string },
): Promise<RestoreResult> {
  if (!client.token) {
    throw new RestoreError("restoreViaPassphrase: client is not authenticated");
  }
  const deriveOpts: { credentialId?: string } = {};
  if (opts.credentialId !== undefined) deriveOpts.credentialId = opts.credentialId;
  const bek = await _deriveBekViaPassphrase(client, opts.projectId, opts.passphrase, deriveOpts);
  return restoreWithBek({
    vaultUrl: client.baseUrl,
    projectId: opts.projectId,
    bearer: client.token,
    bek,
    outDir: opts.outDir,
  });
}

export interface RestoreViaLoopbackOptions {
  /** Vault base URL — e.g. https://vault.tn-proto.org. */
  vaultUrl: string;
  /** Output directory for restored files. */
  outDir: string;
  /** Token wait timeout (ms). Default 300_000. */
  timeoutMs?: number;
  /** Override the loopback state nonce / port (tests). */
  state?: string;
  loopbackPort?: number;
  /** Called with the `/restore?...` URL the operator must open in a browser. */
  onRestoreUrl?: (url: string) => void;
  /** Optional fetch override (tests). */
  fetchImpl?: typeof fetch;
}

/**
 * Full multi-device restore via the browser loopback dance. Mirrors
 * Python's `tn wallet restore`: start a loopback receiver, hand the
 * operator a `/restore` URL, wait for the browser to POST the
 * TransferToken (the browser does the passkey-PRF/AWK unwrap and returns
 * the raw BEK), then fetch + decrypt + write the keystore.
 *
 * The headless CLI never needs the account login credential — the browser
 * performs the unwrap and delivers the raw BEK over loopback (127.0.0.1).
 */
export async function restoreViaLoopback(
  opts: RestoreViaLoopbackOptions,
): Promise<RestoreResult & { accountId: string }> {
  const { LoopbackReceiver } = await import("./restore_loopback.js");
  const base = opts.vaultUrl.replace(/\/+$/, "");
  const startOpts: { allowOrigin: string; state?: string; port?: number } = { allowOrigin: base };
  if (opts.state !== undefined) startOpts.state = opts.state;
  if (opts.loopbackPort !== undefined) startOpts.port = opts.loopbackPort;
  const rx = await LoopbackReceiver.start(startOpts);
  try {
    const restoreUrl =
      `${base}/restore?return_to=${encodeURIComponent(rx.callbackUrl)}` +
      `&state=${encodeURIComponent(rx.state)}`;
    opts.onRestoreUrl?.(restoreUrl);

    const waitOpts: { timeoutMs?: number } = {};
    if (opts.timeoutMs !== undefined) waitOpts.timeoutMs = opts.timeoutMs;
    const token = await rx.waitForToken(waitOpts);

    const bek = _b64decodeLoose(token.rawBekB64);
    const restoreOpts: RestoreOptions = {
      vaultUrl: base,
      projectId: token.projectId,
      bearer: token.vaultJwt,
      bek,
      outDir: opts.outDir,
    };
    if (opts.fetchImpl !== undefined) restoreOpts.fetchImpl = opts.fetchImpl;
    const result = await restoreWithBek(restoreOpts);
    return { ...result, accountId: token.accountId };
  } finally {
    rx.shutdown();
  }
}

// ---------------------------------------------------------------------------
// Legacy mnemonic restore (per-file sealing model). Mirrors Python
// `tn.wallet.restore_ceremony` + the `tn wallet restore --mnemonic` CLI path.
// The per-file sealing is deprecated in favour of the whole-body BEK model
// above; this port exists for recovering pre-account-bound backups.
// ---------------------------------------------------------------------------

/**
 * Pull one project's sealed files into `opts.outDir`, unsealing each under the
 * BIP-39-derived `wrapKey` with the per-file AAD `(did, ceremonyId, fileName)`.
 * Mirrors Python `restore_ceremony`: download `tn.yaml` first trusting its
 * embedded AAD to read `ceremony.id`, then pull the rest with strict AAD.
 * Writes `tn.yaml` to the target root and other files to `.tn/keys/`.
 */
export async function restoreCeremony(
  client: VaultClient,
  projectId: string,
  opts: { outDir: string; wrapKey: Uint8Array; did: string },
): Promise<RestoreResult> {
  mkdirSync(opts.outDir, { recursive: true });
  const keystore = pathResolve(opts.outDir, ".tn", "keys");
  mkdirSync(keystore, { recursive: true });

  const filesWritten: string[] = [];
  const notes: string[] = [];

  const manifest = await client.restoreManifest(projectId);
  const files = Array.isArray(manifest["files"])
    ? (manifest["files"] as Array<Record<string, unknown>>)
    : [];

  const yamlEntry = files.find((f) => f["name"] === "tn.yaml");
  if (yamlEntry === undefined) {
    throw new RestoreError(`project ${projectId} restore manifest has no tn.yaml`);
  }
  // tn.yaml first, trusting the blob's embedded AAD (ceremony id not known yet).
  const yamlBytes = unseal(await client.downloadSealed(projectId, "tn.yaml"), {
    wrapKey: opts.wrapKey,
  });
  writeFileSync(pathResolve(opts.outDir, "tn.yaml"), Buffer.from(yamlBytes));
  const doc = (parseYaml(Buffer.from(yamlBytes).toString("utf8")) ?? {}) as Record<string, unknown>;
  const ceremonyId = String((doc["ceremony"] as Record<string, unknown> | undefined)?.["id"] ?? "");
  if (!ceremonyId) {
    throw new RestoreError("restored tn.yaml has no ceremony.id");
  }

  // Remaining files with strict AAD verification.
  for (const f of files) {
    const name = typeof f["name"] === "string" ? (f["name"] as string) : "";
    if (!name) continue;
    try {
      const plain = unseal(await client.downloadSealed(projectId, name), {
        wrapKey: opts.wrapKey,
        expectedDid: opts.did,
        expectedCeremonyId: ceremonyId,
        expectedFileName: name,
      });
      const dst = name === "tn.yaml" ? pathResolve(opts.outDir, "tn.yaml") : pathResolve(keystore, name);
      writeFileSync(dst, Buffer.from(plain));
      filesWritten.push(name);
    } catch (e) {
      notes.push(`WARN ${name}: ${(e as Error).message}`);
    }
  }

  return { outDir: opts.outDir, projectId, filesWritten, rawBlobPath: null, notes };
}

export interface RestoreViaMnemonicOptions {
  /** BIP-39 recovery phrase. */
  mnemonic: string;
  /** Optional BIP-39 passphrase (the "25th word"). */
  passphrase?: string;
  /** Vault base URL. Omit to restore the identity only (no project pull). */
  vaultUrl?: string;
  /** Base output dir; each project lands in a `<name|id>` subdir. */
  outDir?: string;
  /** Where to write identity.json. Defaults to the standard identity path. */
  identityPath?: string;
  /** Restrict to these project ids. Empty/omitted => all linked projects. */
  projectIds?: string[];
}

export interface RestoreViaMnemonicResult {
  did: string;
  identityPath: string;
  restored: RestoreResult[];
}

/**
 * Recover identity + ceremonies from a BIP-39 mnemonic. Mirrors Python
 * `cmd_wallet_restore`'s legacy path: derive the identity, write identity.json,
 * and (when a vault is given) pull every linked project's sealed files,
 * unsealing under the identity's vault-wrap key.
 */
export async function restoreViaMnemonic(
  opts: RestoreViaMnemonicOptions,
): Promise<RestoreViaMnemonicResult> {
  const fromOpts: { passphrase?: string; path?: string } = {};
  if (opts.passphrase !== undefined) fromOpts.passphrase = opts.passphrase;
  if (opts.identityPath !== undefined) fromOpts.path = opts.identityPath;
  const id = Identity.fromMnemonic(opts.mnemonic, fromOpts);

  if (opts.vaultUrl !== undefined) id.linkedVault = opts.vaultUrl;
  const identityPath = id.save(opts.identityPath);

  if (opts.vaultUrl === undefined) {
    return { did: id.did, identityPath, restored: [] };
  }

  const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(id.deviceKey()), opts.vaultUrl);
  const projects = await client.listProjects();
  const wrapKey = id.vaultWrapKey();
  const baseDir = opts.outDir ?? pathResolve(process.cwd(), "restored");
  const restrict = opts.projectIds && opts.projectIds.length > 0 ? new Set(opts.projectIds) : null;

  const restored: RestoreResult[] = [];
  for (const p of projects) {
    const pid = String(p["id"] ?? p["_id"] ?? "");
    if (!pid || (restrict !== null && !restrict.has(pid))) continue;
    const sub = pathResolve(baseDir, String(p["name"] ?? pid));
    restored.push(await restoreCeremony(client, pid, { outDir: sub, wrapKey, did: id.did }));
  }
  return { did: id.did, identityPath, restored };
}

/** Internals exposed for tests. */
export const _internals = {
  b64decodeLoose: _b64decodeLoose,
  fetchEncryptedBlob,
  writeRestoredBytes,
};
