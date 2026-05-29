// Port of tn_proto/python/tn/handlers/vault_push.py::init_upload (the
// pending-claim / claim-URL path, D-19 / D-5).
//
// Builds an AES-256-GCM-encrypted `full_keystore` tnpkg, POSTs it
// UNAUTHENTICATED to `/api/v1/pending-claims`, and returns a claim URL
// whose fragment carries the BEK. The vault never sees the BEK (it lives
// only in the URL fragment, D-5); the browser claim page recovers it and
// decrypts the body locally.
//
// Python parity is the contract: the encrypted-body blob layout is
// produced by `encryptBodyBlob` (mirrors `_encrypt_body_in_place`), and the
// claim URL shape `{base}/claim/{vault_id}#k={password_b64}` matches the
// browser claim page's sessionStorage key (`static/claim/claim.js`).

import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";

import type { NodeRuntime } from "../runtime/node_runtime.js";

/** Result of {@link initUpload}. Mirrors Python's return dict. */
export interface InitUploadResult {
  /** Server-assigned pending-claim id (a ULID). */
  vaultId: string;
  /** ISO-8601 expiry for the pending claim's TTL. */
  expiresAt: string;
  /** `{base}/claim/{vaultId}#k={passwordB64}` — paste into a browser. */
  claimUrl: string;
  /** base64url(BEK) — the fragment value. Returned for tests / reuse. */
  passwordB64: string;
}

export interface InitUploadOptions {
  /** Vault base URL, e.g. `http://localhost:38790`. Trailing slash ok. */
  vaultBase: string;
  /** Override the global fetch (tests). Default: `globalThis.fetch`. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout in ms. Default: 30_000. */
  timeoutMs?: number;
}

/**
 * Build an encrypted `full_keystore` tnpkg and POST it to the vault's
 * unauthenticated pending-claims endpoint, returning a claim URL.
 *
 * Mirrors `tn.handlers.vault_push.init_upload`. The project name (for the
 * vault's project label) and publisher DID are read from the runtime's
 * config; the BEK is freshly minted here and delivered only in the claim
 * URL fragment.
 *
 * @param rt - the active NodeRuntime (an initialized ceremony).
 * @param opts - vault base URL + optional fetch/timeout overrides.
 */
export async function initUpload(
  rt: NodeRuntime,
  opts: InitUploadOptions,
): Promise<InitUploadResult> {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const vaultBase = opts.vaultBase.replace(/\/+$/, "");

  // Fresh 32-byte BEK. base64url (no padding) for the URL fragment —
  // matches Python's `_b64url(bek)`.
  const bek = new Uint8Array(randomBytes(32));
  const passwordB64 = Buffer.from(bek).toString("base64url");

  // Encrypt a full-keystore tnpkg under the BEK into a temp file, read the
  // bytes, then remove the staged file (it carries ciphertext only, but it
  // has no further local use once POSTed).
  const tmpDir = mkdtempSync(join(tmpdir(), "tn-init-upload-"));
  const outPath = join(tmpDir, "init_upload.tnpkg");
  let body: Uint8Array;
  try {
    await rt.exportFullKeystoreEncrypted(bek, outPath);
    body = new Uint8Array(readFileSync(outPath));
  } finally {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* best-effort cleanup */
    }
  }

  // POST to /api/v1/pending-claims — UNAUTHENTICATED (D-19). Send the
  // publisher DID (so the vault can emit a contact_update back at bind
  // time, D-25) and the project name (so the bound project is labelled).
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
  };
  const publisherDid = rt.config.device.device_identity;
  if (publisherDid) headers["X-Publisher-Did"] = publisherDid;
  const projectName = rt.config.projectName;
  if (projectName) headers["X-Project-Name"] = projectName;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetchImpl(`${vaultBase}/api/v1/pending-claims`, {
      method: "POST",
      headers,
      body,
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(
      `init-upload: POST /api/v1/pending-claims returned ${resp.status}: ${text.slice(0, 512)}`,
    );
  }

  const json = (await resp.json()) as { vault_id?: string; expires_at?: string };
  const vaultId = json.vault_id;
  const expiresAt = json.expires_at;
  if (!vaultId || !expiresAt) {
    throw new Error(
      `init-upload: vault accepted the upload but the response was missing ` +
        `vault_id/expires_at: ${JSON.stringify(json)}`,
    );
  }

  // Fragment carries the BEK per D-5; the server never sees this value.
  const claimUrl = `${vaultBase}/claim/${vaultId}#k=${passwordB64}`;
  return { vaultId, expiresAt, claimUrl, passwordB64 };
}
