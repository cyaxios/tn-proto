// AWK/BEK whole-body vault crypto — TS port of the SUPPORTED model
// (D-20 per-account AWK / per-project BEK, D-22 passphrase fallback).
//
// 1:1 with the byte-exact Python reference
// `tn_proto/python/tn/wallet_restore_passphrase.py` and the browser
// `tnproto-org/static/credentials/wrap_unwrap.js`. The three AAD strings
// and the PBKDF2 params MUST match across Python / browser / TS or
// unwrapping fails.
//
// Key hierarchy:  credential_key --wraps--> AWK --wraps--> BEK --encrypts--> body
//   - credential_key: PBKDF2-SHA256(passphrase, salt, iters) [or passkey PRF, browser-only]
//   - AWK (Account Wrapping Key): 32 random bytes, one per account
//   - BEK (Body Encryption Key):  32 random bytes, one per project
//   - body: the STORED zip of body/<name> entries, AES-256-GCM under BEK
//
// This module is pure crypto (Web Crypto only, no network/node:*); the
// vault GETs that feed it live in the client + the wallet verb.

import {
  importEmk,
  deriveEmkFromPassphrase,
  wrapBytes,
  unwrapBytes,
} from "../core/emk.js";
import { b64ToBytes } from "../core/encoding.js";

const _enc = new TextEncoder();
/** AAD pinning the AWK wrap layer (AWK under credential key). */
export const AAD_AWK_WRAP = _enc.encode("tn-vault-awk-wrap-v1");
/** AAD pinning the BEK wrap layer (BEK under AWK). */
export const AAD_BEK_WRAP = _enc.encode("tn-vault-bek-wrap-v1");
// NOTE: the project BODY is encrypted under the BEK with NO AAD, as a
// `nonce||ct` frame — that's what Python's `_decrypt_blob_with_bek`
// expects and what `core/body_encryption.ts` produces. Only the two
// WRAP layers above are AAD-pinned. (The newer browser binds an
// AAD `tn-vault-body-v1` to the body, which diverges from Python; we
// follow Python.)

export class AwkBekError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AwkBekError";
  }
}

/** PBKDF2-SHA256 credential key from a passphrase. Mirror of Python
 * `_derive_credential_key_pbkdf2`; refuses < 10000 iterations (the
 * browser uses >= 300k) so a low-iteration fixture can't slip through. */
export async function deriveCredentialKeyPbkdf2(
  passphrase: string,
  saltBytes: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  if (iterations < 10_000) {
    throw new AwkBekError(`refusing PBKDF2 with iterations=${iterations} (<10000)`);
  }
  return deriveEmkFromPassphrase(passphrase, saltBytes, iterations);
}

/** AES-256-GCM unwrap (wire b64 fields) to exactly 32 raw bytes. */
async function _unwrap32(
  key: CryptoKey,
  wrappedB64: string,
  nonceB64: string,
  aad: Uint8Array,
  what: string,
): Promise<Uint8Array> {
  let out: Uint8Array;
  try {
    out = await unwrapBytes(key, { ciphertext_b64: wrappedB64, nonce_b64: nonceB64 }, aad);
  } catch {
    throw new AwkBekError(`unwrap ${what} failed (wrong passphrase or KDF mismatch)`);
  }
  if (out.length !== 32) {
    throw new AwkBekError(`unwrapped ${what} has wrong length (${out.length})`);
  }
  return out;
}

/** The credential row's wrapping material (server `?include=wrap` shape). */
export interface CredentialWrap {
  kdf: string;
  kdf_params?: { salt_b64?: string; iterations?: number; iter?: number; [k: string]: unknown };
  wrapped_account_key_b64: string;
  wrap_nonce_b64: string;
}

/** The project's wrapped-key row (GET /projects/{id}/wrapped-key shape). */
export interface WrappedKeyRow {
  wrapped_bek_b64: string;
  wrap_nonce_b64: string;
}

/** Full passphrase-only BEK derivation from already-fetched material.
 * Pure (no network) so it is unit/parity-testable in isolation. Mirror
 * of Python `_derive_bek_via_passphrase` minus the two GETs. Returns the
 * raw 32-byte BEK. */
export async function deriveAwkFromMaterial(
  passphrase: string,
  cred: CredentialWrap,
): Promise<Uint8Array> {
  if (cred.kdf !== "pbkdf2-sha256") {
    throw new AwkBekError(
      `credential KDF ${JSON.stringify(cred.kdf)} not supported in CLI; use the browser flow`,
    );
  }
  const params = cred.kdf_params ?? {};
  const saltB64 = params.salt_b64;
  if (!saltB64) throw new AwkBekError("credential row missing kdf_params.salt_b64");
  const iters = Number(params.iterations ?? params.iter ?? 300_000);

  const credKey = await deriveCredentialKeyPbkdf2(passphrase, b64ToBytes(saltB64), iters);
  return _unwrap32(
    credKey, cred.wrapped_account_key_b64, cred.wrap_nonce_b64, AAD_AWK_WRAP, "AWK",
  );
}

/** Unwrap the project BEK using an already-derived/cached AWK — skips the
 * passphrase→AWK step (the cached-credential push/sync path). Mirror of the
 * second half of {@link deriveBekFromMaterial} / Python's `_aes_gcm_unwrap`
 * under `AAD_BEK_WRAP`. */
export async function bekFromAwk(
  awk: Uint8Array,
  wrapped: WrappedKeyRow,
): Promise<Uint8Array> {
  const awkKey = await importEmk(awk);
  return _unwrap32(awkKey, wrapped.wrapped_bek_b64, wrapped.wrap_nonce_b64, AAD_BEK_WRAP, "BEK");
}

export async function deriveBekFromMaterial(
  passphrase: string,
  cred: CredentialWrap,
  wrapped: WrappedKeyRow,
): Promise<Uint8Array> {
  const awk = await deriveAwkFromMaterial(passphrase, cred);
  return bekFromAwk(awk, wrapped);
}

/** Wrap a fresh BEK under the AWK (for the push/mint side). Returns the
 * wire field names the wrapped-key route expects. */
export async function wrapBekUnderAwk(
  awk: Uint8Array,
  bek: Uint8Array,
): Promise<{ wrapped_bek_b64: string; wrap_nonce_b64: string }> {
  const blob = await wrapBytes(await importEmk(awk), bek, AAD_BEK_WRAP);
  return { wrapped_bek_b64: blob.ciphertext_b64, wrap_nonce_b64: blob.nonce_b64 };
}
