// AWK/BEK wallet verbs — the middle layer between the CLI and the vault
// API + crypto. The CLI calls these; these call VaultClient API methods
// (never raw HTTP) and the awk_bek crypto primitives.
//
// Logic mirrors Python:
//   - deriveBekViaPassphrase  <- wallet_restore_passphrase._derive_bek_via_passphrase
//   - restoreProjectBody       <- wallet_restore (GET blob -> decrypt under BEK)
//   - pushProjectBody          <- the browser project_saver (encrypt -> PUT If-Match)
//
// Crypto is the SUPPORTED whole-body AWK/BEK model (D-20/D-22), not the
// deprecated per-file sealing.

import { bytesToB64, randomBytes } from "../core/encoding.js";
import {
  deriveAwkFromMaterial,
  deriveBekFromMaterial,
  decryptBody,
  encryptBody,
  wrapBekUnderAwk,
  type CredentialWrap,
  type WrappedKeyRow,
} from "../vault/awk_bek.js";
import { VaultError, type VaultClient } from "../vault/client.js";

export class WalletSyncError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WalletSyncError";
  }
}

/**
 * Full passphrase-only BEK derivation against a live vault. Mirror of
 * Python `_derive_bek_via_passphrase`: GET the credential wrap + the
 * project wrapped-key, then run the pure crypto chain. Returns the raw
 * 32-byte BEK.
 */
export async function deriveBekViaPassphrase(
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
 * Derive the account's AWK from the passphrase (one GET + the PBKDF2 +
 * unwrap chain). Used by the mint path, which needs the AWK to wrap a
 * fresh project BEK.
 */
export async function deriveAwkViaPassphrase(
  client: VaultClient,
  passphrase: string,
  opts: { credentialId?: string } = {},
): Promise<Uint8Array> {
  const credOpts: { credentialId?: string } = {};
  if (opts.credentialId !== undefined) credOpts.credentialId = opts.credentialId;
  const cred = (await client.getCredentialWrap(credOpts)) as unknown as CredentialWrap;
  return deriveAwkFromMaterial(passphrase, cred);
}

/**
 * Mint a project's BEK: generate 32 fresh random bytes, wrap them under
 * the account AWK, and PUT the wrapped-key row. Mirrors what the browser
 * project_minter does (BEK = random32 -> wrapKey(awk, bek) -> PUT
 * wrapped-key). Returns the raw BEK so the caller can immediately
 * encrypt + push a body under it. Must run before the first body PUT
 * (the blob route checks ownership against this row).
 */
export async function mintWrappedKey(
  client: VaultClient,
  projectId: string,
  passphrase: string,
  opts: { credentialId?: string; label?: string; packageDid?: string } = {},
): Promise<Uint8Array> {
  const awk = await deriveAwkViaPassphrase(client, passphrase, opts);
  const bek = randomBytes(32);
  const wrapped = await wrapBekUnderAwk(awk, bek);
  const body: { wrapped_bek_b64: string; wrap_nonce_b64: string; label?: string; package_did?: string } = {
    ...wrapped,
  };
  if (opts.label !== undefined) body.label = opts.label;
  if (opts.packageDid !== undefined) body.package_did = opts.packageDid;
  await client.putWrappedKey(projectId, body);
  return bek;
}

/**
 * Restore a project's decrypted body bytes (the STORED zip of
 * body/<name> entries). Derives the BEK, GETs the encrypted blob, and
 * decrypts under the BEK with AAD `tn-vault-body-v1`. The caller unpacks
 * the zip into a keystore.
 */
export async function restoreProjectBody(
  client: VaultClient,
  projectId: string,
  passphrase: string,
  opts: { credentialId?: string } = {},
): Promise<Uint8Array> {
  const bek = await deriveBekViaPassphrase(client, projectId, passphrase, opts);
  const blob = (await client.getEncryptedBlob(projectId)) as {
    ciphertext_b64?: string;
    nonce_b64?: string;
  };
  if (typeof blob.ciphertext_b64 !== "string" || typeof blob.nonce_b64 !== "string") {
    throw new WalletSyncError(
      `encrypted-blob for ${projectId} missing ciphertext_b64/nonce_b64`,
    );
  }
  return decryptBody(bek, { ciphertext_b64: blob.ciphertext_b64, nonce_b64: blob.nonce_b64 });
}

/**
 * Push (back up) a project body: derive the BEK, encrypt the STORED-zip
 * body under it, and PUT to encrypted-blob-account with optimistic
 * concurrency. Reads the current generation off the existing blob (or
 * uses "*" for the first write, mirroring project_saver). Returns the
 * route's response (carries the new generation).
 */
export async function pushProjectBody(
  client: VaultClient,
  projectId: string,
  passphrase: string,
  bodyZip: Uint8Array,
  opts: { credentialId?: string; bek?: Uint8Array } = {},
): Promise<Record<string, unknown>> {
  const bek =
    opts.bek ?? (await deriveBekViaPassphrase(client, projectId, passphrase, opts));

  // Optimistic-concurrency precondition: current generation, or "*" when
  // there is no blob yet (404).
  let ifMatch: string | number = "*";
  try {
    const cur = (await client.getEncryptedBlob(projectId)) as { generation?: number };
    if (typeof cur.generation === "number") ifMatch = cur.generation;
  } catch (e) {
    if (!(e instanceof VaultError) || e.status !== 404) throw e;
  }

  const enc = await encryptBody(bek, bodyZip);
  const body: Record<string, unknown> = {
    ciphertext_b64: enc.ciphertext_b64,
    nonce_b64: enc.nonce_b64,
    // The salt/kdf fields are informational for this route (the AWK does
    // not derive the BEK) but the schema validates salt length (8..64
    // bytes), so we send a real random 16-byte salt like the browser does.
    salt_b64: bytesToB64(randomBytes(16)),
    kdf: "pbkdf2-sha256",
    kdf_params: { iterations: 1 },
    cipher_suite: "aes-256-gcm",
    bundle_kind: "project-body-v1",
  };
  return client.putEncryptedBlobAccount(projectId, body, { ifMatch });
}
