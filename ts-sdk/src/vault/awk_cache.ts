// AWK cache — derive the account AWK from a passphrase once, persist it.
//
// `tn account connect --passphrase` runs {@link cacheAccountAwk}: authenticate
// as the device DID, GET the account credential wrap, run
// passphrase -> credential-key -> AWK (deriveAwkFromMaterial), and store ONLY
// the 32-byte account-scoped AWK in the machine CredentialStore ("token, not
// password"). Warm-attach / `wallet sync` then read it ({@link loadCachedAwk})
// so the body backup runs non-interactively after a one-time connect.
//
// 1:1 with Python `tn._init_attach.cache_account_awk` + the cached-AWK read in
// `attach_or_sync`. The crypto lives in awk_bek.ts, the storage in
// credential_store.ts; this module is the thin network+derive+store glue.

import type { DeviceKey } from "../core/signing.js";
import { VaultClient, vaultIdentityFromDeviceKey } from "./client.js";
import { deriveAwkFromMaterial, type CredentialWrap } from "./awk_bek.js";
import {
  awkKeyName,
  defaultCredentialStore,
  type CredentialStore,
} from "./credential_store.js";

/** Options for {@link cacheAccountAwk}: an injectable store + fetch (tests). */
export interface CacheAccountAwkOptions {
  store?: CredentialStore | undefined;
  fetchImpl?: typeof fetch | undefined;
}

/**
 * Derive the account AWK from `passphrase` and cache it under
 * `awkKeyName(accountId)` — the "connect once, logged in for good" step.
 *
 * Authenticates as the device DID (challenge JWT) to read the credential
 * wrap, runs `passphrase -> credential-key -> AWK`, and stores ONLY the
 * derived AWK (never the passphrase). Throws on any vault / derivation
 * failure (wrong passphrase, KDF mismatch) so the caller decides how loudly
 * to report it. Mirror of Python `_init_attach.cache_account_awk`.
 */
export async function cacheAccountAwk(
  deviceKey: DeviceKey,
  vaultUrl: string,
  passphrase: string,
  accountId: string,
  opts: CacheAccountAwkOptions = {},
): Promise<void> {
  const client = await VaultClient.forIdentity(
    vaultIdentityFromDeviceKey(deviceKey),
    vaultUrl,
    opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {},
  );
  let awk: Uint8Array;
  try {
    const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
    awk = await deriveAwkFromMaterial(passphrase, cred);
  } finally {
    // VaultClient holds no persistent handle today, but close if a future
    // backend adds one (mirrors the finally-close discipline in cache paths).
    (client as { close?: () => void }).close?.();
  }
  (opts.store ?? defaultCredentialStore()).set(awkKeyName(accountId), awk);
}

/**
 * Read the cached AWK for `accountId`, or `null` when none is cached / the
 * store is unreadable. Mirror of the cached-AWK read in Python
 * `attach_or_sync`. Never throws — a broken store must not break init.
 */
export function loadCachedAwk(
  accountId: string,
  opts: { store?: CredentialStore | undefined } = {},
): Uint8Array | null {
  try {
    return (opts.store ?? defaultCredentialStore()).get(awkKeyName(accountId));
  } catch {
    return null;
  }
}
