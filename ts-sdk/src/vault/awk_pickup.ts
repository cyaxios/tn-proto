// Account-level AWK single-pickup — redeem a pre-sealed AWK wrap from
// the vault's /api/v1/account/awk-pickups/:keyIdB64 endpoint and cache
// the resulting 32-byte AWK in a CredentialStore.
//
// Mirrors python/tn/vault/awk_pickup.py::redeem_awk_pickup (awk-autocache
// branch). Takes `vaultBase` directly — there is no vault-DID resolution
// step (matches the Python fix).

import { challengeVerify } from "../runtime/bootstrap_api_key.js";
import { unsealBekFromWrap } from "../core/recipient_seal.js";
import { DeviceKey } from "../core/signing.js";
import {
  defaultCredentialStore,
  awkKeyName,
  type CredentialStore,
} from "./credential_store.js";
import type { RecipientWrap } from "../core/recipient_seal.js";

/** AAD that binds an AWK pickup wrap to its account.
 *
 * Matches the Python constant:
 *   AAD = f"tn-account-awk-pickup-v1:{account_id}".encode()
 */
export function awkPickupAad(accountId: string): Uint8Array {
  return new TextEncoder().encode(`tn-account-awk-pickup-v1:${accountId}`);
}

/**
 * Redeem a pre-sealed AWK pickup from the vault and store it locally.
 *
 * Flow:
 *   1. Derive the device DID from `opts.deviceSeed`.
 *   2. Run `/auth/challenge` + `/auth/verify` to mint a JWT.
 *   3. GET `/api/v1/account/awk-pickups/{keyIdB64}` with the JWT.
 *   4. Unseal the `wrap` field with the device seed and account AAD.
 *   5. Verify the unwrapped key is 32 bytes, then cache it.
 *
 * Returns `true` on success, `false` on any failure (network, auth,
 * bad wrap, wrong length). Never throws.
 */
export async function redeemAwkPickup(opts: {
  vaultBase: string;
  deviceSeed: Uint8Array;
  accountId: string;
  keyIdB64: string;
  store?: CredentialStore;
  fetchImpl?: typeof fetch;
  /** Already-minted vault JWT for this device DID. When given, the redeem
   * reuses it instead of running its own challenge/verify handshake. */
  token?: string;
}): Promise<boolean> {
  const f = opts.fetchImpl ?? fetch;
  try {
    let token: string | null = opts.token ?? null;
    if (!token) {
      const did = DeviceKey.fromSeed(opts.deviceSeed).did;

      // Temporarily replace globalThis.fetch so challengeVerify (which
      // uses the module-level global) routes through the injected fetchImpl.
      const originalFetch = globalThis.fetch;
      if (opts.fetchImpl) {
        globalThis.fetch = opts.fetchImpl as typeof globalThis.fetch;
      }
      try {
        token = await challengeVerify(opts.vaultBase, did, opts.deviceSeed);
      } finally {
        if (opts.fetchImpl) {
          globalThis.fetch = originalFetch;
        }
      }
    }

    if (!token) return false;

    const res = await f(
      `${opts.vaultBase}/api/v1/account/awk-pickups/${opts.keyIdB64}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (res.status !== 200) return false;

    const body = (await res.json()) as { wrap: unknown };
    const aad = awkPickupAad(opts.accountId);
    const awk = await unsealBekFromWrap(
      body.wrap as RecipientWrap,
      opts.deviceSeed,
      aad,
    );
    if (awk.length !== 32) return false;

    const store = opts.store ?? defaultCredentialStore();
    store.set(awkKeyName(opts.accountId), awk);
    return true;
  } catch {
    return false;
  }
}

/**
 * Drain the vault's AWK inbox for pickups addressed to THIS device DID and
 * redeem+cache each. Returns the account_ids whose AWK was cached (usually 0
 * or 1). Never throws — a degraded vault just means "nothing drained, retry
 * next sync".
 *
 * This is the device-pull half of the non-blocking flow: the browser
 * recipient-seals an AWK pickup to this DID at claim/approve time; the sync
 * loop (or a login fallback) drains it whenever it shows up.
 *
 * Mirrors python/tn/awk_pickup.py::drain_pending_awk.
 */
export async function drainPendingAwk(opts: {
  vaultBase: string;
  deviceSeed: Uint8Array;
  store?: CredentialStore;
  fetchImpl?: typeof fetch;
  /** Already-minted vault JWT for this device DID. When given, the drain
   * (and any redeems) reuse it — one challenge/verify per sync cycle. */
  token?: string;
}): Promise<string[]> {
  const f = opts.fetchImpl ?? fetch;
  try {
    let token: string | null = opts.token ?? null;
    if (!token) {
      const did = DeviceKey.fromSeed(opts.deviceSeed).did;

      const originalFetch = globalThis.fetch;
      if (opts.fetchImpl) {
        globalThis.fetch = opts.fetchImpl as typeof globalThis.fetch;
      }
      try {
        token = await challengeVerify(opts.vaultBase, did, opts.deviceSeed);
      } finally {
        if (opts.fetchImpl) {
          globalThis.fetch = originalFetch;
        }
      }
    }
    if (!token) return [];

    const res = await f(
      `${opts.vaultBase}/api/v1/account/awk-pickups/pending`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (res.status !== 200) return [];

    const body = (await res.json()) as {
      pending?: Array<{ key_id?: string; account_id?: string }>;
    };
    const cached: string[] = [];
    for (const p of body.pending ?? []) {
      const acct = p.account_id;
      const kid = p.key_id;
      if (!acct || !kid) continue;
      const ok = await redeemAwkPickup({
        vaultBase: opts.vaultBase,
        deviceSeed: opts.deviceSeed,
        accountId: acct,
        keyIdB64: kid,
        token,
        ...(opts.store ? { store: opts.store } : {}),
        ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
      });
      if (ok) cached.push(acct);
    }
    return cached;
  } catch {
    return [];
  }
}
