// Shared helpers for the LIVE dev-vault round-trip tests
// (wallet_sync_live, wallet_restore_live, account_connect_live).
//
// These tests run against a real dev vault on http://127.0.0.1:34987
// (started with TN_DEV_AUTH_BYPASS=1). They are CI-safe: every test file
// probes the vault first and `test.skip`s cleanly when it is unreachable.
//
// The vault's dev shortcuts (mirrored from scripts/plumb_awk_bek.mts):
//   POST /api/v1/dev/login  {handle} -> {account_id, token, passphrase?}
//     The deterministic passphrase is `tn-dev-<handle>` when absent.
//     The dev account auto-provisions a PBKDF2-SHA256 "dev passphrase"
//     credential whose AWK material unwraps with that passphrase — so the
//     headless restoreViaPassphrase derive path works without a browser.

const C = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32

/** The dev vault base URL. Override with PLUMB_VAULT. */
export const VAULT_BASE = process.env.PLUMB_VAULT ?? "http://127.0.0.1:34987";

/** A throwaway ULID-ish 26-char id for per-test project isolation. */
export function ulidish(): string {
  const r = crypto.getRandomValues(new Uint8Array(26));
  let s = "";
  for (let i = 0; i < 26; i += 1) s += C[r[i]! % 32];
  return s;
}

/** A unique dev handle per test run so accounts never collide. */
export function uniqueHandle(stem: string): string {
  return `${stem}-${ulidish().slice(0, 12).toLowerCase()}`;
}

/**
 * Probe the dev vault. Returns true when /dev/login answers — i.e. the
 * vault is up AND TN_DEV_AUTH_BYPASS is enabled (the route is only mounted
 * then). Returns false on any connection error, so the suite skips cleanly.
 */
export async function vaultReachable(base: string = VAULT_BASE): Promise<boolean> {
  try {
    const r = await fetch(`${base}/api/v1/dev/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ handle: "reachprobe" }),
    });
    return r.ok;
  } catch {
    return false;
  }
}

export interface DevLogin {
  accountId: string;
  token: string;
  passphrase: string;
}

/** Mint a fresh dev account + token + AWK passphrase for `handle`. */
export async function devLogin(handle: string, base: string = VAULT_BASE): Promise<DevLogin> {
  const resp = await fetch(`${base}/api/v1/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle }),
  });
  if (!resp.ok) throw new Error(`dev/login ${resp.status}: ${await resp.text()}`);
  const dev = (await resp.json()) as { account_id: string; token: string; passphrase?: string };
  return {
    accountId: dev.account_id,
    token: dev.token,
    passphrase: dev.passphrase ?? `tn-dev-${handle}`,
  };
}

/**
 * Mint a single-use connect code on the dev account. Uses the auth'd mint
 * route POST /api/v1/account/connect-codes (routes_account_connect.py).
 * Returns the code plus the minter's account id + bearer (for assertions).
 */
export async function mintConnectCode(
  handle: string,
  base: string = VAULT_BASE,
): Promise<{ code: string; token: string; accountId: string; projectName: string }> {
  const dev = await devLogin(handle, base);
  const projectName = `live-connect-${ulidish().slice(0, 8)}`;
  const mint = await fetch(`${base}/api/v1/account/connect-codes`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${dev.token}` },
    body: JSON.stringify({ project_name: projectName }),
  });
  if (!mint.ok) throw new Error(`mint connect-code ${mint.status}: ${await mint.text()}`);
  const minted = (await mint.json()) as { code?: string };
  if (!minted.code) throw new Error(`mint response missing code: ${JSON.stringify(minted)}`);
  return { code: minted.code, token: dev.token, accountId: dev.accountId, projectName };
}
