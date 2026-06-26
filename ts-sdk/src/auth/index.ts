/**
 * tn.auth namespace - account / session / device enrollment (TypeScript).
 *
 * Library-first, mirroring python tn/auth.py: every verb returns an AuthState
 * (or throws AuthError); the CLI (bin/tn-js.mjs) is a thin printer over this.
 * The shared identity-load / vault-resolve / key-cache / enroll logic lives
 * here once. Design:
 * docs/guide/auth-namespace-design.md
 *
 * G1 note (mirrors Python): TN_API_KEY cold-start is keystore-population and
 * ceremony-scoped, so it lives in the init/runtime layer, not account-level
 * `login`. `login` covers TN_VAULT_SESSION_TOKEN > code > accountPassphrase.
 * Browser sign-in is interactive I/O and belongs to the CLI.
 */

export {
  AuthError,
  AuthState,
  VERDICT_MESSAGE,
  computeVerdict,
  type Verdict,
} from "./state.js";

import { AuthError, AuthState } from "./state.js";
import { AccountConnectError, AccountNamespace } from "../account/index.js";
import { Identity } from "../identity.js";
import { VaultClient, VaultError, vaultIdentityFromDeviceKey } from "../vault/client.js";
import { resolveVaultUrl } from "../vault/url.js";
import { cacheAccountAwk, loadCachedAwk } from "../vault/awk_cache.js";
import { awkKeyName, defaultCredentialStore } from "../vault/credential_store.js";

export interface StatusOptions {
  vault?: string;
  verify?: boolean;
}

export interface LoginOptions {
  vault?: string;
  code?: string;
  accountPassphrase?: string;
  interactive?: boolean; // reserved for the CLI browser path
}

export interface ConnectOptions {
  accountPassphrase?: string;
  vault?: string;
}

// ── Shared helpers (the single implementation of each piece) ──────────────

function loadIdentity(): Identity | null {
  try {
    return Identity.load();
  } catch {
    return null; // missing/corrupt reads as "not logged in"
  }
}

function resolveVault(identity: Identity | null, override?: string): string {
  return override ?? identity?.linkedVault ?? resolveVaultUrl();
}

function sessionToken(override?: string | null): string | null {
  return (
    override ??
    process.env.TN_VAULT_SESSION_TOKEN ??
    process.env.TN_VAULT_JWT ??
    null
  );
}

function accountPassphrase(override?: string): string | undefined {
  return override ?? process.env.TN_ACCOUNT_PASSPHRASE;
}

function backupKeyCached(accountId: string | null): boolean {
  if (!accountId) return false;
  try {
    return loadCachedAwk(accountId) != null;
  } catch {
    return false; // a broken store reads as "not cached"
  }
}

async function vaultEnrolled(
  identity: Identity,
  vaultUrl: string,
  token: string | null,
): Promise<boolean> {
  // Best-effort: GET /account/me succeeds only for an account-bound DID.
  try {
    const client = await VaultClient.forIdentity(
      vaultIdentityFromDeviceKey(identity.deviceKey()),
      vaultUrl,
      { sessionToken: token },
    );
    const resp = await client.get("/api/v1/account/me");
    return resp.status === 200;
  } catch {
    return false; // status must never throw
  }
}

async function buildState(
  identity: Identity | null,
  vaultUrl: string,
  verify: boolean,
  token: string | null,
): Promise<AuthState> {
  if (identity === null) {
    return new AuthState(null, null, vaultUrl, false, null, false);
  }
  const accountId = identity.linkedAccountId;
  let enrolled: boolean | null = null;
  if (verify && accountId) {
    enrolled = await vaultEnrolled(identity, vaultUrl, token);
  }
  return new AuthState(
    identity.did,
    accountId,
    vaultUrl,
    accountId != null,
    enrolled,
    backupKeyCached(accountId),
  );
}

async function tryCacheKey(
  identity: Identity,
  vaultUrl: string,
  passphrase: string | undefined,
  accountId: string,
): Promise<void> {
  if (!passphrase) return;
  try {
    await cacheAccountAwk(identity.deviceKey(), vaultUrl, passphrase, accountId);
  } catch {
    // contained; state will show keyCached=false rather than crash
  }
}

// ── The namespace - thin verbs over the helpers above ─────────────────────

/** The `tn.auth` namespace (mirrors python's `tn.auth`). Verbs return
 *  AuthState; only `login` / `connect` may throw AuthError. */
export interface AuthNamespace {
  status(opts?: StatusOptions): Promise<AuthState>;
  whoami(): Promise<AuthState>;
  login(opts?: LoginOptions): Promise<AuthState>;
  connect(code: string, opts?: ConnectOptions): Promise<AuthState>;
  use(vault: string): Promise<AuthState>;
  logout(): Promise<AuthState>;
}

async function status(opts: StatusOptions = {}): Promise<AuthState> {
  const identity = loadIdentity();
  const vaultUrl = resolveVault(identity, opts.vault);
  return buildState(identity, vaultUrl, opts.verify !== false, sessionToken());
}

async function whoami(): Promise<AuthState> {
  return status({ verify: false });
}

async function use(vault: string): Promise<AuthState> {
  const identity = Identity.loadOrMint();
  const vaultUrl = vault.replace(/\/+$/, "");
  const prior = identity.linkedVault;
  identity.linkedVault = vaultUrl;
  if (prior && prior !== vaultUrl && identity.linkedAccountId) {
    // The account lived on the old vault; clear it so no one-sided link forms.
    identity.linkedAccountId = null;
  }
  identity.save();
  return buildState(identity, vaultUrl, false, null);
}

async function logout(): Promise<AuthState> {
  const identity = loadIdentity();
  if (identity === null) {
    return new AuthState(null, null, resolveVaultUrl(), false, null, false);
  }
  const accountId = identity.linkedAccountId;
  if (accountId) {
    try {
      defaultCredentialStore().delete(awkKeyName(accountId));
    } catch {
      // a missing key is fine
    }
  }
  identity.linkedAccountId = null;
  identity.linkedVault = null;
  identity.save();
  return buildState(identity, resolveVaultUrl(), false, null);
}

async function connect(
  code: string,
  opts: ConnectOptions = {},
): Promise<AuthState> {
  const identity = Identity.loadOrMint();
  const vaultUrl = resolveVault(identity, opts.vault);
  let accountId: string;
  try {
    const res = await AccountNamespace.connect(code, vaultUrl, identity.deviceKey());
    accountId = res.accountId;
  } catch (e) {
    // Mirror Python `_redeem`'s `except VaultError`: any vault-level rejection
    // (the specific connect error or the base VaultError) surfaces as AuthError
    // — the one exception tn.auth verbs raise. Non-vault errors (e.g. a raw
    // network failure) propagate, exactly as in Python.
    if (e instanceof AccountConnectError || e instanceof VaultError) {
      throw new AuthError(`connect code rejected: ${e.message}`);
    }
    throw e;
  }
  // Persist the link ONLY after the vault confirms (no one-sided links).
  identity.linkedAccountId = accountId;
  identity.linkedVault = vaultUrl;
  identity.save();
  await tryCacheKey(identity, vaultUrl, accountPassphrase(opts.accountPassphrase), accountId);
  return buildState(identity, vaultUrl, false, sessionToken());
}

async function login(opts: LoginOptions = {}): Promise<AuthState> {
  const identity = Identity.loadOrMint();
  const vaultUrl = resolveVault(identity, opts.vault);
  const passphrase = accountPassphrase(opts.accountPassphrase);

  // Credential precedence: code (enroll) > already-enrolled + passphrase
  // (codeless key cache). Session token flows through the vault calls.
  if (opts.code) {
    return connect(
      opts.code,
      passphrase !== undefined
        ? { accountPassphrase: passphrase, vault: vaultUrl }
        : { vault: vaultUrl },
    );
  }

  const accountId = identity.linkedAccountId;
  if (accountId && passphrase) {
    try {
      await cacheAccountAwk(identity.deviceKey(), vaultUrl, passphrase, accountId);
    } catch (e) {
      throw new AuthError(
        `could not cache backup key: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    return buildState(identity, vaultUrl, true, sessionToken());
  }

  throw new AuthError(
    "login needs a credential: pass code=<tn_connect_...>, or " +
      "accountPassphrase for an already-enrolled device (or set " +
      "TN_ACCOUNT_PASSPHRASE). Browser sign-in is handled by the CLI.",
  );
}

/** The `tn.auth` namespace instance (parity with python's `tn.auth`). */
export const auth: AuthNamespace = {
  status,
  whoami,
  login,
  connect,
  use,
  logout,
};
