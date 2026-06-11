// Top-level `tn wallet pull-prefs` CLI verb — TS parity port of Python's
// `cmd_wallet_pull_prefs` (python/tn/cli.py). Refreshes the machine-global
// identity's account preferences from the vault:
//
//   tn wallet pull-prefs [--vault <url>]
//
// Behaviour, flags, stdout, and exit codes mirror the Python verb:
//   - Loads the global identity (identity.json).
//   - Resolves the vault url from --vault, falling back to the identity's
//     cached `linked_vault`. Dies (exit 1) with the same message Python's
//     `_die` prints when neither is present.
//   - Authenticates against the vault and pulls `GET /api/v1/account/prefs`.
//   - Writes `default_new_ceremony_mode` + `prefs_version` back into
//     identity.json, then prints the three confirmation lines.
//   - Returns 0 on success.
//
// SDK GAP (flagged, not faked): the TS VaultClient does not yet expose a
// `getPrefs()` / `close()` pair (Python's `client.get_prefs()` /
// `client.close()`), and the TS `Identity` exposes `prefs` / `prefsVersion`
// as READ-ONLY getters with no setters or `ensure_written`. So this verb
// (a) reuses the SDK's real auth via `VaultClient.forIdentity` and then
// issues the single `GET /account/prefs` with the client's own bearer token
// — the same raw-fetch pattern `src/account/index.ts` uses for endpoints not
// yet wrapped (no HTTP/crypto re-implemented), and (b) persists the two pref
// fields by re-reading and rewriting identity.json in the exact field shape
// of Python's `Identity.ensure_written`. When `VaultClient.getPrefs` and an
// `Identity` pref-setter land, this file should delegate to them.

import { existsSync, readFileSync, renameSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { Identity, defaultIdentityPath } from "../identity.js";
import { VaultClient, vaultIdentityFromDeviceKey } from "../vault/client.js";

export interface WalletPullPrefsOpts {
  /** Vault URL. Falls back to the identity's cached `linked_vault`. */
  vault?: string | undefined;
  /** Override identity.json path (tests). Default: defaultIdentityPath(). */
  identityPath?: string | undefined;
  /** Override fetch (tests). Default: globalThis.fetch. */
  fetchImpl?: typeof fetch | undefined;
  /** Sink for normal output (defaults to process.stdout). */
  stdout?: { write(s: string): void } | undefined;
  /** Sink for error output (defaults to process.stderr). */
  stderr?: { write(s: string): void } | undefined;
}

/** Shape of the prefs document returned by `GET /api/v1/account/prefs`. */
interface PrefsDoc {
  default_new_ceremony_mode: string;
  prefs_version: number | string;
}

/**
 * Run the `tn wallet pull-prefs` verb. Returns the process exit code so a
 * CLI shell can `process.exit(await walletPullPrefsCmd(...))`. Exit 1 when no
 * vault url can be resolved (mirrors Python's `_die`); 0 on success.
 */
export async function walletPullPrefsCmd(opts: WalletPullPrefsOpts = {}): Promise<number> {
  const out = opts.stdout ?? process.stdout;
  const err = opts.stderr ?? process.stderr;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);

  const identityPath = opts.identityPath ?? defaultIdentityPath();
  const identity = Identity.load(identityPath);

  const vaultUrl = opts.vault ?? identity.linkedVault;
  if (!vaultUrl) {
    err.write("--vault <url> required (no vault cached in identity.json)\n");
    return 1;
  }

  const client = await VaultClient.forIdentity(
    vaultIdentityFromDeviceKey(identity.deviceKey()),
    vaultUrl,
    { fetchImpl },
  );

  const prefs = await getPrefs(client, fetchImpl);
  const mode = prefs.default_new_ceremony_mode;
  const version = Number(prefs.prefs_version);
  writeIdentityPrefs(identityPath, mode, version);

  out.write(`Pulled prefs from ${vaultUrl}:\n`);
  out.write(`  default_new_ceremony_mode: ${mode}\n`);
  out.write(`  prefs_version: ${version}\n`);
  return 0;
}

/**
 * `GET /api/v1/account/prefs` against an already-authed client. Mirror of
 * Python `VaultClient.get_prefs`. Reuses the SDK's bearer token + baseUrl;
 * no auth/crypto is re-implemented here.
 */
async function getPrefs(client: VaultClient, fetchImpl: typeof fetch): Promise<PrefsDoc> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (client.token) headers.Authorization = `Bearer ${client.token}`;
  const resp = await fetchImpl(`${client.baseUrl}/api/v1/account/prefs`, {
    method: "GET",
    headers,
  });
  if (resp.status >= 400) {
    let body = "";
    try {
      body = (await resp.text()).slice(0, 512);
    } catch {
      // Body read failure is non-fatal; report what we have.
    }
    throw new Error(`GET /api/v1/account/prefs returned ${resp.status}: ${body}`);
  }
  return (await resp.json()) as PrefsDoc;
}

/**
 * Persist `default_new_ceremony_mode` + `prefs_version` into identity.json,
 * preserving every other field. Mirrors the field shape Python's
 * `Identity.ensure_written` writes (prefs is a nested object, prefs_version a
 * top-level int). Atomic-ish: write tmp, replace.
 */
function writeIdentityPrefs(identityPath: string, mode: string, version: number): void {
  const raw = JSON.parse(readFileSync(identityPath, "utf8")) as Record<string, unknown>;
  const prefs =
    raw["prefs"] && typeof raw["prefs"] === "object" && !Array.isArray(raw["prefs"])
      ? (raw["prefs"] as Record<string, unknown>)
      : {};
  prefs["default_new_ceremony_mode"] = mode;
  raw["prefs"] = prefs;
  raw["prefs_version"] = version;

  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(raw).sort()) sorted[k] = raw[k];

  mkdirSync(dirname(identityPath), { recursive: true });
  const tmp = `${identityPath}.tmp`;
  writeFileSync(tmp, JSON.stringify(sorted, null, 2), "utf8");
  if (existsSync(identityPath)) rmSync(identityPath);
  renameSync(tmp, identityPath);
}
