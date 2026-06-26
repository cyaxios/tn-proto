// `tn account connect <code>` — bind this device DID to a vault account.
//
// TypeScript port of the inline `accountCmd` previously living in the untyped
// dispatcher `bin/tn-js.mjs`. Behaviour, flags, stdout, stderr, and exit codes
// are preserved byte-for-byte (see test/cli_wallet_account.test.ts,
// test/account_connect.test.ts, test/account_connect_cascade.test.ts):
//
//     tn account connect <code> [--vault <url>] [--yaml <path>]
//                               [--identity <path>] [--passphrase <p>]
//
// The verb redeems the connect code AS a signing identity resolved via the
// tier cascade (resolveSigningIdentity): supplied --identity > machine-global
// identity.json > per-ceremony keystore key. The chosen key's DID binds as the
// account principal. On success it stamps the machine-global identity so future
// `init` runs warm-attach, and — with --passphrase — derives + caches the
// account AWK so later body backups run non-interactively.
//
// This module takes the FULL process argv and preserves the original index
// math verbatim: the subcommand is argv[3] and the flags/positional come from
// argv.slice(4). The caller (dispatcher) owns process.exit; we return the code.

import { existsSync } from "node:fs";

import { Tn } from "../tn.js";
import { Identity, defaultIdentityPath } from "../identity.js";
import { AccountConnectError, AccountNamespace } from "../account/index.js";
import { resolveSigningIdentity } from "../account/signing_identity.js";
import { cacheAccountAwk } from "../vault/awk_cache.js";
import { resolveVaultUrl } from "../vault/url.js";
import { resolveYamlOrDiscover } from "./_discover.js";

/** Usage errors (missing positional / unknown subcommand) → exit 2,
 *  argparse-style. Typed `never` so TypeScript narrows past it. */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

/** Runtime errors (no ceremony, signing failure, vault rejection) → exit 1 with
 *  the `tn: error:` prefix, mirroring Python `_die`. */
function dieRuntime(msg: string): never {
  process.stderr.write(`tn: error: ${msg}\n`);
  process.exit(1);
}

/**
 * Execute `tn account connect`. Takes the FULL process argv (subcommand at
 * argv[3], flags/positional from argv.slice(4)). Returns the process exit
 * code (0 on success); error paths exit 2 via `die`.
 */
export async function accountCmd(argv: string[]): Promise<number> {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts: {
    yaml: string | null;
    vaultUrl: string | null;
    code: string | null;
    identity: string | null;
    passphrase: string | null;
    json: boolean;
  } = { yaml: null, vaultUrl: null, code: null, identity: null, passphrase: null, json: false };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i] as string;
    if (a === "--yaml") opts.yaml = rest[++i] ?? null;
    else if (a === "--vault" || a === "--vault-url") opts.vaultUrl = rest[++i] ?? null;
    else if (a === "--identity") opts.identity = rest[++i] ?? null;
    else if (a === "--passphrase") opts.passphrase = rest[++i] ?? null;
    else if (a === "--json") opts.json = true;
    else if (!a.startsWith("-") && opts.code === null) opts.code = a;
  }
  if (sub !== "connect") {
    die(`account: unknown subcommand ${sub}. try: account connect <code> [--vault <url>] [--yaml <path>] [--identity <path>] [--passphrase <p>]`);
  }
  if (!opts.code) die("account connect: <code> positional is required");

  // --yaml is OPTIONAL: discover an existing ceremony (Python uses
  // _resolve_yaml_or_discover). No ceremony found → exit 1.
  const yamlPath = resolveYamlOrDiscover(opts.yaml, dieRuntime);

  const tn = await Tn.init(yamlPath);
  const cfg = (tn.config() ?? {}) as Record<string, unknown>;
  await tn.close();
  const keystorePath = typeof cfg.keystorePath === "string" ? cfg.keystorePath : null;
  if (!keystorePath) dieRuntime(`ceremony at ${yamlPath} has no keystorePath`);

  // The machine-global identity (if any) drives the vault fallback + warm-attach
  // stamp, independent of which tier signs. Mirrors Python cmd_account_connect.
  const idPath = defaultIdentityPath();
  const globalIdentity = existsSync(idPath) ? Identity.load(idPath) : null;

  // Signing-identity CASCADE (mirrors Python resolve_signing_identity):
  //   tier 2 supplied (--identity) > tier 1 machine-global identity.json >
  //   tier 3 per-ceremony keystore key. The chosen key's DID is what binds
  //   as the account principal, so it MUST agree across CLIs on one machine.
  let signer;
  try {
    signer = resolveSigningIdentity({
      suppliedIdentityPath: opts.identity,
      keystorePath,
    });
  } catch (e) {
    dieRuntime((e as { message?: string })?.message ?? String(e));
  }

  // Vault URL precedence (mirrors Python base_url = args.vault or
  // identity.linked_vault, then resolve_vault_url default): explicit --vault >
  // the machine-global identity's linked_vault > TN_VAULT_URL / hosted default.
  // Never dies for a missing vault — there is always a default.
  const vaultUrl = opts.vaultUrl ?? globalIdentity?.linkedVault ?? resolveVaultUrl(null);

  try {
    const result = await AccountNamespace.connect(opts.code, vaultUrl, signer.deviceKey, { yamlPath });

    // Stamp the account binding onto the machine-global identity so future
    // `tn-js init <name>` runs warm-attach to this account automatically
    // (no browser). Mirrors Python cmd_account_connect persisting
    // identity.linked_account_id. Best-effort: a stamp failure must not
    // fail the connect (the per-ceremony sync-state binding already
    // succeeded inside AccountNamespace.connect).
    let globalStamped = false;
    try {
      const identity = Identity.loadOrMint();
      if (identity.linkedAccountId !== result.accountId || identity.linkedVault !== vaultUrl) {
        identity.linkedAccountId = result.accountId;
        identity.linkedVault = vaultUrl;
        identity.save();
      }
      globalStamped = true;
    } catch (e) {
      process.stdout.write(`[account connect] WARN could not stamp global identity: ${(e as { message?: string })?.message ?? e}\n`);
    }

    // With --passphrase, derive + cache the account AWK ("token, not
    // password") so warm-attach / `wallet sync` push the body backup
    // non-interactively. Best-effort: a derivation failure (e.g. wrong
    // passphrase) must not undo the successful bind. Mirrors Python
    // cmd_account_connect's cache_account_awk call.
    let awkCached = false;
    if (opts.passphrase) {
      try {
        await cacheAccountAwk(signer.deviceKey, vaultUrl, opts.passphrase, result.accountId);
        awkCached = true;
      } catch (e) {
        process.stdout.write(
          `[account connect] WARN could not cache account credential: ${(e as { message?: string })?.message ?? e}\n`,
        );
      }
    }

    if (opts.json) {
      process.stdout.write(
        JSON.stringify({
          ok: true,
          verb: "account.connect",
          account_id: result.accountId,
          did: result.did,
          project_id: result.projectId ?? null,
          project_name: result.projectName ?? null,
          global_identity_stamped: globalStamped,
          awk_cached: awkCached,
        }) + "\n",
      );
    } else {
      // Human summary — mirrors Python cli_auth.cmd_account_connect.
      process.stdout.write(`Connected to vault account ${result.accountId}\n`);
      if (awkCached) {
        process.stdout.write("  cached account credential (body backup runs unattended)\n");
      }
      if (result.projectId) process.stdout.write(`  project_id:   ${result.projectId}\n`);
      if (result.projectName) process.stdout.write(`  project_name: ${result.projectName}\n`);
      process.stdout.write(`  did:          ${result.did}\n`);
    }
  } catch (e) {
    if (e instanceof AccountConnectError) {
      // Vault rejection is a runtime error → exit 1 (Python _die code=1).
      dieRuntime(`connect-code redeem failed${e.status !== null ? ` (status=${e.status})` : ""}: ${e.message}`);
    }
    throw e;
  }
  return 0;
}
