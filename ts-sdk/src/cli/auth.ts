// `tn auth ...` CLI verbs — a THIN printer over the `tn.auth` library
// namespace (src/auth/). All logic + state lives in the library; this module
// only parses argv and formats output. Mirrors Python's `cli_auth.py`
// (status / login / logout / whoami / use / connect).

import { stdout } from "node:process";

import {
  auth,
  AuthError,
  type AuthState,
  type ConnectOptions,
  type LoginOptions,
} from "../auth/index.js";
import { Identity } from "../identity.js";
import { resolveVaultUrl } from "../vault/url.js";
import { requestDeviceCode, pollDeviceToken, openBrowser, DeviceFlowError } from "../auth/device_flow.js";
import { drainPendingAwk, redeemAwkPickup } from "../vault/awk_pickup.js";

/** Usage errors → exit 2 (argparse-style). */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

/** Runtime errors (device-flow failure, vault unreachable) → exit 1 (Python _die). */
function dieRuntime(msg: string): never {
  process.stderr.write(`tn: error: ${msg}\n`);
  process.exit(1);
}

/**
 * Browser device-authorization login (RFC 8628): open the verification URL,
 * ALWAYS print the short code + URL fallback, poll until the user signs in, then
 * stamp the account onto the machine identity. The device key stays the
 * principal — no token to store. Returns the process exit code.
 */
async function deviceLogin(vault: string | null): Promise<number> {
  const identity = Identity.loadOrMint();
  const vaultUrl = vault ?? identity.linkedVault ?? resolveVaultUrl();
  let dc;
  try {
    dc = await requestDeviceCode(vaultUrl, identity.deviceKey());
  } catch (e) {
    dieRuntime(`could not start device login: ${e instanceof Error ? e.message : String(e)}`);
  }
  // Auto-open AND always print — a non-opening browser is then a non-event.
  stdout.write(`\nTo connect this device, open:\n  ${dc.verificationUriComplete}\n\n`);
  stdout.write(`If your browser didn't open, go to  ${dc.verificationUri}\n`);
  stdout.write(`and enter the code:                 ${dc.userCode}\n\n`);
  openBrowser(dc.verificationUriComplete);
  stdout.write("Waiting for you to sign in…  (Ctrl-C to cancel)\n");

  let res;
  try {
    res = await pollDeviceToken(vaultUrl, dc);
  } catch (e) {
    if (e instanceof DeviceFlowError) dieRuntime(e.message);
    throw e;
  }
  identity.linkedAccountId = res.accountId;
  identity.linkedVault = vaultUrl;
  identity.save();
  let cached = false;
  if (res.awkPickupKeyId && process.env.TN_NO_KEY_CACHE !== "1") {
    cached = await redeemAwkPickup({
      vaultBase: vaultUrl,
      deviceSeed: identity.seed,
      accountId: res.accountId,
      keyIdB64: res.awkPickupKeyId,
    });
  }
  // Fallback: the device-approve didn't hand us a key_id (e.g. the AWK pickup
  // was minted by a separate browser claim). Drain the inbox for any pickup
  // sealed to this DID so login still ends with a cached AWK. Best-effort.
  if (!cached && process.env.TN_NO_KEY_CACHE !== "1") {
    await drainPendingAwk({ vaultBase: vaultUrl, deviceSeed: identity.seed });
  }
  stdout.write(`\n✓ Connected as account ${res.accountId}\n`);
  printAuthState(await auth.status({ vault: vaultUrl }));
  return 0;
}

function printAuthState(s: AuthState): void {
  const tri = s.enrolled === true ? "yes" : s.enrolled === false ? "no" : "unknown";
  stdout.write(`device:   ${s.deviceDid ?? "(none)"}\n`);
  stdout.write(`account:  ${s.accountId ?? "(none - not logged in to an account)"}\n`);
  stdout.write(`vault:    ${s.vaultUrl}\n`);
  stdout.write("layers:\n");
  stdout.write(`  linked (local file):  ${s.linked ? "yes" : "no"}\n`);
  stdout.write(`  enrolled (vault):     ${tri}\n`);
  stdout.write(`  backup key (cached):  ${s.keyCached ? "yes" : "no"}\n`);
  stdout.write(`=> ${s.message}\n`);
}

interface AuthCliOpts {
  vault: string | null;
  code: string | null;
  accountPassphrase: string | null;
}

// Build library call-options from parsed CLI opts, omitting nulls so the
// library's own defaults apply. `includeCode` adds `code` (login only).
function authVerbOpts(opts: AuthCliOpts, includeCode: boolean): LoginOptions {
  const o: LoginOptions = {};
  if (opts.vault !== null) o.vault = opts.vault;
  if (opts.accountPassphrase !== null) o.accountPassphrase = opts.accountPassphrase;
  if (includeCode && opts.code !== null) o.code = opts.code;
  return o;
}

/** Execute `tn auth <sub>`. Takes the full process argv; returns the exit code. */
export async function authCmd(argv: string[]): Promise<number> {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts: AuthCliOpts = { vault: null, code: null, accountPassphrase: null };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === undefined) continue;
    if (a === "--vault" || a === "--vault-url") opts.vault = rest[++i] ?? null;
    else if (a === "--code") opts.code = rest[++i] ?? null;
    else if (a === "--account-passphrase") opts.accountPassphrase = rest[++i] ?? null;
    else if (!a.startsWith("-")) {
      // positional: <vault> for `use`, <code> for `connect`
      if (sub === "use" && opts.vault === null) opts.vault = a;
      else if (sub === "connect" && opts.code === null) opts.code = a;
    }
  }
  switch (sub) {
    case "status":
      printAuthState(await auth.status(opts.vault !== null ? { vault: opts.vault } : {}));
      break;
    case "whoami": {
      const s = await auth.whoami();
      if (s.deviceDid === null) {
        stdout.write("not logged in (no identity on this machine)\n");
      } else {
        stdout.write(
          `${s.deviceDid}  ->  account ${s.accountId ?? "(no account)"} @ ${s.vaultUrl}\n`,
        );
      }
      break;
    }
    case "use": {
      if (!opts.vault)
        die("auth use: <vault> is required (e.g. tn-js auth use https://vault.tn-proto.org)");
      const s = await auth.use(opts.vault);
      stdout.write(`vault set to ${s.vaultUrl}\n`);
      stdout.write("  run `tn-js auth login` to connect this device to an account there.\n");
      break;
    }
    case "logout": {
      const s = await auth.logout();
      stdout.write("Logged out on this machine.\n");
      stdout.write(`  device key kept: ${s.deviceDid ?? "(none)"}\n`);
      stdout.write("  your account and backups in the vault are untouched.\n");
      break;
    }
    case "connect": {
      if (!opts.code) die("auth connect: <code> is required");
      try {
        const connectOpts: ConnectOptions = authVerbOpts(opts, false);
        const s = await auth.connect(opts.code, connectOpts);
        stdout.write(`Connected to vault account ${s.accountId}\n`);
        printAuthState(s);
      } catch (e) {
        if (e instanceof AuthError) die(e.message);
        throw e;
      }
      break;
    }
    case "login": {
      // Headless credential paths (CI) delegate to the library: an explicit
      // --code enrolls, an --account-passphrase caches the backup key for an
      // already-enrolled device. With NEITHER, `login` is the interactive
      // browser device-flow — the default, idiomatic path.
      if (opts.code || opts.accountPassphrase) {
        try {
          const s = await auth.login(authVerbOpts(opts, true));
          stdout.write("[tn auth] Connected.\n");
          printAuthState(s);
        } catch (e) {
          if (e instanceof AuthError) dieRuntime(e.message);
          throw e;
        }
        break;
      }
      return deviceLogin(opts.vault);
    }
    default:
      die(
        `auth: unknown subcommand ${sub}. try: status | login | logout | whoami | use <vault> | connect <code>`,
      );
  }
  return 0;
}
