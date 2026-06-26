// `tn wallet <sub>` — the wallet sub-dispatcher, ported VERBATIM from the
// untyped dispatcher in `bin/tn-js.mjs` (`walletCmd`) into a typed module.
//
// Subcommands:
//
//   tn wallet status [<yaml>]
//   tn wallet sync [<yaml>] [--pull] [--push-only] [--drain-queue] [--passphrase <p>] [--vault <url>]
//   tn wallet link <vault-url> [--yaml <path>] [--name <project>]
//   tn wallet unlink --yaml <path>
//   tn wallet restore --vault <url> --out <dir>
//   tn wallet restore --passphrase --session-token <tok> [--project-id <id>] [--credential-id <id>] --vault <url> --out <dir>
//   tn wallet restore --mnemonic <phrase> | --mnemonic-file <path> [--vault <url>] [--out <dir>] [--force]
//   tn wallet pull-prefs [--vault <url>]
//   tn wallet export-mnemonic [--yes]
//
// The `sync`, `pull-prefs`, and `export-mnemonic` legs are ALREADY extracted
// typed verbs and are imported from their SOURCE modules here (the .mjs imports
// the compiled `dist/` builds). The remaining legs (status, link, unlink,
// restore) are ported inline from the original `walletCmd`.
//
// Behaviour, flags, stdout, and exit codes mirror the .mjs verb byte-for-byte:
// the local `die` writes `tn-js: <msg>\n` to stderr and exits the process with
// code 2 (the same as the .mjs file-global `die`); `stdout`/`exit` are mapped
// to `process.stdout`/`process.exit`. The signature takes the FULL process
// argv so the `argv[3]` (subcommand) / `argv.slice(4)` (rest) indexing is
// preserved verbatim.

import { existsSync, readFileSync } from "node:fs";
import { resolve as pathResolve } from "node:path";

import { Identity, defaultIdentityPath } from "../identity.js";
import { VaultClient, VaultError, vaultIdentityFromDeviceKey } from "../vault/client.js";
import { WalletNamespace, readLinkState, readSyncQueue } from "../wallet/index.js";
import { restoreViaLoopback, restoreViaMnemonic } from "../wallet/restore.js";
import { loadKeystore } from "../runtime/keystore.js";
import { Tn } from "../tn.js";

import { walletSyncCmd } from "./wallet_sync.js";
import { walletPullPrefsCmd } from "./wallet_pull_prefs.js";
import { walletExportMnemonicCmd } from "./wallet_export_mnemonic.js";
import { walletRestorePassphraseCmd } from "./wallet_restore_passphrase.js";

/** File-global `die` from bin/tn-js.mjs: print `tn-js: <msg>` to stderr and
 *  exit the process with code 2. Ported verbatim so spawn tests see the same
 *  stderr bytes + exit code. */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

/**
 * Run the `tn wallet` sub-dispatcher. Takes the FULL process argv (so
 * `argv[3]` is the subcommand and `argv.slice(4)` is the rest), and returns
 * the process exit code; some legs call `die` (process.exit(2)) directly.
 */
export async function walletCmd(argv: string[]): Promise<number> {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts: {
    yaml: string | null;
    vaultUrl: string | null;
    projectName: string | null;
    out: string | null;
    timeoutMs: number | null;
    mnemonic: string | null;
    mnemonicFile: string | null;
    // `--passphrase` is a BOOLEAN selector for `wallet restore` (matches the
    // Python `store_true` flag): present => take the headless passphrase
    // fallback instead of opening a browser. (Distinct from `wallet
    // sync --passphrase <p>`, which has its own parser loop below.)
    passphrase: boolean;
    sessionToken: string | null;
    projectId: string | null;
    credentialId: string | null;
    force: boolean;
    json: boolean;
  } = {
    yaml: null,
    vaultUrl: null,
    projectName: null,
    out: null,
    timeoutMs: null,
    mnemonic: null,
    mnemonicFile: null,
    passphrase: false,
    sessionToken: null,
    projectId: null,
    credentialId: null,
    force: false,
    json: false,
  };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i] as string;
    if (a === "--yaml") opts.yaml = rest[++i] as string;
    else if (a === "--name" || a === "--project-name") opts.projectName = rest[++i] as string;
    else if (a === "--vault") opts.vaultUrl = rest[++i] as string;
    else if (a === "--out") opts.out = rest[++i] as string;
    else if (a === "--timeout") opts.timeoutMs = Number(rest[++i]) * 1000;
    else if (a === "--mnemonic") opts.mnemonic = rest[++i] as string;
    else if (a === "--mnemonic-file") opts.mnemonicFile = rest[++i] as string;
    else if (a === "--passphrase") opts.passphrase = true;
    else if (a === "--force") opts.force = true;
    // `--session-token` (legacy alias `--jwt`), `--project-id`, `--credential-id`
    // feed the passphrase fallback (mirrors Python `tn wallet restore`).
    else if (a === "--session-token" || a === "--jwt") opts.sessionToken = rest[++i] as string;
    else if (a === "--project-id") opts.projectId = rest[++i] as string;
    else if (a === "--credential-id") opts.credentialId = rest[++i] as string;
    else if (a === "--json") opts.json = true;
    else if (!a.startsWith("-") && opts.vaultUrl === null) opts.vaultUrl = a;
  }

  // wallet sync: PULL inbox -> ABSORB each -> PUSH body. Wraps
  // cli/wallet_sync.js walletSyncCmd. Optional positional <yaml>; flags
  // --pull (stage only), --push-only, --drain-queue, --passphrase <p>,
  // --vault <url>. Mirrors Python `tn wallet sync`.
  if (sub === "sync") {
    const syncOpts: {
      yaml?: string;
      pull?: boolean;
      pushOnly?: boolean;
      drainQueue?: boolean;
      passphrase?: string;
      vault?: string;
    } = {};
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i] as string;
      if (a === "--yaml") syncOpts.yaml = rest[++i] as string;
      else if (a === "--pull") syncOpts.pull = true;
      else if (a === "--push-only") syncOpts.pushOnly = true;
      else if (a === "--drain-queue") syncOpts.drainQueue = true;
      else if (a === "--passphrase") syncOpts.passphrase = rest[++i] as string;
      else if (a === "--vault") syncOpts.vault = rest[++i] as string;
      else if (!a.startsWith("-") && syncOpts.yaml === undefined) syncOpts.yaml = a;
      else die(`wallet sync: unknown arg ${a}`);
    }
    process.exitCode = await walletSyncCmd(syncOpts);
    return process.exitCode;
  }

  // wallet restore: multi-device restore via the browser loopback dance.
  // Prints a /restore URL; the operator opens it, the browser does the
  // passkey unwrap and POSTs the raw BEK back over loopback; we then fetch
  // + decrypt + write the keystore. Mirrors Python `tn wallet restore`.
  if (sub === "restore") {
    // Legacy mnemonic restore: re-derive the identity from a BIP-39 phrase,
    // write identity.json, and (with --vault) pull + unseal per-file backups.
    // Mirrors Python `tn wallet restore --mnemonic`.
    if (opts.mnemonic || opts.mnemonicFile) {
      let mnemonic = opts.mnemonic;
      if (opts.mnemonicFile) mnemonic = readFileSync(opts.mnemonicFile, "utf8").trim();
      if (!mnemonic) die("wallet restore: empty --mnemonic / --mnemonic-file");
      // Refuse to clobber an existing identity without --force (mirrors Python
      // cli_wallet `if identity_path.exists() and not args.force: _die(... code=2)`).
      // restoreViaMnemonic writes to the default identity path; guard it here.
      const idPath = defaultIdentityPath();
      if (existsSync(idPath) && !opts.force) {
        die(
          `${idPath} already exists. Use --force to overwrite ` +
            `(existing identity will be destroyed).`,
        );
      }
      const mnOpts: {
        mnemonic: string;
        vaultUrl?: string;
        outDir?: string;
      } = { mnemonic };
      const vUrl = opts.vaultUrl || process.env["TN_VAULT_URL"];
      if (vUrl) mnOpts.vaultUrl = vUrl;
      if (opts.out) mnOpts.outDir = opts.out;
      try {
        const res = await restoreViaMnemonic(mnOpts);
        const totalFiles = res.restored.reduce((n, r) => n + r.filesWritten.length, 0);
        process.stdout.write(`\n[tn wallet restore] Identity restored: ${res.did}\n`);
        if (!vUrl) {
          process.stdout.write(`[tn wallet restore] No --vault; restored identity only to ${res.identityPath}\n`);
        } else {
          process.stdout.write(`[tn wallet restore] Restored ${res.restored.length} project(s), ${totalFiles} file(s)\n`);
        }
        if (opts.json) {
          process.stdout.write(
            JSON.stringify({
              ok: true,
              verb: "wallet.restore",
              did: res.did,
              identity_path: res.identityPath,
              projects: res.restored.map((r) => ({
                project_id: r.projectId,
                out_dir: r.outDir,
                files_written: r.filesWritten,
                notes: r.notes,
              })),
            }) + "\n",
          );
        } else {
          // Human per-project summary — mirrors Python cli_wallet
          // _pull_selected_projects "  pulled N files" lines.
          for (const r of res.restored) {
            process.stdout.write(`  ${r.projectId} -> ${r.outDir}\n`);
            process.stdout.write(`    pulled ${r.filesWritten.length} file(s)\n`);
          }
        }
      } catch (e) {
        die(`wallet restore: ${(e as { message?: string })?.message ?? e}`);
      }
      return 0;
    }
    const vaultUrl = opts.vaultUrl || process.env["TN_VAULT_URL"];
    if (!vaultUrl) die("wallet restore: --vault <url> (or TN_VAULT_URL) is required");
    if (!opts.out) die("wallet restore: --out <dir> is required");

    // Passphrase fallback: no browser handoff. Derive the project BEK
    // locally from the account passphrase + a vault session token, then
    // restore. Mirrors Python `_cmd_wallet_restore_account_bound` ->
    // `_restore_via_passphrase` (selected by the `--passphrase` flag).
    if (opts.passphrase) {
      return walletRestorePassphraseCmd({
        vaultUrl,
        outDir: opts.out,
        sessionToken: opts.sessionToken,
        projectId: opts.projectId,
        credentialId: opts.credentialId,
      });
    }

    const loopOpts: {
      vaultUrl: string;
      outDir: string;
      onRestoreUrl: (url: string) => void;
      timeoutMs?: number;
    } = {
      vaultUrl,
      outDir: opts.out,
      onRestoreUrl: (url: string) => {
        process.stdout.write("\n[tn wallet restore] Open this URL in your browser to authorize the restore:\n");
        process.stdout.write(`  ${url}\n\n`);
        process.stdout.write("[tn wallet restore] Waiting for the browser to deliver the unwrapped key...\n");
      },
    };
    if (opts.timeoutMs) loopOpts.timeoutMs = opts.timeoutMs;
    try {
      const res = await restoreViaLoopback(loopOpts);
      process.stdout.write(`\n[tn wallet restore] Restored ${res.filesWritten.length} file(s) to ${res.outDir}\n`);
      if (opts.json) {
        process.stdout.write(
          JSON.stringify({
            ok: true,
            verb: "wallet.restore",
            project_id: res.projectId,
            account_id: res.accountId,
            out_dir: res.outDir,
            files_written: res.filesWritten,
          }) + "\n",
        );
      } else {
        // Human summary — mirrors Python _cmd_wallet_restore_account_bound.
        process.stdout.write(`  account_id: ${res.accountId}\n`);
        process.stdout.write(`  project_id: ${res.projectId}\n`);
        for (const f of res.filesWritten) process.stdout.write(`  wrote: ${f}\n`);
      }
    } catch (e) {
      die(`wallet restore: ${(e as { message?: string })?.message ?? e}`);
    }
    return 0;
  }

  // wallet pull-prefs: refresh the global identity's account prefs from the
  // vault. Wraps cli/wallet_pull_prefs.js. --vault overrides the cached url.
  if (sub === "pull-prefs") {
    // `--help`/`-h` (and any bad flag) must print usage and exit cleanly,
    // never fall through to walletPullPrefsCmd (which dials the vault and
    // throws an uncaught fetch error when no host is reachable).
    if (rest.includes("--help") || rest.includes("-h")) {
      process.stdout.write("usage: tn wallet pull-prefs [--vault <url>]\n");
      return 0;
    }
    // --vault is the only flag this subcommand accepts; reject anything else
    // before we try to reach the vault so a typo fails fast and cleanly.
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i] as string;
      if (a === "--vault") {
        i += 1; // skip its value
        continue;
      }
      if (a.startsWith("-")) {
        die(
          `wallet pull-prefs: unknown flag ${a}. ` +
            `usage: tn wallet pull-prefs [--vault <url>]`,
        );
      }
    }
    process.exitCode = await walletPullPrefsCmd(
      opts.vaultUrl ? { vault: opts.vaultUrl } : {},
    );
    return process.exitCode;
  }

  // wallet export-mnemonic: re-display the stored BIP-39 recovery phrase.
  // Wraps cli/wallet_export_mnemonic.js. Requires --yes to show the phrase.
  if (sub === "export-mnemonic") {
    let yes = false;
    for (const a of rest) {
      if (a === "--yes") yes = true;
    }
    process.exitCode = await walletExportMnemonicCmd({ yes });
    return process.exitCode;
  }

  if (sub === "status") {
    // `tn-js wallet status [<yaml>]`
    // Positional yaml arg ends up in opts.vaultUrl (the generic positional slot);
    // --yaml <path> is also accepted for script use.
    const yamlArg = opts.yaml ?? opts.vaultUrl ?? null;
    const identityPath = defaultIdentityPath();
    if (!existsSync(identityPath)) {
      process.stdout.write(`No identity at ${identityPath}. Run \`tn init <project>\` first.\n`);
      return 0;
    }
    const identity = Identity.load(identityPath);
    process.stdout.write(`Identity: ${identity.did}\n`);
    process.stdout.write(`  file:    ${identity.path}\n`);
    process.stdout.write(`  linked:  ${identity.linkedVault ?? "(not linked)"}\n`);
    process.stdout.write(`  prefs:   default_new_ceremony_mode=${identity.prefs.defaultNewCeremonyMode}\n`);
    process.stdout.write(`           prefs_version=${identity.prefsVersion}\n`);
    if (yamlArg) {
      const yamlPath = pathResolve(yamlArg);
      if (!existsSync(yamlPath)) {
        process.stdout.write(`Ceremony: (no yaml at ${yamlPath})\n`);
        return 0;
      }
      const linkState = readLinkState(yamlPath);
      const tn = await Tn.init(yamlPath);
      const cfg = (tn.config() ?? {}) as Record<string, unknown>;
      await tn.close();
      const groups = cfg["groups"] instanceof Map ? (cfg["groups"] as Map<string, unknown>) : new Map<string, unknown>();
      const pending = readSyncQueue(linkState.ceremonyId);
      process.stdout.write(`Ceremony: ${linkState.ceremonyId}\n`);
      process.stdout.write(`  yaml:            ${yamlPath}\n`);
      process.stdout.write(`  mode:            ${linkState.mode}\n`);
      process.stdout.write(`  cipher:          ${String(cfg["cipher"] ?? "btn")}\n`);
      process.stdout.write(`  linked_vault:    ${linkState.linkedVault || "(none)"}\n`);
      process.stdout.write(`  linked_project:  ${linkState.linkedProjectId || "(none)"}\n`);
      process.stdout.write(`  groups:          ${JSON.stringify([...groups.keys()])}\n`);
      if (pending.length > 0) {
        process.stdout.write(`  pending_sync:    ${pending.length} queued failure(s)\n`);
        const latest = pending[pending.length - 1];
        process.stdout.write(`    latest:        ${String(latest?.["error"] ?? "(no message)")}\n`);
        process.stdout.write(`    run:           tn wallet sync ${yamlArg} --drain-queue\n`);
      } else {
        process.stdout.write(`  pending_sync:    (queue empty)\n`);
      }
    }
    return 0;
  }

  if (sub === "unlink") {
    if (!opts.yaml) die("wallet unlink: --yaml <path> is required");
    // Read the prior link state BEFORE flipping it, so the human line can
    // report the ceremony id + the vault it was linked to (Python parity).
    const prior = readLinkState(opts.yaml);
    WalletNamespace.unlink(opts.yaml);
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: true, verb: "wallet.unlink", yaml: opts.yaml }) + "\n");
    } else {
      // Human summary — mirrors Python cli_wallet.cmd_wallet_unlink.
      process.stdout.write(
        `Unlinked ${prior.ceremonyId} (was ${prior.linkedVault || "not linked"})\n`,
      );
    }
    return 0;
  }
  if (sub !== "link") {
    die(
      `wallet: unknown subcommand ${sub}. try: ` +
        `wallet status [<yaml>] | ` +
        `wallet sync [<yaml>] [--pull] [--push-only] [--drain-queue] [--passphrase <p>] [--vault <url>] | ` +
        `wallet link <vault-url> [--yaml <path>] [--name <project>] | ` +
        `wallet unlink --yaml <path> | ` +
        `wallet restore --vault <url> --out <dir> [--passphrase --session-token <tok> [--project-id <id>] [--credential-id <id>]] | ` +
        `wallet pull-prefs [--vault <url>] | ` +
        `wallet export-mnemonic [--yes]`,
    );
  }
  if (!opts.vaultUrl) die("wallet link: <vault-url> positional is required");
  if (!opts.yaml) die("wallet link: --yaml <path> is required");

  // Load DeviceKey from the ceremony's keystore so we can authenticate
  // against the vault as the same identity that owns the ceremony.
  const tn = await Tn.init(opts.yaml);
  const cfg = (tn.config() ?? {}) as Record<string, unknown>;
  await tn.close();
  const keystorePath = typeof cfg["keystorePath"] === "string" ? (cfg["keystorePath"] as string) : null;
  if (!keystorePath) die(`wallet link: ceremony at ${opts.yaml} has no keystorePath`);
  const ks = loadKeystore(keystorePath);

  const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(ks.device), opts.vaultUrl);
  const linkOpts: { projectName?: string } = {};
  if (opts.projectName) linkOpts.projectName = opts.projectName;
  try {
    const result = await WalletNamespace.link(client, opts.yaml, linkOpts);
    if (opts.json) {
      process.stdout.write(
        JSON.stringify({
          ok: true,
          verb: "wallet.link",
          project_id: result.projectId,
          project_name: result.projectName,
          vault_base_url: result.vaultBaseUrl,
          newly_linked: result.newlyLinked,
        }) + "\n",
      );
    } else {
      // Human summary — mirrors Python cli_wallet.cmd_wallet_link
      // `Linked {ceremony} -> {vault}/projects/{project_id}`.
      process.stdout.write(
        `Linked ${result.projectName} -> ${result.vaultBaseUrl}/projects/${result.projectId}\n`,
      );
      process.stdout.write(`  newly_linked: ${result.newlyLinked ? "yes" : "no"}\n`);
    }
  } catch (e) {
    if (e instanceof VaultError) {
      die(`wallet link: ${e.message}${e.status !== null ? ` (status=${e.status})` : ""}`);
    }
    throw e;
  }
  return 0;
}
