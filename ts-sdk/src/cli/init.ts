// `tn init [<project-name>]` — mint or attach to a TN ceremony.
//
// TypeScript port of the inline `initCmd` from the untyped dispatcher
// `bin/tn-js.mjs` (plus its helpers `_tryWarmAttach` and
// `_formatExpiresLocal`). Behaviour, flags, stdout/stderr bytes, the JSON
// receipt shape, and exit codes mirror the .mjs verb byte-for-byte:
//
//     tn init [<project-name>] [--yaml <yaml-path>] [--no-link] [--link <url>]
//
// A bare <project-name> mints a root ceremony at <cwd>/.tn/<name>/ (own
// keystore + admin + logs) seeded from the machine-global device identity,
// and — unless --no-link — backs it up to the vault. The WARM path attaches
// directly via wallet.link (DID-challenge, no browser); the COLD path mints a
// pending claim and prints a claim URL. A re-attach to an existing ceremony
// does NOT re-upload. Failures warn but never fail init — the on-disk
// ceremony stays valid.
//
// Unlike the other typed CLI modules this one OWNS its argv parsing (it is a
// verbatim port of the inline dispatcher case), so it takes the FULL process
// argv and preserves the `argv[2]`/`argv.slice(3)` indexing exactly.

import { existsSync, renameSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve as pathResolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { init as tnInit, close as tnClose } from "../index.js";
import type { Tn } from "../tn.js";
import { ensureCeremonyOnDisk, isValidCeremonyName } from "../multi.js";
import { resolveVaultUrl } from "../vault/url.js";
import { Identity, defaultIdentityPath } from "../identity.js";
import { VaultClient, vaultIdentityFromDeviceKey } from "../vault/client.js";
import { loadCachedAwk } from "../vault/awk_cache.js";
import { WalletNamespace } from "../wallet/index.js";
import { walletSyncCmd } from "./wallet_sync.js";

/**
 * Execute `tn init`. Takes the FULL process argv (so `argv.slice(3)` indexing
 * is preserved verbatim) and returns the process exit code (0 on success).
 * Mirror of the inline `initCmd` in bin/tn-js.mjs.
 */
export async function initCmd(argv: string[]): Promise<number> {
  const rest = argv.slice(3);
  let yamlPath: string | null = null;
  let projectArg: string | null = null;
  let noLink = false;
  let linkUrl: string | null = null;
  let force = false;
  let cipher = "btn";
  let versionName: string | null = null;
  let asJson = false;
  let words = 12;
  let mnemonicFile: string | null = null;
  let skipConfirm = false;
  let keepMnemonic = false;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i] as string;
    if (a === "--yaml") yamlPath = rest[++i] as string;
    else if (a === "--no-link") noLink = true;
    else if (a === "--link") linkUrl = rest[++i] as string;
    else if (a === "--force") force = true;
    else if (a === "--cipher") cipher = rest[++i] as string;
    else if (a === "--version-name") versionName = rest[++i] as string;
    else if (a === "--words") words = Number(rest[++i]);
    else if (a === "--mnemonic-file") mnemonicFile = rest[++i] as string;
    else if (a === "--skip-confirm") skipConfirm = true;
    else if (a === "--keep-mnemonic") keepMnemonic = true;
    else if (a === "--json") asJson = true;
    else if (a === "-h" || a === "--help") {
      process.stdout.write(
        "tn-js init [<project-name>] [--yaml <yaml-path>] [--no-link] [--link <url>]\n" +
          "           [--force] [--cipher btn|hibe] [--version-name <name>] [--json]\n" +
          "           [--words 12|15|18|21|24] [--mnemonic-file <path>]\n" +
          "           [--skip-confirm] [--keep-mnemonic]\n" +
          "  Mint or attach to a TN ceremony. A <project-name> mints a root\n" +
          "  ceremony at <cwd>/.tn/<name>/ (own keystore + admin + logs) and,\n" +
          "  unless --no-link, backs it up to the vault and prints a claim URL.\n" +
          "  No name + no --yaml uses the current folder's name (Python parity).\n" +
          "  A fresh identity prints its BIP-39 recovery phrase ONCE (TTY) and\n" +
          "  waits for Enter unless --skip-confirm. --keep-mnemonic persists the\n" +
          "  phrase into identity.json; --mnemonic-file derives the identity from\n" +
          "  a file; --words sets the entropy. --force moves an existing ceremony\n" +
          "  aside (.tn/_overwritten_*) and re-mints. Human output by default;\n" +
          "  --json prints the receipt.\n",
      );
      return 0;
    } else if (!a.startsWith("-") && projectArg === null) {
      projectArg = a;
    }
  }

  if (![12, 15, 18, 21, 24].includes(words)) {
    process.stderr.write(`tn: error: --words must be one of 12, 15, 18, 21, 24 (got ${words}).\n`);
    return 1;
  }

  // NodeRuntime creates btn, hibe, and jwe ceremonies (createFreshCeremony
  // mints the matching default group for each). Reject anything else up front.
  if (cipher !== "btn" && cipher !== "hibe" && cipher !== "jwe") {
    process.stderr.write(
      `tn: error: tn-js init supports cipher 'btn', 'hibe', or 'jwe' ` +
        `(got ${JSON.stringify(cipher)}).\n`,
    );
    return 1;
  }

  // Resolve the ceremony yaml. A bare project name flips into the
  // `.tn/<name>/` layout via an as-root mint (mirrors Python cmd_init's
  // `_ensure_ceremony_on_disk(name, as_root=True, project_dir=...)`).
  // ensureCeremonyOnDisk is idempotent — re-running attaches to the
  // existing ceremony instead of erroring.
  // Load-or-create the machine-global device identity with the full Python
  // `cmd_init` ceremony (reuse-vs-mint, mnemonic banner, Enter prompt, non-TTY
  // provisioning, --keep-mnemonic / --mnemonic-file / --words). Every
  // flip-minted ceremony is seeded from this one device key so they share ONE
  // device DID — the precondition for warm-attach.
  const identity = await _resolveOrCreateIdentity({
    words,
    mnemonicFile,
    skipConfirm,
    keepMnemonic,
    asJson,
  });

  let resolvedYaml: string | null = yamlPath;
  let flipMint = false;
  let wasFresh = false;
  // Decide the ceremony NAME + project dir. With an explicit --yaml we attach
  // to that yaml. Otherwise: a positional yaml path attaches; a positional name
  // mints `.tn/<name>/`; NO name uses the current folder's name (Python parity).
  if (resolvedYaml === null) {
    let ceremonyName: string;
    let projectDir: string;
    if (projectArg !== null && /\.ya?ml$/i.test(projectArg)) {
      // Positional is an explicit yaml path — attach mode (back-compat).
      resolvedYaml = projectArg;
    } else {
      if (projectArg !== null) {
        ceremonyName = basename(projectArg);
        const parent = dirname(projectArg);
        projectDir = parent === "." ? process.cwd() : pathResolve(parent);
        if (!isValidCeremonyName(ceremonyName)) {
          process.stderr.write(
            `tn: error: invalid project name ${JSON.stringify(ceremonyName)}: use letters, ` +
              "digits, underscore, or dash (must not start with a dash, and 'tn' is reserved).\n",
          );
          return 1;
        }
      } else {
        // No name given: use the current folder's name (Python parity).
        projectDir = process.cwd();
        ceremonyName = basename(projectDir);
        if (!isValidCeremonyName(ceremonyName)) {
          process.stderr.write(
            `tn: error: can't use the current folder name ${JSON.stringify(ceremonyName)} as a ` +
              "project name (use letters, digits, underscore, or dash; not starting with a dash). " +
              "Pass an explicit name: tn-js init <name>.\n",
          );
          return 1;
        }
        if (!asJson) process.stdout.write(`[tn init] no name given; using current folder: ${ceremonyName}\n`);
      }
      flipMint = true;
      const expectedYaml = join(projectDir, ".tn", ceremonyName, "tn.yaml");
      // --force: move an existing ceremony aside (never delete silently) so a
      // re-mint can proceed. Mirrors Python cmd_init's `_overwritten_*` backup.
      if (existsSync(expectedYaml) && force) {
        const stamp = isoStampUtc();
        const backup = join(projectDir, ".tn", `_overwritten_${ceremonyName}_${stamp}`);
        renameSync(join(projectDir, ".tn", ceremonyName), backup);
        if (!asJson) process.stdout.write(`[tn init] --force: prior ceremony moved to ${backup}\n`);
      }
      wasFresh = !existsSync(expectedYaml);
      resolvedYaml = ensureCeremonyOnDisk(ceremonyName, {
        projectDir,
        asRoot: true,
        devicePrivateBytes: identity.seed,
        cipher: cipher as "btn" | "hibe" | "jwe",
      });
      // Stamp the operator-chosen version label into the freshly-minted yaml
      // (ensureCeremonyOnDisk already stamps ceremony.project_name = name).
      if (wasFresh && versionName !== null) stampVersionName(resolvedYaml, versionName);
    }
  }

  // link:false — the CLI runs its OWN vault warm-attach / claim-URL flow below;
  // the module-level auto-link must not also fire (Python's CLI passes link=False).
  const tn = await tnInit(resolvedYaml ?? undefined, { link: false });
  let did: string | null = null;
  let ceremonyId: string | null = null;
  let cfgCipher: string | null = null;
  let keystorePath: string | null = null;
  let projectName: string | null = null;
  try {
    const cfg = (tn.config() ?? {}) as Record<string, unknown>;
    if (typeof cfg.ceremonyId === "string") ceremonyId = cfg.ceremonyId;
    if (typeof cfg.cipher === "string") cfgCipher = cfg.cipher;
    if (typeof cfg.keystorePath === "string") keystorePath = cfg.keystorePath;
    if (typeof cfg.projectName === "string") projectName = cfg.projectName;
    const device = cfg.device as Record<string, unknown> | undefined;
    if (device && typeof device.device_identity === "string") did = device.device_identity;
  } catch {
    // Config readback is best-effort; init itself succeeded.
  }

  // Human ceremony summary — mirrors Python cmd_init's `[tn init]` lines
  // (created vs reused), printed before the vault-attach section below.
  if (!asJson) {
    if (flipMint && wasFresh) {
      process.stdout.write(`[tn init] Ceremony ${ceremonyId ?? "?"} created at ${resolvedYaml}\n`);
      if (projectName) {
        process.stdout.write(
          `[tn init]   project: ${projectName}` +
            (versionName ? ` (version: ${versionName})` : "") +
            "\n",
        );
      }
    } else {
      process.stdout.write(`[tn init] Reusing ceremony ${ceremonyId ?? "?"} at ${resolvedYaml}\n`);
    }
    process.stdout.write(`[tn init]   cipher: ${cfgCipher ?? "btn"}\n`);
    if (keystorePath) process.stdout.write(`[tn init]   keystore: ${keystorePath}\n`);
  }

  // Vault attach. Only on a fresh flip-mint, unless --no-link. Mirrors
  // Python cmd_init: a re-attach to an existing ceremony does NOT re-upload.
  //
  //   WARM path: if TN_API_KEY is set (wins) or the global identity already
  //   carries a linked_account_id, try to authenticate (DID-challenge — the
  //   device DID is a minted DID on the account) and attach the project
  //   directly via wallet.link. No browser, no claim URL.
  //
  //   COLD path: otherwise (or if warm-attach fails), mint a pending claim
  //   and print a CLAIM URL the operator opens in a browser.
  //
  // Failures warn but never fail init — the on-disk ceremony is still valid.
  let claimUrl: string | null = null;
  let attached = false;
  let warmVaultBase: string | null = null; // hoisted: the body backup below runs after tnClose
  if (flipMint && wasFresh && !noLink) {
    const vaultBase = resolveVaultUrl(linkUrl ?? undefined);
    warmVaultBase = vaultBase;

    // Persist the resolved vault into the global identity.json when it was
    // previously null — mirrors Python cmd_init (cli.py:404-406). This makes
    // resolution tier #2 (identity.linkedVault) and future warm-attach work.
    // Best-effort: a write failure must not fail the init.
    if (identity.linkedVault === null) {
      try {
        identity.linkedVault = vaultBase;
        identity.save();
      } catch (e) {
        process.stdout.write(
          `[tn init] WARN could not persist linked vault: ${(e as Error)?.message ?? e}\n`,
        );
      }
    }

    const warmSignal =
      process.env.TN_VAULT_API_KEY || process.env.TN_API_KEY || identity.linkedAccountId;
    if (warmSignal) {
      attached = await _tryWarmAttach(tn, resolvedYaml as string, identity, vaultBase);
    }
    if (!attached) {
      // Cold fallback: pending-claim + claim URL.
      try {
        const res = await tn.initUpload({ vaultBase });
        claimUrl = res.claimUrl;
        process.stdout.write(`\n[tn init] Backed up to ${vaultBase}\n`);
        process.stdout.write(`[tn init]   vault_id:   ${res.vaultId}\n`);
        process.stdout.write(`[tn init]   expires:    ${_formatExpiresLocal(res.expiresAt)}\n`);
        process.stdout.write(
          `\n[tn init] CLAIM URL - open this in your browser to attach the project to your account:\n`,
        );
        process.stdout.write(`  ${res.claimUrl}\n`);
        process.stdout.write(
          `\n[tn init] Already have a vault account, or want to attach this project later?\n`,
        );
        process.stdout.write(`[tn init]   1. Sign in at ${vaultBase}/account\n`);
        process.stdout.write(`[tn init]   2. On the Projects tab, mint a connect code\n`);
        process.stdout.write(
          `[tn init]   3. Run:  tn-js account connect <code> --yaml ${resolvedYaml}\n\n`,
        );
        // Non-blocking by design: init does NOT wait for the browser claim
        // (the old 30-min poll hung every init). The AWK gets cached later —
        // `tn-js auth login` and `tn-js wallet sync` drain the vault's AWK
        // inbox for any pickup the browser sealed to this device DID.
      } catch (e) {
        process.stdout.write(
          `[tn init] WARN backup to vault failed: ${(e as Error)?.message ?? e}\n`,
        );
        process.stdout.write(`[tn init]   The ceremony at ${resolvedYaml} is still valid.\n`);
      }
    }
  }

  // Close the init runtime BEFORE any body backup: walletSyncCmd opens its own
  // short-lived runtime (which rotates the log on init), so running it while
  // this one is open would double-init. Mirrors Python flush_and_close() ahead
  // of the cached-AWK body push.
  await tnClose();

  // Warm body backup: with a cached AWK (from `account connect --passphrase`),
  // push the freshly-minted ceremony body non-interactively now that the
  // credential-free link has registered the project. This is the body leg
  // Python attach_or_sync runs with the cached AWK during cmd_init; no cached
  // AWK -> a one-line hint, never an error (the on-disk ceremony stays valid).
  if (attached && warmVaultBase && identity.linkedAccountId) {
    const awk = loadCachedAwk(identity.linkedAccountId);
    if (awk) {
      try {
        await walletSyncCmd({
          yaml: resolvedYaml as string,
          vault: warmVaultBase,
          awk,
          pushOnly: true,
          stdout: process.stdout,
        });
      } catch (e) {
        process.stdout.write(`[tn init] WARN body backup failed: ${(e as Error)?.message ?? e}\n`);
      }
    } else {
      process.stdout.write(
        "[tn init]   (body backup skipped: run " +
          "`tn-js account connect <code> --passphrase` to cache your account credential)\n",
      );
    }
  }

  // The receipt is opt-in (--json); human output above is the default, matching
  // Python's human-only `tn init` plus the "human preferred" CLI convention.
  if (asJson) {
    process.stdout.write(
      JSON.stringify({
        ok: true,
        yaml_path: resolvedYaml ?? "(discovery)",
        ceremony_id: ceremonyId,
        did,
        ...(claimUrl ? { claim_url: claimUrl } : {}),
        ...(attached ? { attached: true } : {}),
      }) + "\n",
    );
  }
  return 0;
}

/** UTC timestamp `YYYYMMDDTHHMMSSZ` for the --force backup dir (mirrors Python's
 *  `datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")`). */
function isoStampUtc(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

/** True iff both stdin and stdout are TTYs. Mirrors Python `_is_tty`. */
function _isTty(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

/** Print the one-time recovery-phrase banner. Mirrors Python
 *  `_print_mnemonic_banner` (76-char rules). */
function _printMnemonicBanner(mnemonic: string): void {
  const bar = "=".repeat(76);
  process.stdout.write(
    `\n${bar}\n` +
      "  WRITE THIS DOWN NOW. You will NOT see it again without\n" +
      "  explicit re-display, and without it you CANNOT recover\n" +
      "  your TN identity if this machine is lost.\n" +
      `${bar}\n\n` +
      `  ${mnemonic}\n\n` +
      `${bar}\n\n`,
  );
}

/** Pause for Enter on a TTY. Best-effort; never throws. */
async function _promptEnter(prompt: string): Promise<void> {
  if (!_isTty()) return;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    await rl.question(prompt);
  } catch {
    // EOF / closed stream — proceed.
  } finally {
    rl.close();
  }
}

/**
 * Load the machine-global identity or create a fresh one, running the full
 * Python `cmd_init` ceremony: reuse-vs-mint, `--mnemonic-file` derivation,
 * one-time mnemonic banner + Enter prompt on a fresh TTY mint, `--keep-mnemonic`
 * persistence, and non-TTY provisioning (persist the phrase + print a notice,
 * no banner). Returns the resolved Identity (its `seed` seeds every ceremony).
 */
async function _resolveOrCreateIdentity(o: {
  words: number;
  mnemonicFile: string | null;
  skipConfirm: boolean;
  keepMnemonic: boolean;
  asJson: boolean;
}): Promise<Identity> {
  const identityPath = defaultIdentityPath();
  const exists = existsSync(identityPath);
  // Interactive only on a real TTY and not in --json mode (banners/prompts
  // would corrupt the receipt). In non-interactive contexts with no
  // mnemonic-file and no existing identity, provision unattended: persist the
  // mnemonic into identity.json (so it's recoverable) and skip the prompt.
  const interactive = _isTty() && !o.asJson;
  let { skipConfirm, keepMnemonic } = o;
  const nonTtyProvision = !interactive && o.mnemonicFile === null && !exists;
  if (nonTtyProvision) {
    skipConfirm = true;
    keepMnemonic = true;
    if (!o.asJson) {
      process.stdout.write(
        "[tn init] non-interactive mode: mnemonic will be persisted into " +
          "identity.json (treat that file as a secret).\n",
      );
    }
  }

  if (exists) {
    const id = Identity.load(identityPath);
    if (!o.asJson) {
      process.stdout.write(`[tn init] Reusing identity at ${identityPath}\n`);
      process.stdout.write(`[tn init]   DID: ${id.did}\n`);
    }
    return id;
  }

  let id: Identity;
  if (o.mnemonicFile !== null) {
    const wordsText = readFileSync(o.mnemonicFile, "utf8").trim();
    id = Identity.fromMnemonic(wordsText, { path: identityPath });
    if (keepMnemonic) id.mnemonicStored = wordsText;
    if (!o.asJson) process.stdout.write(`[tn init] Identity derived from ${o.mnemonicFile}\n`);
  } else {
    id = Identity.createNew(o.words, { path: identityPath });
    if (interactive) _printMnemonicBanner(id.mnemonic ?? "");
    if (keepMnemonic) {
      id.mnemonicStored = id.mnemonic;
      if (!o.asJson) {
        process.stdout.write(
          "[tn init] --keep-mnemonic is SET: the recovery phrase will be stored " +
            "in identity.json alongside your keys.\n" +
            "[tn init] Anyone with read access to that file can steal your identity. " +
            "Use ONLY on hardware you trust.\n",
        );
      }
    }
    if (!skipConfirm) await _promptEnter("Press Enter after you have recorded the mnemonic... ");
  }
  id.save(identityPath);
  if (!o.asJson) {
    process.stdout.write(`[tn init] New identity written to ${identityPath}\n`);
    process.stdout.write(`[tn init]   DID: ${id.did}\n`);
  }
  return id;
}

/** Stamp `ceremony.version_name` into a freshly-minted yaml, preserving every
 *  other key (read-modify-write). Mirrors Python `_stamp_project_labels` for the
 *  version_name leg (project_name is already stamped by ensureCeremonyOnDisk). */
function stampVersionName(yamlPath: string, versionName: string): void {
  try {
    const doc = (parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown> | null) ?? {};
    const ceremony = (doc["ceremony"] as Record<string, unknown> | undefined) ?? {};
    ceremony["version_name"] = versionName;
    doc["ceremony"] = ceremony;
    writeFileSync(yamlPath, stringifyYaml(doc), "utf8");
  } catch {
    // Best-effort label stamp; a failure must not fail the init.
  }
}

// Warm-attach: authenticate to the vault with the global device identity
// (DID-challenge — the device DID is a minted DID on the account after a
// prior `account connect`) and register the project directly via
// wallet.link. No browser, no claim URL. Returns true on success; false on
// any auth/link failure so the caller falls back to the cold claim-URL path.
// Mirrors Python's `_try_warm_attach`.
async function _tryWarmAttach(
  _tn: Tn,
  yamlPath: string,
  identity: Identity,
  vaultBase: string,
): Promise<boolean> {
  let client: VaultClient;
  try {
    const vid = vaultIdentityFromDeviceKey(identity.deviceKey());
    client = await VaultClient.forIdentity(vid, vaultBase);
  } catch (e) {
    process.stdout.write(
      `[tn init] WARN account auth failed (${(e as Error)?.message ?? e}); using claim URL instead\n`,
    );
    return false;
  }
  try {
    const res = await WalletNamespace.link(client, yamlPath);
    process.stdout.write(`\n[tn init] Attached to your vault account (no browser needed).\n`);
    process.stdout.write(`[tn init]   project:    ${res.projectName}\n`);
    process.stdout.write(`[tn init]   project_id: ${res.projectId}\n`);
    process.stdout.write(`[tn init]   linked:     ${vaultBase}\n\n`);
    return true;
  } catch (e) {
    process.stdout.write(
      `[tn init] WARN account attach failed (${(e as Error)?.message ?? e}); using claim URL instead\n`,
    );
    return false;
  } finally {
    try {
      // VaultClient has no `close()`; the optional-chain mirrors the .mjs's
      // defensive call (a no-op here) without assuming the method exists.
      (client as { close?: () => void })?.close?.();
    } catch {
      /* no-op */
    }
  }
}

// Render the vault's ISO-8601 UTC `expires_at` as local-time + tz label.
// Falls back to the raw ISO string on parse failure. Mirrors Python's
// _format_expires_local.
function _formatExpiresLocal(expiresIso: string): string {
  try {
    const dt = new Date(expiresIso);
    if (Number.isNaN(dt.getTime())) return expiresIso;
    const pad = (n: number) => String(n).padStart(2, "0");
    const local =
      `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ` +
      `${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
    // tz label from Intl when available, else numeric offset.
    let tz = "";
    try {
      const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(dt);
      tz = parts.find((p) => p.type === "timeZoneName")?.value ?? "";
    } catch {
      const off = -dt.getTimezoneOffset();
      const sign = off >= 0 ? "+" : "-";
      const abs = Math.abs(off);
      tz = `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
    }
    return `${local} ${tz}`.trim();
  } catch {
    return expiresIso;
  }
}
