// `tn wallet export-mnemonic` — re-display the current identity's BIP-39
// recovery phrase.
//
// TypeScript port of Python's `tn.cli.cmd_wallet_export_mnemonic`
// (python/tn/cli.py ~L1300) + its `p_export` parser (~L3143). Mirrors the
// verb's behaviour, the single `--yes` flag, stdout banner, and exit codes:
//
//     tn wallet export-mnemonic [--yes]
//
// Behaviour (1:1 with Python):
//   * Load the machine-global identity (mirrors `_load_identity_or_die` →
//     `Identity.load(_default_identity_path())`). On a missing/corrupt
//     identity, print the same `tn init` / `tn wallet restore` hint to
//     stderr and exit non-zero.
//   * If no mnemonic was persisted (identity created without
//     `--keep-mnemonic`), print the "no mnemonic stored" guidance to stderr
//     and exit 2. This is NOT a derived/BIP-39 computation — Python's
//     `mnemonic_stored` is a plaintext string that `tn init --keep-mnemonic`
//     wrote into `identity.json`; we surface the SAME field here. We do not
//     reimplement BIP-39.
//   * If `--yes` was not passed, print the "about to display" warning to
//     stdout and exit 2 WITHOUT showing the phrase (matches Python).
//   * With `--yes` and a stored mnemonic, print the banner + phrase, exit 0.
//
// GAP (flagged, not faked): the TS `Identity` class (src/identity.ts) does
// not expose a `mnemonicStored` accessor — it only surfaces the device key
// and link fields, preserving everything else in a private `_raw` doc. The
// `mnemonic_stored` field IS present in identity.json (the Python writer
// persists it, and the TS `Identity.load`/`save` round-trip preserves it),
// so we read it back off the resolved identity-file path rather than adding
// a new accessor to Identity (this task is limited to two new files). When
// Identity grows a `mnemonicStored` getter, swap the file read for it.

import { readFileSync } from "node:fs";

import { Identity, defaultIdentityPath } from "../identity.js";

/** Options for {@link walletExportMnemonicCmd}, one-to-one with the flags. */
export interface WalletExportMnemonicOptions {
  /** `--yes`: confirm you want the phrase displayed on screen. */
  yes?: boolean;
  /**
   * Identity path override (test seam). Mirrors Python's implicit use of
   * `_default_identity_path()`; defaults to that when omitted.
   */
  identityPath?: string;
}

/**
 * Print the recovery-phrase banner. Byte-for-byte mirror of Python's
 * `_print_mnemonic_banner` (python/tn/cli.py ~L93).
 */
function printMnemonicBanner(mnemonic: string): void {
  const bar = "=".repeat(76);
  process.stdout.write("\n");
  process.stdout.write(`${bar}\n`);
  process.stdout.write("  WRITE THIS DOWN NOW. You will NOT see it again without\n");
  process.stdout.write("  explicit re-display, and without it you CANNOT recover\n");
  process.stdout.write("  your TN identity if this machine is lost.\n");
  process.stdout.write(`${bar}\n`);
  process.stdout.write("\n");
  process.stdout.write(`  ${mnemonic}\n`);
  process.stdout.write("\n");
  process.stdout.write(`${bar}\n`);
  process.stdout.write("\n");
}

/**
 * Read the stored mnemonic off the resolved identity file. See the GAP note
 * at the top of this module: `Identity` has no public `mnemonicStored`
 * accessor, so we read the same JSON field Python's `mnemonic_stored` maps
 * to. Returns the trimmed phrase, or null when absent/empty (matching
 * Python's `if not identity.mnemonic_stored` truthiness check).
 */
function readStoredMnemonic(identityFilePath: string): string | null {
  const doc = JSON.parse(readFileSync(identityFilePath, "utf8")) as Record<string, unknown>;
  const raw = doc["mnemonic_stored"];
  if (typeof raw !== "string" || raw.length === 0) return null;
  return raw;
}

/**
 * Execute `tn wallet export-mnemonic`. Returns the process exit code,
 * mirroring Python's `cmd_wallet_export_mnemonic` (0 success / 2 guard /
 * 1 on a missing identity).
 */
export async function walletExportMnemonicCmd(
  opts: WalletExportMnemonicOptions,
): Promise<number> {
  // Python: identity_path = _default_identity_path()
  const identityPath = opts.identityPath ?? defaultIdentityPath();

  // Python: identity = _load_identity_or_die(identity_path). The load is
  // the die-on-missing check; only identityPath is needed afterwards.
  try {
    Identity.load(identityPath);
  } catch (e) {
    // Mirror Python's `_load_identity_or_die`: print the error + the
    // `tn init` / `tn wallet restore` hint to stderr and exit non-zero.
    process.stderr.write(
      `tn: error: ${(e as Error).message}. Run \`tn init <project>\` to create ` +
        "one, or `tn wallet restore --mnemonic ...` on a fresh machine.\n",
    );
    return 1;
  }

  // Python: if not identity.mnemonic_stored: _die(..., code=2)
  const mnemonic = readStoredMnemonic(identityPath);
  if (!mnemonic) {
    process.stderr.write(
      "tn: error: no mnemonic stored on this machine. identity.json was " +
        "created without --keep-mnemonic (the default and safer " +
        "path), so the recovery phrase was only shown once at " +
        "`tn init` time. Record it elsewhere when you first see it.\n" +
        "\n" +
        "If you want future `tn wallet export-mnemonic` calls to " +
        "work, re-run `tn init <new-project> --keep-mnemonic` on a " +
        "fresh project — this stores the phrase in identity.json " +
        "(trades some security for recovery convenience).\n",
    );
    return 2;
  }

  // Python: if not args.yes: print(warning); return 2
  if (!opts.yes) {
    process.stdout.write(
      "ABOUT TO DISPLAY YOUR RECOVERY PHRASE.\n" +
        "Anyone watching your screen can steal your identity.\n" +
        "Re-run with --yes to confirm, or Ctrl-C to abort.\n",
    );
    return 2;
  }

  // Python: _print_mnemonic_banner(identity.mnemonic_stored); return 0
  printMnemonicBanner(mnemonic);
  return 0;
}
