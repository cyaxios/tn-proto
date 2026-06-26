// `tn compile` — thin CLI over the SDK's `compileKitBundleToFile`: build a
// kit-bundle `.tnpkg` from a keystore (or yaml) and print a JSON receipt.
// TypeScript port of the inline `compileCmd` from `bin/tn-js.mjs`.
//
// Behaviour, stdout/stderr, and exit codes match the .mjs verb line-for-line.
// The verb owns no argv parsing: the dispatcher parses the flags and the
// missing-`--out` / missing-`--keystore`-and-`--yaml` guards stay in the
// dispatcher wrapper (those `die(...)` → exit 2). The compile-failure
// `catch` is intrinsic to the command, so it lives here and reproduces the
// .mjs `die` exactly: `tn-js: <msg>` on stderr, exit code 2.

import { compileKitBundleToFile } from "../compile.js";

/** Print `tn-js: <msg>` to stderr and return 2 — the value-returning
 *  analogue of the .mjs module-level `die` (which writes the same bytes and
 *  calls `exit(2)`). The caller owns the process exit. */
function die(msg: string): number {
  process.stderr.write(`tn-js: ${msg}\n`);
  return 2;
}

/** Options for {@link compileCmd}, one-to-one with the .mjs `compile` flags
 *  (`--keystore/--yaml/--out/--label/--kit/--full`). The dispatcher resolves
 *  argv into this shape (including collecting repeated `--kit` into `kits`)
 *  and applies the required-flag guards before calling. */
export interface CompileOptions {
  /** Keystore directory (`--keystore`). Either this or `yaml` is required. */
  keystore?: string;
  /** Path to tn.yaml (`--yaml`). Either this or `keystore` is required. */
  yaml?: string;
  /** Output `.tnpkg` path (`--out`). Required by the verb. */
  out: string;
  /** Bundle label (`--label`). */
  label?: string;
  /** Group names to include (`--kit`, repeatable). Empty ⇒ all groups. */
  kits: string[];
  /** Include full keystore material (`--full`). */
  full: boolean;
}

/**
 * Execute `tn compile`. Returns the process exit code (0 on success, 2 on a
 * compile failure — matching the .mjs `die`).
 */
export function compileCmd(opts: CompileOptions): number {
  try {
    const result = compileKitBundleToFile({
      ...(opts.keystore ? { keystoreDir: opts.keystore } : {}),
      ...(opts.yaml ? { yamlPath: opts.yaml } : {}),
      outPath: opts.out,
      ...(opts.kits.length ? { groups: opts.kits } : {}),
      ...(opts.label ? { label: opts.label } : {}),
      full: opts.full,
    });
    process.stdout.write(
      JSON.stringify({
        ok: true,
        out: result.outPath,
        kits: result.kits,
        kind: result.manifest.kind,
        label: opts.label ?? null,
      }) + "\n",
    );
    return 0;
  } catch (e) {
    return die(e instanceof Error ? e.message : String(e));
  }
}
