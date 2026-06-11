// `tn absorb <package>` — install a `.tnpkg` (kit bundle, enrolment, etc.)
// into the active ceremony. TypeScript parity port of Python's
// `cmd_absorb` (python/tn/cli.py). Behaviour, flags, stdout, and exit
// codes match the Python verb line-for-line, including the self-absorb
// guard added in 0.4.2a9.
//
// The verb is kept as a standalone, dependency-injectable function so it
// can be unit-tested in-process (no subprocess) and later wired into
// `bin/tn-js.mjs` without re-plumbing. It owns no argv parsing; the
// caller resolves flags into the explicit `AbsorbCmdOptions` shape.

import { existsSync } from "node:fs";
import { isAbsolute, resolve as pathResolve } from "node:path";
import { homedir } from "node:os";

import { NodeRuntime } from "../runtime/node_runtime.js";
import { readTnpkg } from "../tnpkg_io.js";

/** Options for {@link absorbCmd}. Mirrors the Python `p_absorb` parser:
 *  positional `package`; flags `--yaml`, `--allow-self-absorb`. */
export interface AbsorbCmdOptions {
  /** Path to the `.tnpkg` to absorb (the positional `package` argument). */
  packagePath: string;
  /** Path to the absorber's `tn.yaml`. When omitted, discover via the
   *  standard chain (`$TN_YAML`, `./tn.yaml`, `~/.tn/tn.yaml`). */
  yaml?: string;
  /** Allow absorbing a `.tnpkg` this ceremony itself minted. Default is
   *  to refuse (self-absorb overwrites the publisher's own keystore with
   *  a reader-kit copy). */
  allowSelfAbsorb?: boolean;
  /** Sink for normal output. Defaults to `process.stdout.write`. Injected
   *  so tests can capture without poking global streams. */
  stdout?: (line: string) => void;
  /** Sink for error output. Defaults to `process.stderr.write`. */
  stderr?: (line: string) => void;
}

/** Print `tn: error: <msg>` to stderr and return `code` — the TS analogue
 *  of Python's `_die`, but as a value-returning helper so the caller owns
 *  the process exit. Mirrors `python/tn/cli.py::_die`. */
function die(stderr: (line: string) => void, msg: string, code = 1): number {
  stderr(`tn: error: ${msg}\n`);
  return code;
}

/** Resolve the yaml path: explicit arg if given (must exist), else walk a
 *  minimal discovery chain (`$TN_YAML`, `./tn.yaml`, `~/.tn/tn.yaml`).
 *  Returns the resolved path, or a `die` exit code on a missing explicit
 *  arg. Mirrors `_resolve_yaml_or_discover` for the branches the verb can
 *  reach (the cwd ceremony-sniffing fallback is Python-only). */
function resolveYamlOrDiscover(
  arg: string | undefined,
  stderr: (line: string) => void,
): { yamlPath: string } | { code: number } {
  if (arg) {
    const p = pathResolve(arg);
    if (!existsSync(p)) return { code: die(stderr, `yaml not found: ${p}`) };
    return { yamlPath: p };
  }
  const env = process.env["TN_YAML"];
  if (env && existsSync(env)) {
    return { yamlPath: isAbsolute(env) ? env : pathResolve(env) };
  }
  const cwdYaml = pathResolve("tn.yaml");
  if (existsSync(cwdYaml)) return { yamlPath: cwdYaml };
  const homeYaml = pathResolve(homedir(), ".tn", "tn.yaml");
  if (existsSync(homeYaml)) return { yamlPath: homeYaml };
  return { code: die(stderr, "no tn.yaml found (pass --yaml or set $TN_YAML)") };
}

/**
 * Absorb a `.tnpkg` into the active ceremony.
 *
 * Returns the process exit code (0 on success, non-zero on error). Never
 * throws for the expected failure modes — it prints the Python-matching
 * `tn: error: ...` message and returns the matching code:
 *
 *   - package not found            → code 1
 *   - yaml not found (explicit)    → code 1
 *   - self-absorb without override → code 2
 *
 * @param opts See {@link AbsorbCmdOptions}.
 */
export async function absorbCmd(opts: AbsorbCmdOptions): Promise<number> {
  const out = opts.stdout ?? ((s: string) => void process.stdout.write(s));
  const err = opts.stderr ?? ((s: string) => void process.stderr.write(s));

  const resolved = resolveYamlOrDiscover(opts.yaml, err);
  if ("code" in resolved) return resolved.code;
  const yamlPath = resolved.yamlPath;

  const pkgPath = pathResolve(opts.packagePath);
  if (!existsSync(pkgPath)) {
    return die(err, `package not found: ${pkgPath}`);
  }

  const rt = NodeRuntime.init(yamlPath);
  try {
    // 0.4.2a9: reject self-absorb. A .tnpkg whose `from_did` matches the
    // active ceremony's DID means the publisher is trying to absorb a
    // bundle they just minted — that overwrites their OWN publisher
    // keystore with a reader-kit copy. The absorb path warns on the
    // collision but proceeds; that's a foot-cannon in a CLI. Block it at
    // the verb so the user has to use `--allow-self-absorb` (escape hatch
    // for tests). Matches python/tn/cli.py::cmd_absorb.
    let fromDid: string | null = null;
    try {
      const { manifest } = readTnpkg(pkgPath);
      // `manifest.fromDid` is the TS-side camelCase mirror of the wire
      // field `publisher_identity` (see core/tnpkg.ts).
      fromDid = manifest.fromDid ?? null;
    } catch {
      // Not a zip / no manifest / bad JSON — let the real absorb path
      // produce its own error message about the corrupt package.
      fromDid = null;
    }
    if (fromDid && fromDid === rt.did && !opts.allowSelfAbsorb) {
      return die(
        err,
        `refusing to absorb a package this ceremony minted ` +
          `(from_did=${fromDid}). Absorbing it would overwrite ` +
          `the publisher's own keystore with a reader-kit ` +
          `copy. Pass --allow-self-absorb if you actually ` +
          `intend to do this (tests, recovery flows).`,
        2,
      );
    }

    const receipt = rt.absorbPkg(pkgPath);

    const kind = receipt.kind ?? "?";
    const accepted = receipt.acceptedCount ?? 0;
    const skipped = receipt.dedupedCount ?? 0;
    out(`[tn absorb] kind=${kind} accepted=${accepted} skipped=${skipped}\n`);
    const replaced = receipt.replacedKitPaths ?? [];
    if (replaced.length > 0) {
      out(`[tn absorb] WARN: overwrote ${replaced.length} existing kit file(s):\n`);
      for (const p of replaced) {
        out(`             ${p}\n`);
      }
      out(
        "[tn absorb] prior bytes preserved at <name>.previous.<UTC_TS> " +
          "in the same directory.\n",
      );
    }
    return accepted >= 0 ? 0 : 1;
  } finally {
    rt.close();
  }
}
