// `tn import <package>` — restore a `project_seed` backup into a project
// directory. TypeScript port of the inline `importCmd` from `bin/tn-js.mjs`.
// Behaviour, flags, stdout, and exit codes match the original verb
// byte-for-byte:
//
//   tn-js import <package> [--cwd <dir>]
//
// The verb owns no argv parsing; the caller (dispatcher) resolves flags into
// the explicit {@link ImportCmdOptions} shape and forwards the exit code.
//
// On any expected misuse the original called the dispatcher's `die`, which
// writes `tn-js: <msg>\n` to stderr and `process.exit(2)`. That exact
// behaviour is preserved via the local {@link die} helper below.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve as pathResolve } from "node:path";

import { absorbBootstrap } from "../runtime/absorb_bootstrap.js";

/** Options for {@link importCmd}. Mirrors the inline `importCmd` flag set:
 *  positional `package`; flags `--cwd`, `--json`. */
export interface ImportCmdOptions {
  /** Path to the `.tnpkg` to restore (the positional `package` argument). */
  packagePath?: string;
  /** Directory to restore into (`--cwd`). Defaults to `process.cwd()`. */
  cwd?: string;
  /** Print the structured receipt instead of the human `[tn import]` lines
   *  (`--json`). */
  json?: boolean;
}

/** Replicates the dispatcher's `die`: write `tn-js: <msg>\n` to stderr and
 *  exit the process with code 2. Preserves the original verb's exact
 *  stderr bytes and exit code. */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

/** Runtime/restore errors exit 1 with the `tn: error:` prefix (Python `_die`),
 *  distinct from the exit-2 usage `die` above. */
function dieRuntime(msg: string): never {
  process.stderr.write(`tn: error: ${msg}\n`);
  process.exit(1);
}

/**
 * Execute `tn import`. Returns the process exit code (0 on success). On any
 * expected misuse it calls {@link die}, which exits the process with code 2
 * — matching the inline `importCmd` it ports.
 *
 * @param opts See {@link ImportCmdOptions}.
 */
export function importCmd(opts: ImportCmdOptions): number {
  // tn-js import <package> [--cwd <dir>] — restore a project_seed backup.
  const pkg = opts.packagePath ?? null;
  const cwd = opts.cwd ?? process.cwd();
  if (!pkg) die("import: <package> path is required");
  const pkgPath = pathResolve(pkg);
  // Not-found / empty / restore failures are runtime errors → exit 1 (Python
  // _die), not the exit-2 usage path.
  if (!existsSync(pkgPath) || statSync(pkgPath).size === 0) {
    dieRuntime(`package not found or empty: ${pkgPath}`);
  }
  const cwdAbs = pathResolve(cwd);
  let receipt: ReturnType<typeof absorbBootstrap>;
  try {
    receipt = absorbBootstrap(pkgPath, { cwd: cwdAbs });
  } catch (exc) {
    // Surface a clean CLI error instead of a stack trace (mirrors Python's
    // try/except around absorb()).
    dieRuntime(`import failed: ${exc instanceof Error ? exc.message : String(exc)}`);
  }
  if (receipt.rejectedReason) {
    dieRuntime(`[tn import] rejected: ${receipt.rejectedReason}`);
  }
  // The receipt's derivedState doesn't carry the restored DID; read it
  // back from the installed keystore so the output is verifiable.
  let restoredDid: string | null = null;
  const stack: string[] = [cwdAbs];
  while (stack.length) {
    const dir = stack.pop() as string;
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) stack.push(p);
      else if (name === "local.public") restoredDid = readFileSync(p, "utf8").trim();
    }
    if (restoredDid) break;
  }
  if (opts.json === true) {
    process.stdout.write(
      JSON.stringify({
        ok: true,
        kind: receipt.kind,
        accepted: receipt.acceptedCount,
        device_identity: restoredDid,
      }) + "\n",
    );
    return 0;
  }
  // Human summary — mirrors Python cli_pkg.cmd_import `[tn import]` lines.
  process.stdout.write(`[tn import] restored kind=${receipt.kind} files=${receipt.acceptedCount}\n`);
  if (restoredDid) {
    process.stdout.write(`[tn import]   device:  ${restoredDid}\n`);
  }
  process.stdout.write(
    "[tn import] ceremony is live here; run `tn-js read` or `tn-js info --event <event_type>`.\n",
  );
  return 0;
}
