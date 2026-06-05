// `tn inbox list-local [--dir <path>]` — list invitation/kit zips found
// locally (default `~/Downloads`), without contacting the vault.
//
// TypeScript parity port of Python's `tn.inbox` `list-local` subcommand
// (python/tn/inbox.py): the `main()` dispatcher's `list-local` branch, the
// `_cmd_list_local` wrapper, and `list_local(...)`. Behaviour, the `--dir`
// flag, stdout lines, and exit code match the Python verb line-for-line:
//
//     python -m tn.inbox list-local [--dir ~/Downloads]
//
// The vault is a one-way channel: Alice deposits a zip, Frank downloads it,
// Frank lists/accepts locally. This verb is the read-only "what did I
// download?" half — no vault contact, no write-back.
//
// Kept as a standalone, dependency-injectable function (explicit options +
// stdout/stderr sinks) so it can be unit-tested in-process and later wired
// into `bin/tn-js.mjs` without re-plumbing — exactly like `absorbCmd`.

import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve as pathResolve } from "node:path";

/** Options for {@link inboxListLocalCmd}. Mirrors the Python `p_list`
 *  parser: a single optional `--dir` flag. */
export interface InboxListLocalOptions {
  /** Directory to scan (`--dir`). When omitted, defaults to `~/Downloads`,
   *  matching Python's `list_local(downloads_dir=None)`. */
  dir?: string;
  /** Sink for normal output. Defaults to `process.stdout.write`. Injected
   *  so tests can capture without poking global streams. */
  stdout?: (line: string) => void;
  /** Sink for error output. Defaults to `process.stderr.write`. Present for
   *  signature parity with the other verbs; this verb never errors. */
  stderr?: (line: string) => void;
}

/**
 * List `tn-invite-*.zip` files in `downloadsDir` (or `~/Downloads`).
 *
 * Mirror of Python's `list_local`: a non-existent directory yields an empty
 * list (not an error), and matches are returned sorted by path string.
 *
 * @returns Absolute paths of the matching zips, sorted ascending.
 */
export function listLocal(downloadsDir?: string): string[] {
  // Python: downloads_dir = Path.home() / "Downloads" when None.
  const dir = downloadsDir ?? join(homedir(), "Downloads");
  // Python: if not downloads_dir.exists(): return []
  if (!existsSync(dir)) return [];
  // Python: sorted(downloads_dir.glob("tn-invite-*.zip"))
  const matches = readdirSync(dir)
    .filter((name) => name.startsWith("tn-invite-") && name.endsWith(".zip"))
    .map((name) => join(dir, name));
  // Python sorts Path objects, i.e. by the full path string; the directory
  // prefix is identical for every entry, so this is equivalent to sorting by
  // filename. Sort the full paths to match Python's ordering exactly.
  matches.sort();
  return matches;
}

/**
 * Execute `tn inbox list-local`. Returns the process exit code (always 0;
 * `_cmd_list_local` never raises and `main()` does not `sys.exit` on this
 * branch). Mirrors Python's `_cmd_list_local`.
 *
 * @param opts See {@link InboxListLocalOptions}.
 */
export async function inboxListLocalCmd(
  opts: InboxListLocalOptions = {},
): Promise<number> {
  const out = opts.stdout ?? ((s: string) => void process.stdout.write(s));

  // Python: dir_path = Path(args.dir).expanduser().resolve() if args.dir else None
  const dirPath = opts.dir ? pathResolve(expanduser(opts.dir)) : undefined;

  const zips = listLocal(dirPath);

  if (zips.length === 0) {
    // Python: d = dir_path or (Path.home() / "Downloads")
    const d = dirPath ?? join(homedir(), "Downloads");
    out(`No tn-invite-*.zip files found in ${d}\n`);
    return 0;
  }

  // Python: print(f"Found {len(zips)} invitation zip(s):")
  out(`Found ${zips.length} invitation zip(s):\n`);
  for (const z of zips) {
    // Python: print(f"  {z}")
    out(`  ${z}\n`);
  }
  return 0;
}

/** Expand a leading `~` to the user's home directory, mirroring Python's
 *  `Path.expanduser()` for the only form the CLI passes (`~` / `~/...`). */
function expanduser(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) {
    return join(homedir(), p.slice(2));
  }
  return p;
}
