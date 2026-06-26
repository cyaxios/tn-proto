// Shared stdin-filter plumbing for the `seal` / `verify` / `canonical`
// CLI verbs. These three commands are line-oriented stdin filters: they
// read one JSON object per line from stdin and write one line per input
// to stdout. This module factors out the two helpers they share —
// `forEachLine` (the per-line JSON reader) and `cliDie` (the fatal-error
// printer) — so the per-command modules under `src/cli/` stay thin.
//
// Behaviour is a verbatim port of the inline `forEachLine` + `die`
// helpers in `bin/tn-js.mjs`: same stdout/stderr bytes and same exit
// codes (spawn-based tests assert exact output).

import { createInterface } from "node:readline";
import { stdin, exit } from "node:process";

/**
 * Print `tn-js: <msg>\n` to stderr and terminate the process with exit
 * code 2. Verbatim port of `bin/tn-js.mjs::die`.
 *
 * The return type is `never`: the call exits the process, so it never
 * returns. Typing it `never` lets callers use it in expression position
 * (e.g. inside the JSON-parse catch) without TypeScript complaining that
 * a value-producing branch is missing.
 */
export function cliDie(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  return exit(2);
}

/**
 * Read stdin line by line, parse each non-blank line as JSON, and invoke
 * `handler` with the parsed value. A line that fails to parse triggers
 * `cliDie` (exit 2), matching the inline helper. Verbatim port of
 * `bin/tn-js.mjs::forEachLine`.
 *
 * The parsed value is typed `unknown`; each command narrows the fields it
 * reads. (The original untyped `.mjs` read fields off the parsed object
 * directly; the per-command modules cast to a local input shape.)
 */
export async function forEachLine(
  handler: (input: unknown) => unknown,
): Promise<void> {
  const rl = createInterface({ input: stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let input: unknown;
    try {
      input = JSON.parse(line);
    } catch (e) {
      cliDie(`invalid JSON on stdin: ${(e as Error).message}`);
    }
    await handler(input);
  }
}
