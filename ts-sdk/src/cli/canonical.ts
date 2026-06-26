// `tn-js canonical` — stdin filter that echoes canonical bytes.
//
// Diagnostic: reads one JSON object per line from stdin and writes the
// canonical (JCS) byte encoding of each as a UTF-8 line to stdout.
// TypeScript port of the inline `canonicalCmd` in `bin/tn-js.mjs`;
// behaviour, stdout bytes, and exit codes are verbatim.

import { Buffer } from "node:buffer";
import { stdout } from "node:process";

import { canonicalize } from "../core/canonical.js";
import { forEachLine } from "./_stdin.js";

/**
 * Execute `tn-js canonical`. Reads JSON lines from stdin and writes the
 * canonical encoding of each. Returns the process exit code (0).
 */
export async function canonicalCmd(): Promise<number> {
  // Useful diagnostic: echo canonical bytes of stdin JSON.
  await forEachLine((inp) => {
    const bytes = canonicalize(inp);
    stdout.write(Buffer.from(bytes).toString("utf8") + "\n");
  });
  return 0;
}
