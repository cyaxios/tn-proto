// `tn vault link|unlink` — record a vault link/unlink as an attested audit
// event on the ceremony log.
//
// TypeScript port of the untyped `vaultCmd` from `bin/tn-js.mjs`. Mirrors
// the verb's behaviour, flags, stdout, and exit code:
//
//     tn vault link <vault-did> <project-id> [--yaml <path>]
//     tn vault unlink <vault-did> <project-id> [--reason <r>] [--yaml <path>]
//
// This is a sub-dispatcher over `argv[3]` (`link`/`unlink`) reading the
// positionals + flags out of `argv.slice(4)`. It wraps `tn.vault.link` /
// `tn.vault.unlink` (VaultNamespace, exposed on the Tn instance) and prints
// the resulting receipt as a single JSON line.

import { Tn } from "../tn.js";

/** Print `tn-js: <msg>` to stderr and return exit code 2 — the
 *  value-returning analogue of the .mjs `die` so the caller owns
 *  process exit. */
function die(msg: string): number {
  process.stderr.write(`tn-js: ${msg}\n`);
  return 2;
}

/**
 * Execute `tn vault link|unlink`. Takes the FULL process argv (`argv[3]` is
 * the subcommand, `argv.slice(4)` the positionals + flags), mirroring the
 * .mjs indexing verbatim. Returns the process exit code.
 */
export async function vaultCmd(argv: string[]): Promise<number> {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts: {
    yaml: string | null;
    vaultDid: string | null;
    projectId: string | null;
    reason: string | null;
  } = { yaml: null, vaultDid: null, projectId: null, reason: null };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === undefined) continue;
    if (a === "--yaml") opts.yaml = rest[++i] ?? null;
    else if (a === "--reason") opts.reason = rest[++i] ?? null;
    else if (!a.startsWith("-")) {
      if (opts.vaultDid === null) opts.vaultDid = a;
      else if (opts.projectId === null) opts.projectId = a;
    }
  }
  if (sub !== "link" && sub !== "unlink") {
    return die(
      `vault: unknown subcommand ${sub}. try: vault link <vault-did> <project-id> [--yaml <path>]`,
    );
  }
  if (!opts.vaultDid || !opts.projectId) {
    return die(`vault ${sub}: <vault-did> and <project-id> are required positionals`);
  }
  const tn = await Tn.init(opts.yaml ?? undefined);
  try {
    const receipt =
      sub === "link"
        ? await tn.vault.link(opts.vaultDid, opts.projectId)
        : await tn.vault.unlink(opts.vaultDid, opts.projectId, opts.reason ?? undefined);
    process.stdout.write(
      JSON.stringify({
        ok: true,
        verb: `vault.${sub}`,
        event_id: receipt.eventId,
        row_hash: receipt.rowHash,
        vault_did: opts.vaultDid,
        project_id: opts.projectId,
      }) + "\n",
    );
  } finally {
    await tn.close();
  }
  return 0;
}
