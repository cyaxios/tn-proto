// `tn group add <name>` — add a group to an existing ceremony post-init.
//
// TypeScript port of Python's `tn.cli.cmd_group_add`
// (python/tn/cli.py) + its `p_group_add` parser. Mirrors the verb's
// behaviour, flags, stdout, and exit code:
//
//     tn group add <name> [--fields a,b,c] [--cipher btn|jwe|hibe] [--yaml <path>]
//
// Like Python, group-add was previously API-only (`tn.admin.ensureGroup`).
// This module exposes it on the CLI. Under the multi-ceremony layout the
// group is written to the AUTHORITATIVE project-root yaml (the head of a
// stream's `extends:` chain) so it persists for fresh-process readers and a
// later `add-recipient`. All of it — minting btn keys, writing the
// authoritative `groups.<name>` block, AND routing `--fields` into it — is
// delegated to `tn.admin.ensureGroup({ fields })` →
// `NodeRuntime.persistBtnGroup`, which mirrors Python's
// `ensure_group(cfg, name, fields=..., cipher=...)`.

import { Tn } from "../tn.js";

/** Options for {@link groupAddCmd}, one-to-one with the CLI flags. */
export interface GroupAddOptions {
  /** Group name to add (positional `name`, e.g. "partners"). */
  name: string;
  /** Comma-separated field names to route into this group (`--fields`). */
  fields?: string;
  /** Cipher for the new group (`--cipher`); default = the ceremony's cipher. */
  cipher?: "btn" | "jwe" | "hibe";
  /** Path to tn.yaml (`--yaml`); default = discover via the standard chain. */
  yaml?: string;
}

/**
 * Execute `tn group add`. Returns the process exit code (0 on success),
 * mirroring Python's `cmd_group_add`.
 */
export async function groupAddCmd(opts: GroupAddOptions): Promise<number> {
  // Python: fields = [f.strip() ...] if args.fields else None
  const fields = opts.fields
    ? opts.fields
        .split(",")
        .map((f) => f.trim())
        .filter((f) => f.length > 0)
    : null;

  // Python: tn_init(yaml_path) — Tn.init runs the same discovery chain
  // (TN_YAML / ./tn.yaml / ./.tn/default/tn.yaml / $TN_HOME) when yaml is
  // omitted, matching `_resolve_yaml_or_discover`.
  const tn = await Tn.init(opts.yaml);
  try {
    // Python: ensure_group(cfg, name, fields=fields, cipher=args.cipher)
    // — mints btn keys, writes the authoritative groups.<name> block, and
    // routes the fields into it.
    await tn.admin.ensureGroup(opts.name, {
      ...(opts.cipher ? { cipher: opts.cipher } : {}),
      ...(fields && fields.length > 0 ? { fields } : {}),
    });

    // stdout — byte-for-byte the same three lines Python prints.
    const cipherName = opts.cipher ?? (tn.config() as { cipher?: string }).cipher ?? "btn";
    process.stdout.write(`[tn group add] added group '${opts.name}'\n`);
    if (fields && fields.length > 0) {
      process.stdout.write(`[tn group add]   fields: ${fields.join(", ")}\n`);
    }
    process.stdout.write(`[tn group add]   cipher: ${cipherName}\n`);
  } finally {
    // Python: flush_and_close()
    await tn.close();
  }
  return 0;
}
