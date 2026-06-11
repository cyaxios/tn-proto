// `tn group add <name>` — add a group to an existing ceremony post-init.
//
// TypeScript port of Python's `tn.cli.cmd_group_add`
// (python/tn/cli.py) + its `p_group_add` parser. Mirrors the verb's
// behaviour, flags, stdout, and exit code:
//
//     tn group add <name> [--fields a,b,c] [--cipher btn|jwe] [--yaml <path>]
//
// Like Python, group-add was previously API-only (`tn.admin.ensureGroup`).
// This module exposes it on the CLI. Under the multi-ceremony layout the
// group is written to the AUTHORITATIVE project-root yaml (the head of a
// stream's `extends:` chain) so it persists for fresh-process readers and a
// later `add-recipient`. The heavy lifting (mint btn keys + write the
// authoritative `groups.<name>` block) is delegated to the existing SDK
// machinery — `tn.admin.ensureGroup` → `NodeRuntime.persistBtnGroup`. The
// only thing layered on top here is `--fields` routing, which the TS
// `ensureGroup` does not yet accept; it is written into the SAME
// authoritative yaml exactly as Python's `_yaml_add_fields` does.

import { readFileSync, writeFileSync } from "node:fs";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { Tn } from "../tn.js";
import { authoritativeYamlFor } from "../runtime/config.js";

/** Options for {@link groupAddCmd}, one-to-one with the CLI flags. */
export interface GroupAddOptions {
  /** Group name to add (positional `name`, e.g. "partners"). */
  name: string;
  /** Comma-separated field names to route into this group (`--fields`). */
  fields?: string;
  /** Cipher for the new group (`--cipher`); default = the ceremony's cipher. */
  cipher?: "btn" | "jwe";
  /** Path to tn.yaml (`--yaml`); default = discover via the standard chain. */
  yaml?: string;
}

/**
 * Mirror of Python's `_yaml_add_fields`: record `fields` under
 * `groups[<group>].fields` (canonical, multi-group) AND in the legacy flat
 * `fields:` block (single-route back-compat). De-dupes while preserving
 * order. Writes into the authoritative yaml that owns `groups`.
 */
function addFieldRoutes(yamlPath: string, group: string, fields: string[]): void {
  const target = authoritativeYamlFor(yamlPath, "groups");
  const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};

  // Canonical: groups[<group>].fields
  const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
  const gspec = (groups[group] ?? {}) as Record<string, unknown>;
  const existingRaw = gspec.fields;
  const existing: string[] = Array.isArray(existingRaw)
    ? (existingRaw as unknown[]).map((f) => String(f))
    : [];
  const seen = new Set(existing);
  for (const f of fields) {
    if (!seen.has(f)) {
      existing.push(f);
      seen.add(f);
    }
  }
  gspec.fields = existing;
  groups[group] = gspec;
  doc.groups = groups;

  // Legacy flat block — keep up to date for single-route consumers.
  const flat = (doc.fields ?? {}) as Record<string, unknown>;
  for (const f of fields) {
    flat[f] = { group };
  }
  doc.fields = flat;

  writeFileSync(target, stringifyYaml(doc), "utf8");
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
    // — mints btn keys + writes the authoritative groups.<name> block.
    await tn.admin.ensureGroup(opts.name, opts.cipher ? { cipher: opts.cipher } : undefined);

    // TS ensureGroup has no `fields` arg yet; layer the field routing onto
    // the authoritative yaml the same way Python's ensure_group does.
    if (fields && fields.length > 0) {
      const yamlPath = (tn.config() as { yamlPath?: string }).yamlPath ?? "";
      addFieldRoutes(yamlPath, opts.name, fields);
    }

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
