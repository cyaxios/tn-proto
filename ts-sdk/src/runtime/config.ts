// Ceremony yaml loader. Mirrors the minimum shape that tn.logger.init
// consumes in Python. Only btn ceremonies are supported; jwe/bgw fall
// outside the Rust-backed path (those stay Python-owned for now).

import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { parse as parseYaml } from "yaml";

export interface RecipientSpec {
  did: string;
}

export interface GroupConfig {
  name: string;
  policy: string;
  cipher: string;
  recipients: RecipientSpec[];
}

export interface CeremonyConfig {
  yamlPath: string;
  yamlDir: string;
  ceremonyId: string;
  mode: string;
  cipher: string;
  logPath: string;
  keystorePath: string;
  me: { did: string };
  publicFields: Set<string>;
  /**
   * Multi-group field routing: a field listed under N groups in yaml
   * is encrypted into all N groups' payloads. Each group's reader
   * sees the same plaintext value independently. The list per field is
   * sorted alphabetically at load time so canonical envelope encoding
   * stays deterministic across SDKs.
   */
  fieldToGroups: Map<string, string[]>;
  groups: Map<string, GroupConfig>;
  defaultPolicy: string;
  sign: boolean;
  /**
   * Optional ceremony.protocol_events_location value. "main_log"
   * (default) keeps tn.* events in the main log. Anything else is
   * treated as a path template (e.g. ./.tn/logs/admin/{event_type}.ndjson)
   * under the yaml directory. Used by scan helpers so reconciliation
   * doesn't miss events that a Python-side writer routed off.
   */
  protocolEventsLocation: string;
  /**
   * Optional ``ceremony.log_level`` from yaml. ``"debug"`` (the floor,
   * default) emits everything; ``"info"`` drops debug-level emits;
   * ``"warning"`` drops debug+info; ``"error"`` drops everything below
   * error. Honored by the client at init unless `setLevel(...)` was
   * already called programmatically. (AVL J3.2.)
   */
  logLevel?: string;
  /**
   * Raw yaml ``handlers:`` block. Each entry is a freeform object
   * (typically `{kind: "file.rotating", path: ..., ...}` or
   * `{kind: "stdout"}`). The TS runtime currently writes to a
   * hardcoded file sink + an optional stdout sink (see
   * ``TNClient.init``); this field exposes the operator's declared
   * intent so the client can honor it (e.g. silence stdout when the
   * yaml's handlers list explicitly omits it — FINDINGS S0.4 parity
   * with Python).
   */
  handlers: Array<Record<string, unknown>>;
}

function pathFromYaml(yamlDir: string, raw: string): string {
  return isAbsolute(raw) ? raw : resolve(yamlDir, raw);
}

// Compose-style env-var substitution. Mirrors `_substitute_env_vars` in
// `tn-protocol/python/tn/config.py` and the Rust helper in
// `tn-protocol/crypto/tn-core/src/config.rs`. Applied to the raw yaml
// *string* before yaml parsing so the substitution model matches
// docker-compose's: simple textual replacement with no awareness of
// yaml types. Recognized syntax:
//   ${NAME}             - required; throws if NAME is unset
//   ${NAME:-default}    - falls back to `default` when NAME is unset
//   $${literal}         - escape; emits the literal `${literal}`
// Variable names follow `[A-Za-z_][A-Za-z0-9_]*`. No recursive expansion.
const ENV_VAR_RE = /(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g;
const BAD_ENV_VAR_RE = /(?<!\$)\$\{([^}]*)\}/g;
const STRICT_ENV_VAR_RE = /^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}$/;

export function substituteEnvVars(text: string, sourcePath: string): string {
  const lineOf = (offset: number): number => {
    let line = 1;
    for (let i = 0; i < offset; i += 1) {
      if (text.charCodeAt(i) === 10) line += 1;
    }
    return line;
  };

  // Validate first against the *original* text so we surface helpful
  // errors for malformed references like `${1FOO}` or `${FOO BAR}`
  // before substitution scrambles offsets.
  BAD_ENV_VAR_RE.lastIndex = 0;
  let badMatch: RegExpExecArray | null;
  while ((badMatch = BAD_ENV_VAR_RE.exec(text)) !== null) {
    const token = badMatch[0];
    if (!STRICT_ENV_VAR_RE.test(token)) {
      throw new Error(
        `${sourcePath}:${lineOf(badMatch.index)}: ` +
          `malformed env-var reference ${JSON.stringify(token)} ` +
          "(expected ${NAME} or ${NAME:-default} where " +
          "NAME matches [A-Za-z_][A-Za-z0-9_]*)",
      );
    }
  }

  const substituted = text.replace(ENV_VAR_RE, (match, name: string, def: string | undefined, offset: number) => {
    const env = process.env[name];
    if (env !== undefined) return env;
    if (def !== undefined) return def;
    throw new Error(
      `${sourcePath}:${lineOf(offset)}: ` +
        `required environment variable \${${name}} is not set ` +
        `(use \${${name}:-default} to provide a fallback)`,
    );
  });

  // Collapse `$$` to `$` last so escaped tokens survive the substitution.
  return substituted.replace(/\$\$/g, "$");
}

export function loadConfig(yamlPath: string): CeremonyConfig {
  const resolved = resolve(yamlPath);
  const rawText = readFileSync(resolved, "utf8");
  const text = substituteEnvVars(rawText, resolved);
  const doc = parseYaml(text) as Record<string, unknown>;
  const yamlDir = dirname(resolved);

  const ceremony = (doc.ceremony ?? {}) as Record<string, unknown>;
  const me = (doc.me ?? {}) as Record<string, unknown>;
  const logs = (doc.logs ?? {}) as Record<string, unknown>;
  const keystore = (doc.keystore ?? {}) as Record<string, unknown>;
  const fieldsMap = (doc.fields ?? {}) as Record<string, unknown>;
  const groups = (doc.groups ?? {}) as Record<string, unknown>;
  const publicFields = Array.isArray(doc.public_fields) ? (doc.public_fields as string[]) : [];

  // Reserved namespace check: `tn.*` group names are reserved for
  // protocol-level conventions (per the 2026-04-25 read-ergonomics spec
  // §2.2). The only allowed name in the reserved namespace is the
  // auto-injected `tn.agents` group. Anything else is rejected at load
  // time so the failure surfaces at `init()` not at first emit.
  for (const gname of Object.keys(groups)) {
    if (gname.startsWith("tn.") && gname !== "tn.agents") {
      throw new Error(
        `${resolved}: reserved group name: ${gname} ` +
          `(the \`tn.*\` namespace is for protocol-level conventions; ` +
          `only \`tn.agents\` is allowed). Rename your group.`,
      );
    }
  }

  const groupMap = new Map<string, GroupConfig>();
  // Track per-group field declarations for the new canonical multi-group
  // routing path (`groups[<name>].fields: [...]`). When any group declares
  // its fields the inverted map is built from that; otherwise we fall
  // back to the legacy flat `fields:` block (deprecated, warned below).
  const perGroupFields = new Map<string, string[]>();
  let anyGroupDeclaresFields = false;
  for (const [name, raw] of Object.entries(groups)) {
    const g = raw as Record<string, unknown>;
    const recipients = Array.isArray(g.recipients)
      ? (g.recipients as Array<Record<string, unknown>>).map((r) => ({ did: String(r.did ?? "") }))
      : [];
    groupMap.set(name, {
      name,
      policy: String(g.policy ?? "private"),
      cipher: String(g.cipher ?? ceremony.cipher ?? "btn"),
      recipients,
    });
    if (Array.isArray(g.fields)) {
      anyGroupDeclaresFields = true;
      const list: string[] = [];
      for (const f of g.fields) {
        if (typeof f !== "string") {
          throw new Error(
            `${resolved}: groups.${name}.fields entries must be strings ` +
              `(got ${typeof f})`,
          );
        }
        list.push(f);
      }
      perGroupFields.set(name, list);
    }
  }
  if (!groupMap.has("default")) {
    groupMap.set("default", {
      name: "default",
      policy: "private",
      cipher: String(ceremony.cipher ?? "btn"),
      recipients: me.did ? [{ did: String(me.did) }] : [],
    });
  }

  const fieldToGroups = new Map<string, string[]>();
  if (anyGroupDeclaresFields) {
    for (const [gname, fnames] of perGroupFields) {
      for (const fname of fnames) {
        const list = fieldToGroups.get(fname) ?? [];
        if (!list.includes(gname)) list.push(gname);
        fieldToGroups.set(fname, list);
      }
    }
  } else if (Object.keys(fieldsMap).length > 0) {
    // Back-compat: legacy flat `fields:` block. Emit a deprecation warning
    // so callers migrate to per-group declarations.
    console.warn(
      `${resolved}: the flat top-level \`fields:\` block is deprecated; ` +
        "declare field membership inside each group as " +
        "`groups[<name>].fields: [...]`. The flat form supports only one " +
        "group per field and will be removed in a future release.",
    );
    for (const [fname, fspec] of Object.entries(fieldsMap)) {
      let gname: string;
      if (typeof fspec === "string") {
        gname = fspec;
      } else if (fspec && typeof fspec === "object" && "group" in fspec) {
        gname = String((fspec as Record<string, unknown>).group ?? "default");
      } else {
        throw new Error(
          `${resolved}: fields.${fname} must be a string group name or ` +
            `{group: <name>} (got ${typeof fspec})`,
        );
      }
      const list = fieldToGroups.get(fname) ?? [];
      if (!list.includes(gname)) list.push(gname);
      fieldToGroups.set(fname, list);
    }
  }

  // Validation: every routed group must exist.
  const knownGroups = new Set(groupMap.keys());
  for (const [fname, gnames] of fieldToGroups) {
    for (const gname of gnames) {
      if (!knownGroups.has(gname)) {
        throw new Error(
          `${resolved}: field ${JSON.stringify(fname)} routed to unknown ` +
            `group ${JSON.stringify(gname)} ` +
            `(known groups: ${JSON.stringify([...knownGroups].sort())})`,
        );
      }
    }
  }

  // Validation: a field cannot be both public and group-routed.
  const publicSet = new Set(publicFields);
  const overlap = [...fieldToGroups.keys()].filter((f) => publicSet.has(f)).sort();
  if (overlap.length > 0) {
    throw new Error(
      `${resolved}: fields ${JSON.stringify(overlap)} appear in both ` +
        "public_fields and a group's fields: list. A field is either " +
        "public (plaintext on the envelope) or encrypted into one or " +
        "more groups, never both.",
    );
  }

  // Sort each group list deterministically (alphabetical) so canonical
  // envelope encoding is stable across SDKs regardless of yaml key order.
  for (const [fname, gnames] of fieldToGroups) {
    fieldToGroups.set(fname, [...new Set(gnames)].sort());
  }

  const cfg: CeremonyConfig = {
    yamlPath: resolved,
    yamlDir,
    ceremonyId: String(ceremony.id ?? ""),
    mode: String(ceremony.mode ?? "local"),
    cipher: String(ceremony.cipher ?? "btn"),
    logPath: pathFromYaml(yamlDir, String(logs.path ?? "./.tn/logs/tn.ndjson")),
    keystorePath: pathFromYaml(yamlDir, String(keystore.path ?? "./.tn/keys")),
    me: { did: String(me.did ?? "") },
    publicFields: new Set(publicFields),
    fieldToGroups,
    groups: groupMap,
    defaultPolicy: String(doc.default_policy ?? "private"),
    sign: (ceremony.sign as boolean | undefined) ?? true,
    protocolEventsLocation: String(
      ceremony.admin_log_location ?? ceremony.protocol_events_location ?? "main_log",
    ),
    // Pass the raw handlers list through so the client can honor
    // operator intent (FINDINGS S0.4): when the yaml declares a
    // handlers block without a stdout entry, stdout should not fire
    // for any emit (admin or user).
    handlers: Array.isArray(doc.handlers)
      ? (doc.handlers as Array<unknown>).filter(
          (h): h is Record<string, unknown> =>
            !!h && typeof h === "object" && !Array.isArray(h),
        )
      : [],
  };
  if (typeof ceremony.log_level === "string" && ceremony.log_level) {
    cfg.logLevel = ceremony.log_level;
  }
  return cfg;
}
