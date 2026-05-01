// Markdown loader for `.tn/config/agents.md` policy files.
//
// Per the 2026-04-25 read-ergonomics spec §2.4 the canonical format for
// the `tn.agents` policy file is markdown. Each event type is a
// `## <event_type>` section; each section MUST have all five required
// `### <field>` subsections (`instruction`, `use_for`, `do_not_use_for`,
// `consequences`, `on_violation_or_error`).
//
// A YAML-frontmatter block at the top carries `version` and `schema`.
// The loader is intentionally tiny — split-on-line-prefix is enough.
//
// Returned per event type:
//
//     {
//       eventType: "...",
//       instruction: "...",
//       useFor: "...",
//       doNotUseFor: "...",
//       consequences: "...",
//       onViolationOrError: "...",
//       contentHash: "sha256:...",
//       version: "v1",
//       path: ".tn/config/agents.md",
//     }
//
// If the file is missing, `loadPolicyFile()` returns `null` — absence is
// not an error (no policy → no splice → `tn.agents` group stays empty for
// every event). Mirrors `tn-protocol/python/tn/_agents_policy.py`.
//
// Layer 1 — browser-safe: no node:* imports.

import { sha256HexBytes } from "./chain.js";

export const POLICY_RELATIVE_PATH = ".tn/config/agents.md";

/** Five required `### <field>` subsections per `## <event_type>` block. */
export const REQUIRED_FIELDS = [
  "instruction",
  "use_for",
  "do_not_use_for",
  "consequences",
  "on_violation_or_error",
] as const;

export type RequiredField = (typeof REQUIRED_FIELDS)[number];

/** One event type's worth of policy text. */
export interface PolicyTemplate {
  eventType: string;
  instruction: string;
  use_for: string;
  do_not_use_for: string;
  consequences: string;
  on_violation_or_error: string;
  /** "sha256:<hex>" — same value for every template parsed from the same file. */
  contentHash: string;
  version: string;
  /** Repository-relative path, e.g. ".tn/config/agents.md". */
  path: string;
}

/** Top-level shape returned by `loadPolicyFile`. */
export interface PolicyDocument {
  templates: Map<string, PolicyTemplate>;
  version: string;
  schema: string;
  path: string;
  /** Raw markdown text after frontmatter. */
  body: string;
  /** sha256 of canonical-bytes(per_event_dict). */
  contentHash: string;
}

/** Stable JSON encoding for hashing — sorted keys, compact separators. */
function canonicalBytes(obj: unknown): Uint8Array {
  return new TextEncoder().encode(stableStringify(obj));
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(JSON.stringify(k) + ":" + stableStringify(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}

/** Pull a tiny `key: value` block off the top of the doc.
 *
 * Frontmatter is the leading lines before the first `# ` heading. Each
 * line must look like `key: value`. Two supported flavours:
 *
 * 1. Plain leading lines (no fences) before the first `# ` heading.
 * 2. A fenced block delimited by `---` lines (Jekyll-style).
 *
 * Anything inside `# TN Agents Policy` (the title) belongs to the body.
 */
function stripFrontmatter(text: string): { meta: Record<string, string>; rest: string } {
  const lines = text.split(/\r?\n/);
  const meta: Record<string, string> = {};

  // Fenced `---` style.
  if (lines.length > 0 && lines[0]!.trim() === "---") {
    let end = -1;
    for (let i = 1; i < lines.length; i += 1) {
      if (lines[i]!.trim() === "---") {
        end = i;
        break;
      }
    }
    if (end > 0) {
      for (let i = 1; i < end; i += 1) {
        const ln = lines[i]!;
        const idx = ln.indexOf(":");
        if (idx >= 0) {
          meta[ln.slice(0, idx).trim()] = ln.slice(idx + 1).trim();
        }
      }
      return { meta, rest: lines.slice(end + 1).join("\n") };
    }
  }

  // Plain-leading style: scan until the first level-1 or level-2 heading.
  let bodyStart = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const ln = lines[i]!;
    if (ln.startsWith("# ") || ln.startsWith("## ")) {
      bodyStart = i;
      break;
    }
    const s = ln.trim();
    if (!s) continue;
    const idx = s.indexOf(":");
    if (idx >= 0) {
      meta[s.slice(0, idx).trim()] = s.slice(idx + 1).trim();
    }
  }
  return { meta, rest: lines.slice(bodyStart).join("\n") };
}

/** Drop a single leading `# ` heading and any frontmatter-shaped
 * `key: value` lines that follow it (some authors put `version: 1` under
 * the title rather than at the very top of the file).
 */
function stripTitle(body: string): string {
  const lines = body.split(/\r?\n/);
  while (lines.length > 0 && !lines[0]!.trim()) lines.shift();
  if (lines.length > 0 && lines[0]!.startsWith("# ")) lines.shift();
  while (lines.length > 0) {
    const s = lines[0]!.trim();
    if (s.startsWith("## ")) break;
    if (!s) {
      lines.shift();
      continue;
    }
    if (s.includes(":") && !s.startsWith("#")) {
      lines.shift();
      continue;
    }
    break;
  }
  return lines.join("\n");
}

/** Split `body` on `## ` headings. Returns `[(eventType, body), ...]`. */
function splitEventSections(body: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let curEvent: string | null = null;
  let curLines: string[] = [];
  for (const ln of body.split(/\r?\n/)) {
    if (ln.startsWith("## ")) {
      if (curEvent !== null) {
        out.push([curEvent, curLines.join("\n").trim()]);
      }
      curEvent = ln.slice(3).trim();
      curLines = [];
    } else {
      curLines.push(ln);
    }
  }
  if (curEvent !== null) {
    out.push([curEvent, curLines.join("\n").trim()]);
  }
  return out;
}

/** Split one event-type section on `### ` subheadings. */
function splitFieldSections(sectionBody: string): Record<string, string> {
  const out: Record<string, string> = {};
  let cur: string | null = null;
  let curLines: string[] = [];
  for (const ln of sectionBody.split(/\r?\n/)) {
    if (ln.startsWith("### ")) {
      if (cur !== null) {
        out[cur] = curLines.join("\n").trim();
      }
      cur = ln.slice(4).trim();
      curLines = [];
    } else {
      curLines.push(ln);
    }
  }
  if (cur !== null) {
    out[cur] = curLines.join("\n").trim();
  }
  return out;
}

/** Parse a markdown policy doc.
 *
 * Throws `Error` if a section is missing one of the five required
 * subfields, or if frontmatter is malformed. `path` is a label only; no
 * I/O is done by this function.
 */
export function parsePolicyText(text: string, path: string): PolicyDocument {
  const { meta, rest } = stripFrontmatter(text);
  const body = stripTitle(rest);

  const version = String(meta.version ?? "1");
  const schema = String(meta.schema ?? "tn-agents-policy@v1");

  const sections = splitEventSections(body);
  const templates = new Map<string, PolicyTemplate>();
  const perEventForHash: Record<string, Record<string, string>> = {};

  for (const [eventType, sectionBody] of sections) {
    if (!eventType) continue;
    const fields = splitFieldSections(sectionBody);
    const missing: string[] = [];
    for (const f of REQUIRED_FIELDS) {
      if (!(f in fields) || !fields[f]) missing.push(f);
    }
    if (missing.length > 0) {
      throw new Error(
        `${path}: agents policy section ## ${eventType} is missing ` +
          `required subsection(s): ${JSON.stringify(missing)}`,
      );
    }

    perEventForHash[eventType] = {};
    for (const f of REQUIRED_FIELDS) {
      perEventForHash[eventType]![f] = fields[f]!;
    }
  }

  const canonical = canonicalBytes({ events: perEventForHash, schema, version });
  const contentHash = "sha256:" + sha256HexBytes(canonical);

  for (const [eventType, payload] of Object.entries(perEventForHash)) {
    templates.set(eventType, {
      eventType,
      instruction: payload["instruction"]!,
      use_for: payload["use_for"]!,
      do_not_use_for: payload["do_not_use_for"]!,
      consequences: payload["consequences"]!,
      on_violation_or_error: payload["on_violation_or_error"]!,
      contentHash,
      version,
      path,
    });
  }

  return {
    templates,
    version,
    schema,
    path,
    body: text,
    contentHash,
  };
}

/** Canonical path for the policy file given a yaml directory.
 *
 * Uses plain string concatenation (no node:path) — forward slashes are
 * accepted by existsSync / readFileSync on all platforms including
 * Windows. Layer 2 (src/agents_policy.ts) owns the actual I/O.
 */
export function policyPathFor(yamlDir: string): string {
  return `${yamlDir}/${POLICY_RELATIVE_PATH}`;
}
