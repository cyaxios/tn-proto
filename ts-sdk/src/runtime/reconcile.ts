// Init-time reconciliation helpers for NodeRuntime.
//
// Mirrors tn-protocol/python/tn/__init__.py's _scan_attested_events and
// _emit_missing_recipients so Python and TS agree on idempotence and
// yaml-driven recipient provisioning.
//
// - iterLogFiles(cfg): every ndjson file where attested events for this
//   ceremony could live (main log + any PEL tree from
//   protocol_events_location).
// - scanAttestedEvents(cfg, eventType, key): set of values at
//   envelope[key] for matching events across all log files.
// - emitMissingRecipients(runtime): for each yaml recipient without a
//   matching tn.recipient.added/revoked event, mint + write + attest.
// - scanAttestedGroups(yamlPath): convenience sugar for tests and the
//   dashboard; wraps scanAttestedEvents with "group" as the key.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";

import { loadConfig, type CeremonyConfig } from "./config.js";

/**
 * Enumerate every ndjson file where attested events for this ceremony
 * could live. Always includes the main log. If
 * `ceremony.protocol_events_location` is set to a path template with
 * or without a `{event_type}` placeholder, recursively sweeps the
 * directory above the template for ndjson files.
 */
export function iterLogFiles(cfg: CeremonyConfig): string[] {
  const out: string[] = [];
  if (existsSync(cfg.logPath)) out.push(cfg.logPath);
  const pel = cfg.protocolEventsLocation;
  if (!pel || pel === "main_log") return out;
  // Resolve the template against yamlDir. Strip "./" and split off the
  // stem before the first substitution to get a stable directory.
  let base = pel.startsWith("./") ? pel.slice(2) : pel;
  base = base.split("{")[0] ?? base;
  let resolvedBase: string;
  try {
    resolvedBase = resolve(cfg.yamlDir, base);
  } catch {
    return out;
  }
  // The template may resolve to a file (no {}), a file-prefix, or a
  // directory. We always walk its parent looking for ndjson siblings.
  const parent = pel.includes("{") ? resolvedBase : dirname(resolvedBase);
  if (!existsSync(parent)) return out;
  try {
    const st = statSync(parent);
    if (!st.isDirectory()) return out;
  } catch {
    return out;
  }
  const stack: string[] = [parent];
  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        stack.push(full);
      } else if (name.endsWith(".ndjson") && !out.includes(full)) {
        out.push(full);
      }
    }
  }
  return out;
}

/**
 * Walk every log file associated with `cfg` and return the set of
 * values at `envelope[key]` for envelopes whose `event_type` matches.
 */
export function scanAttestedEvents(
  cfg: CeremonyConfig,
  eventType: string,
  key: string = "group",
): Set<string> {
  const out = new Set<string>();
  for (const path of iterLogFiles(cfg)) {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split(/\r?\n/)) {
      if (!line) continue;
      try {
        const env = JSON.parse(line);
        if (env.event_type !== eventType) continue;
        const v = env[key];
        if (v !== undefined && v !== null) out.add(String(v));
      } catch {
        // skip malformed lines
      }
    }
  }
  return out;
}

/** Variant that returns the full envelope records, not just one key. */
export function scanAttestedEventRecords(
  cfg: CeremonyConfig,
  eventType: string,
): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const path of iterLogFiles(cfg)) {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split(/\r?\n/)) {
      if (!line) continue;
      try {
        const env = JSON.parse(line);
        if (env.event_type === eventType) out.push(env);
      } catch {
        // skip
      }
    }
  }
  return out;
}

/**
 * Convenience wrapper for callers that just want "which groups have
 * been attested in the log(s)". Used by tests and the dashboard.
 * Takes a yaml path so it's callable without pre-loading the cfg.
 */
export function scanAttestedGroups(yamlPath: string): Set<string> {
  const cfg = loadConfig(yamlPath);
  return scanAttestedEvents(cfg, "tn.group.added", "group");
}

/**
 * Read the yaml one more time (via js-yaml parse on the file) and
 * pull every declared recipient DID per group. Matches Python's
 * _yaml_recipient_dids behavior: the loaded GroupConfig drops the
 * recipients list for non-bookkeeping ciphers, so we re-parse.
 */
export function yamlRecipientDids(cfg: CeremonyConfig): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let doc: Record<string, unknown>;
  try {
    doc = parseYaml(readFileSync(cfg.yamlPath, "utf8")) as Record<string, unknown>;
  } catch {
    return out;
  }
  const groups = (doc?.groups ?? {}) as Record<string, unknown>;
  for (const [gname, raw] of Object.entries(groups)) {
    const g = raw as Record<string, unknown>;
    const rs = Array.isArray(g?.recipients) ? g.recipients : [];
    const dids: string[] = [];
    for (const r of rs as Array<Record<string, unknown>>) {
      if (r && typeof r === "object" && r.did) dids.push(String(r.did));
    }
    out.set(gname, dids);
  }
  return out;
}
