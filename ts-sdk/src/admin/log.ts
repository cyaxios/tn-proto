// Dedicated admin log routing.
//
// Mirrors python/tn/admin_log.py — the prefix predicate + default path
// resolution + dedupe / append helpers for `<yamlDir>/.tn/admin/admin.ndjson`.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import { dirname, isAbsolute, resolve as pathResolve } from "node:path";

import type { CeremonyConfig } from "../runtime/config.js";

export const DEFAULT_ADMIN_LOG_LOCATION = "./.tn/admin/admin.ndjson";

const ADMIN_PREFIXES = [
  "tn.ceremony.",
  "tn.group.",
  "tn.recipient.",
  "tn.rotation.",
  "tn.coupon.",
  "tn.enrolment.",
  "tn.vault.",
  // `tn.agents.policy_published` carries the inline markdown text + hash
  // of the active policy file at init time (per 2026-04-25 spec §2.7).
  // Belongs in the admin log so policy version history is replayable.
  "tn.agents.",
  // Tampered-row visibility (per spec §3.3). `tn.read.tampered_row_skipped`
  // is emitted by `secureRead()` when a row fails (sig|row_hash|chain)
  // verification. Public fields only — no body content.
  "tn.read.",
];

/** True iff `eventType` belongs to the admin-log prefix family. */
export function isAdminEventType(eventType: unknown): boolean {
  if (typeof eventType !== "string") return false;
  return ADMIN_PREFIXES.some((p) => eventType.startsWith(p));
}

/** Resolve the absolute admin log path for `cfg`. Mirrors Python's
 * `resolve_admin_log_path`: respects a single-file `protocol_events_location`
 * override, else falls back to `<yamlDir>/.tn/admin/admin.ndjson`. */
export function resolveAdminLogPath(cfg: CeremonyConfig): string {
  const yamlDir = cfg.yamlDir;
  const pel = cfg.protocolEventsLocation;
  if (pel && pel !== "main_log" && !pel.includes("{")) {
    return isAbsolute(pel) ? pel : pathResolve(yamlDir, pel);
  }
  return pathResolve(yamlDir, DEFAULT_ADMIN_LOG_LOCATION);
}

/** Set of `row_hash` strings present in an admin ndjson file (used by
 * absorb to dedupe). Returns an empty set if the file does not exist. */
export function existingRowHashes(adminLog: string): Set<string> {
  const out = new Set<string>();
  if (!existsSync(adminLog)) return out;
  const text = readFileSync(adminLog, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const s = rawLine.trim();
    if (!s) continue;
    try {
      const env = JSON.parse(s) as Record<string, unknown>;
      const rh = env["row_hash"];
      if (typeof rh === "string") out.add(rh);
    } catch {
      /* skip malformed lines */
    }
  }
  return out;
}

/** Append a sequence of envelope dicts to the admin ndjson file. Creates
 * the parent directory lazily. Each line uses compact JSON separators
 * to match the on-disk format Python writes. */
export function appendAdminEnvelopes(
  adminLog: string,
  envelopes: Iterable<Record<string, unknown>>,
): number {
  const dir = dirname(adminLog);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  let written = 0;
  for (const env of envelopes) {
    appendFileSync(adminLog, JSON.stringify(env) + "\n");
    written += 1;
  }
  return written;
}
