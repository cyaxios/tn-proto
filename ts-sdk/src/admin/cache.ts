// Materialized AdminState LKV cache — Layer 2 wrapper.
//
// Mirrors `python/tn/admin_cache.py`. Adds filesystem (LKV file) + log-tailing
// on top of the pure `AdminStateReducer` (Layer 1) in `./core/admin_state.ts`.
//
// The reducer handles all event-folding logic; this class handles:
//  * Reading the ndjson admin log from disk.
//  * Persisting/restoring the materialised state to/from the LKV file.
//  * Detecting when the log has advanced (via envelope-count check) and
//    triggering an incremental replay.
//
// Convergence rules (enforced by the reducer, documented here for context):
//  * `tn.recipient.added` events are idempotent under set union.
//  * `tn.recipient.revoked` events are absorbing: once a leaf revokes,
//    subsequent adds for the same `(group, leaf_index)` are flagged
//    as `LeafReuseAttempt` and excluded from `state.recipients`.
//  * `tn.rotation.completed` events are monotonic on `(group, generation)`.
//    Two events at the same generation with different `previous_kit_sha256`
//    are flagged as `RotationConflict`.
//  * Same-coordinate forks (`(did, event_type, sequence)` seen twice
//    with different `row_hash`) are flagged as `SameCoordinateFork`.
//
// All conflicts surface in `cache.headConflicts`. The reducer never
// throws — divergence is informational. `cache.diverged()` is the
// strict-callers' fast path.

import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import { isAdminEventType, resolveAdminLogPath } from "./log.js";
import type {
  AdminCeremonyState,
  AdminState,
  RecipientEntry,
} from "../core/types.js";
import type { CeremonyConfig } from "../runtime/config.js";
import {
  AdminStateReducer,
  emptyState,
  type ChainConflict,
} from "../core/admin/state.js";

/** Bump if the on-disk LKV layout changes incompatibly. */
export const LKV_VERSION = 1;

// Re-export conflict types so existing callers of admin_cache.js continue to
// find them here (transitional re-export; prefer importing from core/admin_state).
export type {
  ChainConflict,
  LeafReuseAttempt,
  RotationConflict,
  SameCoordinateFork,
} from "../core/admin/state.js";

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// emptyState is re-exported from core/admin_state; keep the alias private.
export { emptyState } from "../core/admin/state.js";

function lkvPathFor(cfg: CeremonyConfig): string {
  return pathResolve(cfg.yamlDir, ".tn", "admin", "admin.lkv.json");
}

// Separator used inside Map keys. Must match the SEP constant in core/admin_state.ts.
const SEP = " ";

// ---------------------------------------------------------------------
// AdminStateCache — Layer 2 (fs + log-tailing)
// ---------------------------------------------------------------------

export class AdminStateCache {
  private readonly cfg: CeremonyConfig;
  private readonly lkvPath: string;

  private readonly _reducer: AdminStateReducer;
  private _atOffset = 0;

  constructor(cfg: CeremonyConfig) {
    this.cfg = cfg;
    this.lkvPath = lkvPathFor(this.cfg);
    this._reducer = new AdminStateReducer();
    this._loadFromDisk();
  }

  // ---- Public surface ------------------------------------------------

  get atOffset(): number {
    this._refreshIfLogAdvanced();
    return this._atOffset;
  }

  get headRowHash(): string | null {
    this._refreshIfLogAdvanced();
    return this._reducer.headRowHash;
  }

  get headConflicts(): ChainConflict[] {
    this._refreshIfLogAdvanced();
    return [...this._reducer.conflicts];
  }

  /** Vector clock as `{did → {event_type → max_seq}}`. */
  clock(): Record<string, Record<string, number>> {
    this._refreshIfLogAdvanced();
    const out: Record<string, Record<string, number>> = {};
    for (const [k, seq] of this._reducer.clock) {
      const idx = k.indexOf(SEP);
      if (idx < 0) continue;
      const did = k.slice(0, idx);
      const et = k.slice(idx + SEP.length);
      if (!did || !et) continue;
      const slot = out[did] ?? {};
      slot[et] = seq;
      out[did] = slot;
    }
    return out;
  }

  state(): AdminState {
    this._refreshIfLogAdvanced();
    return this._reducer.state;
  }

  recipients(group: string, opts?: { includeRevoked?: boolean }): RecipientEntry[] {
    this._refreshIfLogAdvanced();
    const includeRevoked = opts?.includeRevoked ?? false;
    const out: RecipientEntry[] = [];
    for (const rec of this._reducer.state.recipients) {
      if (rec.group !== group) continue;
      if (!includeRevoked && rec.activeStatus !== "active") continue;
      out.push({
        leafIndex: rec.leafIndex,
        recipientDid: rec.recipientDid,
        mintedAt: rec.mintedAt,
        kitSha256: rec.kitSha256,
        revoked: rec.activeStatus === "revoked" || rec.activeStatus === "retired",
        revokedAt: rec.revokedAt,
      });
    }
    return out.sort((a, b) => a.leafIndex - b.leafIndex);
  }

  /** True iff any same-coordinate fork has been observed. Leaf-reuse
   * attempts and rotation conflicts are recorded but do not count. */
  diverged(): boolean {
    this._refreshIfLogAdvanced();
    return this._reducer.conflicts.some((c) => c.type === "same_coordinate_fork");
  }

  /** Force a reload from the log. Returns the number of newly ingested
   * envelopes. Idempotent. */
  refresh(): number {
    const before = this._atOffset;
    this._replayForward();
    this._saveToDisk();
    return this._atOffset - before;
  }

  // ---- Internal ------------------------------------------------------

  private _sourcePaths(): string[] {
    const main = this.cfg.logPath;
    const admin = resolveAdminLogPath(this.cfg);
    const out: string[] = [];
    if (existsSync(main)) out.push(main);
    if (admin !== main && existsSync(admin)) out.push(admin);
    return out;
  }

  private _totalEnvelopeCount(): number {
    let total = 0;
    for (const path of this._sourcePaths()) {
      let text: string;
      try {
        text = readFileSync(path, "utf8");
      } catch {
        continue;
      }
      for (const line of text.split(/\r?\n/)) {
        const s = line.trim();
        if (!s) continue;
        try {
          const env = JSON.parse(s) as Record<string, unknown>;
          if (isAdminEventType(env["event_type"])) total += 1;
        } catch {
          /* skip */
        }
      }
    }
    return total;
  }

  private _refreshIfLogAdvanced(): void {
    if (this._totalEnvelopeCount() <= this._atOffset) return;
    this._replayForward();
    this._saveToDisk();
  }

  private _replayForward(): void {
    const envs: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (const path of this._sourcePaths()) {
      let text: string;
      try {
        text = readFileSync(path, "utf8");
      } catch {
        continue;
      }
      for (const line of text.split(/\r?\n/)) {
        const s = line.trim();
        if (!s) continue;
        let env: Record<string, unknown>;
        try {
          env = JSON.parse(s) as Record<string, unknown>;
        } catch {
          continue;
        }
        if (!isAdminEventType(env["event_type"])) continue;
        const rh = env["row_hash"];
        if (typeof rh !== "string") continue;
        if (seen.has(rh)) continue;
        seen.add(rh);
        envs.push(env);
      }
    }
    // applyMany handles sorting + dedup against already-applied hashes.
    this._reducer.applyMany(envs, this._reducer.seenRowHashes);
    this._atOffset = this._reducer.seenRowHashes.size;
  }

  // ---- Persistence ---------------------------------------------------

  private _saveToDisk(): void {
    const dir = dirname(this.lkvPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const clockOut: Record<string, Record<string, number>> = {};
    for (const [k, seq] of this._reducer.clock) {
      const idx = k.indexOf(SEP);
      if (idx < 0) continue;
      const did = k.slice(0, idx);
      const et = k.slice(idx + SEP.length);
      if (!did || !et) continue;
      const slot = clockOut[did] ?? {};
      slot[et] = seq;
      clockOut[did] = slot;
    }
    const doc = {
      version: LKV_VERSION,
      ceremony_id: this.cfg.ceremonyId,
      clock: clockOut,
      head_row_hash: this._reducer.headRowHash,
      at_offset: this._atOffset,
      state: this._reducer.state,
      head_conflicts: this._reducer.conflicts,
      _row_hashes: [...this._reducer.seenRowHashes].sort(),
      _revoked_leaves: [...this._reducer.revokedLeaves.entries()].map(([k, rh]) => {
        const idx = k.indexOf(SEP);
        const group = idx >= 0 ? k.slice(0, idx) : k;
        const leafStr = idx >= 0 ? k.slice(idx + SEP.length) : "";
        return { group, leaf_index: Number(leafStr), row_hash: rh };
      }),
      _rotations_seen: [...this._reducer.rotationsSeen.entries()].map(([k, prev]) => {
        const idx = k.indexOf(SEP);
        const group = idx >= 0 ? k.slice(0, idx) : k;
        const genStr = idx >= 0 ? k.slice(idx + SEP.length) : "";
        return { group, generation: Number(genStr), previous_kit_sha256: prev };
      }),
      _coord_to_row_hash: [...this._reducer.coordToRowHash.entries()].map(([k, v]) => {
        // Key format: "did{SEP}et{SEP}seq"
        const first = k.indexOf(SEP);
        const d = first >= 0 ? k.slice(0, first) : k;
        const rest = first >= 0 ? k.slice(first + SEP.length) : "";
        const second = rest.indexOf(SEP);
        const et = second >= 0 ? rest.slice(0, second) : rest;
        const seqStr = second >= 0 ? rest.slice(second + SEP.length) : "";
        return { did: d, event_type: et, sequence: Number(seqStr), row_hash: v };
      }),
    };
    const tmp = `${this.lkvPath}.tmp`;
    writeFileSync(tmp, JSON.stringify(doc, null, 2), "utf8");
    renameSync(tmp, this.lkvPath);
  }

  private _loadFromDisk(): void {
    if (!existsSync(this.lkvPath)) return;
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(readFileSync(this.lkvPath, "utf8")) as Record<string, unknown>;
    } catch {
      return;
    }
    if (doc["version"] !== LKV_VERSION) return;
    if (doc["ceremony_id"] !== this.cfg.ceremonyId) return;

    const state = emptyState();
    const stateRaw = doc["state"];
    if (stateRaw && typeof stateRaw === "object" && !Array.isArray(stateRaw)) {
      const s = stateRaw as Record<string, unknown>;
      if ("ceremony" in s) state.ceremony = (s["ceremony"] as AdminCeremonyState | null) ?? null;
      if (Array.isArray(s["groups"])) state.groups = s["groups"] as AdminState["groups"];
      if (Array.isArray(s["recipients"]))
        state.recipients = s["recipients"] as AdminState["recipients"];
      if (Array.isArray(s["rotations"]))
        state.rotations = s["rotations"] as AdminState["rotations"];
      if (Array.isArray(s["coupons"])) state.coupons = s["coupons"] as AdminState["coupons"];
      if (Array.isArray(s["enrolments"]))
        state.enrolments = s["enrolments"] as AdminState["enrolments"];
      if (Array.isArray(s["vaultLinks"]))
        state.vaultLinks = s["vaultLinks"] as AdminState["vaultLinks"];
    }

    const clock = new Map<string, number>();
    const clockDoc = doc["clock"];
    if (clockDoc && typeof clockDoc === "object" && !Array.isArray(clockDoc)) {
      for (const [did, etMap] of Object.entries(clockDoc as Record<string, unknown>)) {
        if (!etMap || typeof etMap !== "object" || Array.isArray(etMap)) continue;
        for (const [et, seq] of Object.entries(etMap as Record<string, unknown>)) {
          const n = typeof seq === "number" ? seq : Number(seq);
          if (Number.isFinite(n)) clock.set(`${did}${SEP}${et}`, Math.trunc(n));
        }
      }
    }

    const headRowHash =
      typeof doc["head_row_hash"] === "string" ? (doc["head_row_hash"] as string) : null;
    const offRaw = doc["at_offset"];
    this._atOffset = typeof offRaw === "number" ? offRaw : Number(offRaw) || 0;

    const conflicts: ChainConflict[] = [];
    const conflictsRaw = doc["head_conflicts"];
    if (Array.isArray(conflictsRaw)) {
      for (const c of conflictsRaw) {
        if (c && typeof c === "object" && (c as { type?: unknown }).type !== undefined) {
          conflicts.push(c as ChainConflict);
        }
      }
    }

    const rowHashes = new Set<string>();
    const rhRaw = doc["_row_hashes"];
    if (Array.isArray(rhRaw)) for (const rh of rhRaw) rowHashes.add(String(rh));

    const revokedLeaves = new Map<string, string | null>();
    const revokedRaw = doc["_revoked_leaves"];
    if (Array.isArray(revokedRaw)) {
      for (const e of revokedRaw) {
        if (e && typeof e === "object") {
          const r = e as Record<string, unknown>;
          if (typeof r["group"] === "string" && typeof r["leaf_index"] === "number") {
            revokedLeaves.set(
              `${r["group"]}${SEP}${r["leaf_index"]}`,
              typeof r["row_hash"] === "string" ? (r["row_hash"] as string) : null,
            );
          }
        }
      }
    }

    const rotationsSeen = new Map<string, string>();
    const rotsRaw = doc["_rotations_seen"];
    if (Array.isArray(rotsRaw)) {
      for (const e of rotsRaw) {
        if (e && typeof e === "object") {
          const r = e as Record<string, unknown>;
          if (typeof r["group"] === "string" && typeof r["generation"] === "number") {
            rotationsSeen.set(
              `${r["group"]}${SEP}${r["generation"]}`,
              String(r["previous_kit_sha256"] ?? ""),
            );
          }
        }
      }
    }

    const coordToRowHash = new Map<string, string>();
    const coordsRaw = doc["_coord_to_row_hash"];
    if (Array.isArray(coordsRaw)) {
      for (const e of coordsRaw) {
        if (e && typeof e === "object") {
          const r = e as Record<string, unknown>;
          if (
            typeof r["did"] === "string" &&
            typeof r["event_type"] === "string" &&
            typeof r["sequence"] === "number" &&
            typeof r["row_hash"] === "string"
          ) {
            coordToRowHash.set(
              `${r["did"]}${SEP}${r["event_type"]}${SEP}${r["sequence"]}`,
              r["row_hash"] as string,
            );
          }
        }
      }
    }

    this._reducer.reset({
      state,
      clock,
      headRowHash,
      conflicts,
      rowHashes,
      revokedLeaves,
      rotationsSeen,
      coordToRowHash,
    });
  }
}

export { lkvPathFor };
