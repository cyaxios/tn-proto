// Materialized AdminState LKV cache.
//
// Mirrors `python/tn/admin_cache.py` — replays admin envelopes from the
// log forward into a materialized `AdminState`, persists the result to
// `<yamlDir>/.tn/admin/admin.lkv.json`, and surfaces the convergence
// rules from the 2026-04-24 admin log architecture plan §6.1:
//
//  * `tn.recipient.added` events are idempotent under set union.
//  * `tn.recipient.revoked` events are absorbing: once a leaf revokes,
//    subsequent adds for the same `(group, leaf_index)` are flagged
//    as `LeafReuseAttempt` and excluded from `state.recipients`.
//  * `tn.rotation.completed` events are monotonic on `(group, generation)`.
//    Two events at the same generation with different
//    `previous_kit_sha256` are flagged as `RotationConflict`.
//  * Same-coordinate forks (`(did, event_type, sequence)` seen twice
//    with different `row_hash`) are flagged as `SameCoordinateFork`.
//
// All conflicts surface in `cache.headConflicts`. The reducer never
// throws — divergence is informational. `cache.diverged()` is the
// strict-callers' fast path.

import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import { isAdminEventType, resolveAdminLogPath } from "./admin_log.js";
import type {
  AdminCeremonyState,
  AdminEnrolmentState,
  AdminRecipientState,
  AdminState,
  AdminVaultLinkState,
  RecipientEntry,
} from "./client.js";
import type { TNClient } from "./client.js";
import type { CeremonyConfig } from "./runtime/config.js";

/** Bump if the on-disk LKV layout changes incompatibly. */
export const LKV_VERSION = 1;

// ---------------------------------------------------------------------
// Conflict types
// ---------------------------------------------------------------------

export interface LeafReuseAttempt {
  type: "leaf_reuse_attempt";
  group: string;
  leafIndex: number;
  attemptedRowHash: string;
  originallyRevokedAtRowHash: string | null;
}

export interface SameCoordinateFork {
  type: "same_coordinate_fork";
  did: string;
  eventType: string;
  sequence: number;
  rowHashes: [string, string];
}

export interface RotationConflict {
  type: "rotation_conflict";
  group: string;
  generation: number;
  previousKitSha256A: string;
  previousKitSha256B: string;
}

export type ChainConflict = LeafReuseAttempt | SameCoordinateFork | RotationConflict;

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

function emptyState(): AdminState {
  return {
    ceremony: null,
    groups: [],
    recipients: [],
    rotations: [],
    coupons: [],
    enrolments: [],
    vaultLinks: [],
  };
}

function lkvPathFor(cfg: CeremonyConfig): string {
  return pathResolve(cfg.yamlDir, ".tn", "admin", "admin.lkv.json");
}

// ---------------------------------------------------------------------
// AdminStateCache
// ---------------------------------------------------------------------

export class AdminStateCache {
  private readonly client: TNClient;
  private readonly cfg: CeremonyConfig;
  private readonly lkvPath: string;

  private _state: AdminState = emptyState();
  private _clock = new Map<string, number>(); // "did\u0000eventType" → seq
  private _headRowHash: string | null = null;
  private _atOffset = 0;
  private _headConflicts: ChainConflict[] = [];

  // Auxiliary tracking for convergence checks.
  private _coordToRowHash = new Map<string, string>(); // "did\u0000et\u0000seq" → row_hash
  private _revokedLeaves = new Map<string, string | null>(); // "group\u0000leaf" → revoked-at row_hash
  private _rotationsSeen = new Map<string, string>(); // "group\u0000gen" → previous_kit_sha256
  private _rowHashes = new Set<string>();

  constructor(client: TNClient) {
    this.client = client;
    this.cfg = client.runtime.config;
    this.lkvPath = lkvPathFor(this.cfg);
    this._loadFromDisk();
  }

  // ---- Public surface ------------------------------------------------

  get atOffset(): number {
    this._refreshIfLogAdvanced();
    return this._atOffset;
  }

  get headRowHash(): string | null {
    this._refreshIfLogAdvanced();
    return this._headRowHash;
  }

  get headConflicts(): ChainConflict[] {
    this._refreshIfLogAdvanced();
    return [...this._headConflicts];
  }

  /** Vector clock as `{did → {event_type → max_seq}}`. */
  clock(): Record<string, Record<string, number>> {
    this._refreshIfLogAdvanced();
    const out: Record<string, Record<string, number>> = {};
    for (const [k, seq] of this._clock) {
      const [did, et] = k.split("\u0000");
      if (!did || !et) continue;
      const slot = out[did] ?? {};
      slot[et] = seq;
      out[did] = slot;
    }
    return out;
  }

  state(): AdminState {
    this._refreshIfLogAdvanced();
    return this._state;
  }

  recipients(group: string, opts?: { includeRevoked?: boolean }): RecipientEntry[] {
    this._refreshIfLogAdvanced();
    const includeRevoked = opts?.includeRevoked ?? false;
    const out: RecipientEntry[] = [];
    for (const rec of this._state.recipients) {
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
    return this._headConflicts.some((c) => c.type === "same_coordinate_fork");
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
    envs.sort((a, b) => {
      const ta = String(a["timestamp"] ?? "");
      const tb = String(b["timestamp"] ?? "");
      if (ta !== tb) return ta < tb ? -1 : 1;
      const sa = Number(a["sequence"] ?? 0);
      const sb = Number(b["sequence"] ?? 0);
      if (sa !== sb) return sa - sb;
      return String(a["row_hash"]).localeCompare(String(b["row_hash"]));
    });

    for (const env of envs) this._applyEnvelope(env);
    this._atOffset = this._rowHashes.size;
  }

  private _applyEnvelope(env: Record<string, unknown>): void {
    const rh = env["row_hash"];
    if (typeof rh !== "string") return;

    const did = env["did"];
    const et = env["event_type"];
    const seqRaw = env["sequence"];
    const seq = typeof seqRaw === "number" ? seqRaw : Number(seqRaw);

    // Same-coordinate fork detection — must run BEFORE dedupe.
    if (typeof did === "string" && typeof et === "string" && Number.isFinite(seq)) {
      const coordKey = `${did}\u0000${et}\u0000${seq}`;
      const existingRh = this._coordToRowHash.get(coordKey);
      if (existingRh === undefined) {
        this._coordToRowHash.set(coordKey, rh);
      } else if (existingRh !== rh) {
        const already = this._headConflicts.some(
          (c) =>
            c.type === "same_coordinate_fork" &&
            c.did === did &&
            c.eventType === et &&
            c.sequence === seq,
        );
        if (!already) {
          this._headConflicts.push({
            type: "same_coordinate_fork",
            did,
            eventType: et,
            sequence: seq,
            rowHashes: [existingRh, rh],
          });
        }
      }
    }

    if (this._rowHashes.has(rh)) return;
    this._rowHashes.add(rh);

    if (typeof did === "string" && typeof et === "string" && Number.isFinite(seq)) {
      const k = `${did}\u0000${et}`;
      const cur = this._clock.get(k) ?? 0;
      if (seq > cur) this._clock.set(k, seq);
    }

    this._headRowHash = rh;
    const ts = typeof env["timestamp"] === "string" ? (env["timestamp"] as string) : null;

    if (typeof et !== "string") return;

    if (et === "tn.ceremony.init") {
      const cer: AdminCeremonyState = {
        ceremonyId: String(env["ceremony_id"] ?? ""),
        cipher: String(env["cipher"] ?? ""),
        deviceDid: String(env["device_did"] ?? env["did"] ?? ""),
        createdAt: typeof env["created_at"] === "string" ? (env["created_at"] as string) : ts,
      };
      this._state.ceremony = cer;
      return;
    }

    if (et === "tn.group.added") {
      this._state.groups.push({
        group: String(env["group"] ?? ""),
        cipher: String(env["cipher"] ?? ""),
        publisherDid: String(env["publisher_did"] ?? ""),
        addedAt: typeof env["added_at"] === "string" ? (env["added_at"] as string) : (ts ?? ""),
      });
      return;
    }

    if (et === "tn.recipient.added") {
      const group = env["group"];
      const leaf = env["leaf_index"];
      if (typeof group !== "string" || typeof leaf !== "number") return;
      const key = `${group}\u0000${leaf}`;
      if (this._revokedLeaves.has(key)) {
        this._headConflicts.push({
          type: "leaf_reuse_attempt",
          group,
          leafIndex: leaf,
          attemptedRowHash: rh,
          originallyRevokedAtRowHash: this._revokedLeaves.get(key) ?? null,
        });
        return;
      }
      // Already-active double-add: also a leaf reuse — first add wins.
      for (const rec of this._state.recipients) {
        if (rec.group === group && rec.leafIndex === leaf) {
          this._headConflicts.push({
            type: "leaf_reuse_attempt",
            group,
            leafIndex: leaf,
            attemptedRowHash: rh,
            originallyRevokedAtRowHash: null,
          });
          return;
        }
      }
      this._state.recipients.push({
        group,
        leafIndex: leaf,
        recipientDid:
          env["recipient_did"] === null || env["recipient_did"] === undefined
            ? null
            : String(env["recipient_did"]),
        kitSha256: String(env["kit_sha256"] ?? ""),
        mintedAt: ts,
        activeStatus: "active",
        revokedAt: null,
        retiredAt: null,
      } satisfies AdminRecipientState);
      return;
    }

    if (et === "tn.recipient.revoked") {
      const group = env["group"];
      const leaf = env["leaf_index"];
      if (typeof group !== "string" || typeof leaf !== "number") return;
      const key = `${group}\u0000${leaf}`;
      this._revokedLeaves.set(key, rh);
      for (const rec of this._state.recipients) {
        if (rec.group === group && rec.leafIndex === leaf && rec.activeStatus === "active") {
          rec.activeStatus = "revoked";
          rec.revokedAt = ts;
        }
      }
      return;
    }

    if (et === "tn.rotation.completed") {
      const group = env["group"];
      const genRaw = env["generation"];
      const gen = typeof genRaw === "number" ? genRaw : Number(genRaw);
      const prevKit = env["previous_kit_sha256"];
      if (typeof group === "string" && Number.isFinite(gen)) {
        const k = `${group}\u0000${gen}`;
        if (this._rotationsSeen.has(k)) {
          if (typeof prevKit === "string" && this._rotationsSeen.get(k) !== prevKit) {
            this._headConflicts.push({
              type: "rotation_conflict",
              group,
              generation: gen,
              previousKitSha256A: this._rotationsSeen.get(k)!,
              previousKitSha256B: prevKit,
            });
          }
        } else if (typeof prevKit === "string") {
          this._rotationsSeen.set(k, prevKit);
        }
      }
      this._state.rotations.push({
        group: String(group ?? ""),
        cipher: String(env["cipher"] ?? ""),
        generation: Number.isFinite(gen) ? gen : 0,
        previousKitSha256: typeof prevKit === "string" ? prevKit : "",
        rotatedAt: typeof env["rotated_at"] === "string" ? (env["rotated_at"] as string) : (ts ?? ""),
      });
      // Retire any currently-active recipients in this group.
      if (typeof group === "string") {
        for (const rec of this._state.recipients) {
          if (rec.group === group && rec.activeStatus === "active") {
            rec.activeStatus = "retired";
            rec.retiredAt = ts;
          }
        }
      }
      return;
    }

    if (et === "tn.coupon.issued") {
      this._state.coupons.push({
        group: String(env["group"] ?? ""),
        slot: Number(env["slot"] ?? 0),
        toDid: String(env["to_did"] ?? ""),
        issuedTo: String(env["issued_to"] ?? ""),
        issuedAt: ts,
      });
      return;
    }

    if (et === "tn.enrolment.compiled") {
      this._state.enrolments.push({
        group: String(env["group"] ?? ""),
        peerDid: String(env["peer_did"] ?? ""),
        packageSha256: String(env["package_sha256"] ?? ""),
        status: "offered",
        compiledAt:
          typeof env["compiled_at"] === "string" ? (env["compiled_at"] as string) : ts,
        absorbedAt: null,
      } satisfies AdminEnrolmentState);
      return;
    }

    if (et === "tn.enrolment.absorbed") {
      const fromDid = env["from_did"];
      const group = env["group"];
      for (const enr of this._state.enrolments) {
        if (enr.group === group && enr.peerDid === fromDid) {
          enr.status = "absorbed";
          enr.absorbedAt =
            typeof env["absorbed_at"] === "string" ? (env["absorbed_at"] as string) : ts;
          return;
        }
      }
      this._state.enrolments.push({
        group: String(group ?? ""),
        peerDid: String(fromDid ?? ""),
        packageSha256: String(env["package_sha256"] ?? ""),
        status: "absorbed",
        compiledAt: null,
        absorbedAt:
          typeof env["absorbed_at"] === "string" ? (env["absorbed_at"] as string) : ts,
      });
      return;
    }

    if (et === "tn.vault.linked") {
      const vd = env["vault_did"];
      if (typeof vd !== "string") return;
      this._state.vaultLinks = this._state.vaultLinks.filter((l) => l.vaultDid !== vd);
      this._state.vaultLinks.push({
        vaultDid: vd,
        projectId: String(env["project_id"] ?? ""),
        linkedAt: typeof env["linked_at"] === "string" ? (env["linked_at"] as string) : (ts ?? ""),
        unlinkedAt: null,
      } satisfies AdminVaultLinkState);
      return;
    }

    if (et === "tn.vault.unlinked") {
      const vd = env["vault_did"];
      if (typeof vd !== "string") return;
      for (const link of this._state.vaultLinks) {
        if (link.vaultDid === vd) {
          link.unlinkedAt =
            typeof env["unlinked_at"] === "string"
              ? (env["unlinked_at"] as string)
              : ts;
        }
      }
      return;
    }
  }

  // ---- Persistence ---------------------------------------------------

  private _saveToDisk(): void {
    const dir = dirname(this.lkvPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const clockOut: Record<string, Record<string, number>> = {};
    for (const [k, seq] of this._clock) {
      const [did, et] = k.split("\u0000");
      if (!did || !et) continue;
      const slot = clockOut[did] ?? {};
      slot[et] = seq;
      clockOut[did] = slot;
    }
    const doc = {
      version: LKV_VERSION,
      ceremony_id: this.cfg.ceremonyId,
      clock: clockOut,
      head_row_hash: this._headRowHash,
      at_offset: this._atOffset,
      state: this._state,
      head_conflicts: this._headConflicts,
      _row_hashes: [...this._rowHashes].sort(),
      _revoked_leaves: [...this._revokedLeaves.entries()].map(([k, rh]) => {
        const [group, leafStr] = k.split("\u0000");
        return { group, leaf_index: Number(leafStr), row_hash: rh };
      }),
      _rotations_seen: [...this._rotationsSeen.entries()].map(([k, prev]) => {
        const [group, genStr] = k.split("\u0000");
        return { group, generation: Number(genStr), previous_kit_sha256: prev };
      }),
      _coord_to_row_hash: [...this._coordToRowHash.entries()].map(([k, v]) => {
        const [d, et, seqStr] = k.split("\u0000");
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

    const state = doc["state"];
    if (state && typeof state === "object" && !Array.isArray(state)) {
      const base = emptyState();
      const s = state as Record<string, unknown>;
      if ("ceremony" in s) base.ceremony = (s["ceremony"] as AdminCeremonyState | null) ?? null;
      if (Array.isArray(s["groups"])) base.groups = s["groups"] as AdminState["groups"];
      if (Array.isArray(s["recipients"]))
        base.recipients = s["recipients"] as AdminState["recipients"];
      if (Array.isArray(s["rotations"]))
        base.rotations = s["rotations"] as AdminState["rotations"];
      if (Array.isArray(s["coupons"])) base.coupons = s["coupons"] as AdminState["coupons"];
      if (Array.isArray(s["enrolments"]))
        base.enrolments = s["enrolments"] as AdminState["enrolments"];
      if (Array.isArray(s["vaultLinks"]))
        base.vaultLinks = s["vaultLinks"] as AdminState["vaultLinks"];
      this._state = base;
    }

    const clockDoc = doc["clock"];
    if (clockDoc && typeof clockDoc === "object" && !Array.isArray(clockDoc)) {
      for (const [did, etMap] of Object.entries(clockDoc as Record<string, unknown>)) {
        if (!etMap || typeof etMap !== "object" || Array.isArray(etMap)) continue;
        for (const [et, seq] of Object.entries(etMap as Record<string, unknown>)) {
          const n = typeof seq === "number" ? seq : Number(seq);
          if (Number.isFinite(n)) this._clock.set(`${did}\u0000${et}`, Math.trunc(n));
        }
      }
    }

    this._headRowHash =
      typeof doc["head_row_hash"] === "string" ? (doc["head_row_hash"] as string) : null;
    const offRaw = doc["at_offset"];
    this._atOffset = typeof offRaw === "number" ? offRaw : Number(offRaw) || 0;

    const conflicts = doc["head_conflicts"];
    if (Array.isArray(conflicts)) {
      this._headConflicts = conflicts.filter(
        (c): c is ChainConflict =>
          !!c &&
          typeof c === "object" &&
          (c as { type?: unknown }).type !== undefined,
      );
    }

    const rh = doc["_row_hashes"];
    if (Array.isArray(rh)) this._rowHashes = new Set(rh.map(String));
    const revoked = doc["_revoked_leaves"];
    if (Array.isArray(revoked)) {
      for (const e of revoked) {
        if (e && typeof e === "object") {
          const r = e as Record<string, unknown>;
          if (typeof r["group"] === "string" && typeof r["leaf_index"] === "number") {
            this._revokedLeaves.set(
              `${r["group"]}\u0000${r["leaf_index"]}`,
              typeof r["row_hash"] === "string" ? (r["row_hash"] as string) : null,
            );
          }
        }
      }
    }
    const rots = doc["_rotations_seen"];
    if (Array.isArray(rots)) {
      for (const e of rots) {
        if (e && typeof e === "object") {
          const r = e as Record<string, unknown>;
          if (typeof r["group"] === "string" && typeof r["generation"] === "number") {
            this._rotationsSeen.set(
              `${r["group"]}\u0000${r["generation"]}`,
              String(r["previous_kit_sha256"] ?? ""),
            );
          }
        }
      }
    }
    const coords = doc["_coord_to_row_hash"];
    if (Array.isArray(coords)) {
      for (const e of coords) {
        if (e && typeof e === "object") {
          const r = e as Record<string, unknown>;
          if (
            typeof r["did"] === "string" &&
            typeof r["event_type"] === "string" &&
            typeof r["sequence"] === "number" &&
            typeof r["row_hash"] === "string"
          ) {
            this._coordToRowHash.set(
              `${r["did"]}\u0000${r["event_type"]}\u0000${r["sequence"]}`,
              r["row_hash"] as string,
            );
          }
        }
      }
    }
  }
}

export { lkvPathFor };
