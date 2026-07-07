// tn.scopeTo(did).spawn() — per-DID scoped capability handles.
//
// A ScopedTn is a read-only view derived from a seeded Tn. It opens ONLY the
// groups where one of the scoped DIDs is a listed recipient, and leaves every
// other group sealed. Reads operate on a handed-in tn stream (bytes or
// string), so a scoped handle needs no filesystem of its own — a Worker or
// governance mesh hands it the message it received, and it surfaces exactly
// what those DIDs are entitled to.
//
// The seeded Tn is the project publisher and physically holds kits for every
// group, so the scoping is a capability FILTER (driven by each group's
// recipient list in the config), not a missing-key accident. That is the
// honest custodial property: least privilege per request, even though the
// holder could open more.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";

import { Entry } from "./Entry.js";
import { aadBytesFor, decryptGroup, type GroupKits } from "./core/decrypt.js";
import { hibeCandidateKeys, loadHibeGroup } from "./runtime/hibe_group.js";
import type { CeremonyConfig } from "./runtime/config.js";

/**
 * The slice of ceremony config a scoped reader needs.
 *
 * `groups` is the group→recipient map: it answers "which groups is a given
 * DID a recipient of," and that membership IS the capability. `keystorePath`
 * is where the btn kits live; the scoped reader loads only the kits for the
 * groups in its allowed set.
 *
 * @remarks A deliberately narrow projection of {@link CeremonyConfig}, so a
 * scoped reader can be built from anything that can produce these two fields,
 * not only a full live `Tn`.
 */
export interface ScopeSource {
  /** The ceremony's groups, each carrying its `recipients` list. */
  groups: CeremonyConfig["groups"];
  /** Directory holding the `<group>.btn.mykit` files. */
  keystorePath: string;
}

/**
 * Resolve the set of group names that ANY of `dids` is a declared recipient of.
 *
 * This is the whole authorization decision, and it is data-driven: it reads
 * each group's `recipients` list from the config. It never looks at keys or
 * ciphertext — entitlement is a property of the ceremony declaration, not of
 * who happens to hold a kit.
 *
 * @param groups - the ceremony's group→recipient map.
 * @param dids - the DIDs being scoped to (a user, an agt, a mesh, ...).
 * @returns the names of the groups those DIDs may open.
 */
export function groupsForDids(
  groups: CeremonyConfig["groups"],
  dids: ReadonlySet<string>,
): Set<string> {
  const allowed = new Set<string>();
  for (const [gname, gcfg] of groups) {
    if (gcfg.recipients.some((r) => dids.has(r.did))) allowed.add(gname);
  }
  return allowed;
}

/**
 * A read-only capability handle scoped to a fixed set of group names.
 *
 * Returned by {@link ScopeBuilder.spawn}. A `ScopedTn` opens ONLY the groups
 * in its allowed set and leaves every other group sealed. It is the read-side
 * enforcement of TN's recipient model: even though the seeded `Tn` it was
 * derived from holds the kits for every group, this handle surfaces only what
 * its DIDs are entitled to.
 *
 * @remarks
 * - **Bytes-in.** {@link read} takes the stream content, not a file path, so a
 *   handle works with no filesystem of its own (e.g. inside a Worker handed a
 *   message off the wire).
 * - **Honest custodial ceiling.** The scoping is a *filter* over the config's
 *   recipient lists, not a missing-key accident. The holder could open more;
 *   it chooses not to. Hard isolation (an agt that physically lacks the other
 *   kits) is a deployment concern layered on top of this.
 */
export class ScopedTn {
  /** Per-group kit cache, so re-reading a group does not re-hit disk. */
  private readonly _kitCache = new Map<string, GroupKits | null>();

  /**
   * @param _keystorePath - where the `<group>.btn.mykit` files live.
   * @param _allowed - the group names this handle may open, already resolved
   *   from the scoped DIDs by {@link ScopeBuilder.spawn}.
   */
  constructor(
    private readonly _keystorePath: string,
    private readonly _allowed: Set<string>,
  ) {}

  /** The group names this handle is allowed to open, sorted. */
  get groups(): string[] {
    return [...this._allowed].sort();
  }

  /**
   * Load (and memoize) the decrypt kits for one group — the btn self-kit
   * when `<group>.btn.mykit` exists, else the hibe reader material when
   * `<group>.hibe.sk` exists.
   *
   * @returns the kit set, or `null` when no key file is present — in which
   * case the group simply stays sealed (it surfaces in `entry.hidden_groups`).
   */
  private _kits(group: string): GroupKits | null {
    const cached = this._kitCache.get(group);
    if (cached !== undefined) return cached;
    let kits: GroupKits | null = null;
    try {
      const kit = new Uint8Array(readFileSync(join(this._keystorePath, `${group}.btn.mykit`)));
      kits = { cipher: "btn", kits: [kit] };
    } catch {
      // No btn kit on disk — try the hibe material next.
    }
    if (kits === null) {
      try {
        const mat = loadHibeGroup(this._keystorePath, group);
        if (mat !== null) {
          kits = { cipher: "hibe", kits: hibeCandidateKeys(mat), mpk: mat.mpk };
        }
      } catch {
        // No usable hibe material — leave null; the group stays sealed.
      }
    }
    this._kitCache.set(group, kits);
    return kits;
  }

  /**
   * Open a handed-in tn stream and yield one typed {@link Entry} per record.
   *
   * For each line, only the groups in the allowed set are decrypted; every
   * other group block present in the envelope lands in `entry.hidden_groups`,
   * so a caller can see that *something* was there without reading it.
   *
   * @param message - the ndjson stream content (a `string`, or `Uint8Array`
   *   bytes received off the wire). Not a file path.
   * @yields one {@link Entry} per non-empty, valid-JSON line.
   *
   * @example
   * ```ts
   * for (const entry of tn.scopeTo(userDid).spawn().read(message)) {
   *   console.log(entry.event_type, entry.fields, entry.hidden_groups);
   * }
   * ```
   */
  *read(message: string | Uint8Array): IterableIterator<Entry> {
    const text = typeof message === "string" ? message : Buffer.from(message).toString("utf8");
    for (const rawLine of text.split(/\r?\n/)) {
      const s = rawLine.trim();
      if (!s) continue;
      let env: Record<string, unknown>;
      try {
        env = JSON.parse(s) as Record<string, unknown>;
      } catch {
        continue;
      }
      const plaintext: Record<string, unknown> = {};
      for (const group of this._allowed) {
        const block = env[group];
        if (!block || typeof block !== "object" || Array.isArray(block)) continue;
        const ct = (block as Record<string, unknown>)["ciphertext"];
        if (typeof ct !== "string") continue;
        const kits = this._kits(group);
        if (!kits) continue;
        plaintext[group] = decryptGroup(
          { ct: new Uint8Array(Buffer.from(ct, "base64")), aad: aadBytesFor(env, group) },
          kits,
        );
      }
      yield Entry.fromRaw({ envelope: env, plaintext });
    }
  }
}

/**
 * Builder returned by `tn.scopeTo(...)`.
 *
 * Collects the DIDs to scope to; {@link spawn} resolves them against the
 * config and launches an independent, read-only {@link ScopedTn}. Splitting
 * "which DIDs" (here) from "go" ({@link spawn}) lets a caller hold a
 * pre-configured scope and spawn many readers from it.
 */
export class ScopeBuilder {
  private readonly _dids: Set<string>;

  /**
   * @param _source - the group map + keystore the spawned reader will use.
   * @param dids - one or more DIDs to scope to; their capabilities union.
   */
  constructor(
    private readonly _source: ScopeSource,
    dids: Iterable<string>,
  ) {
    this._dids = new Set(dids);
  }

  /**
   * Resolve the allowed group set (via {@link groupsForDids}) and return a
   * fresh {@link ScopedTn} bound to it.
   */
  spawn(): ScopedTn {
    const allowed = groupsForDids(this._source.groups, this._dids);
    return new ScopedTn(this._source.keystorePath, allowed);
  }
}
