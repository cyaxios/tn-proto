// Node-only runtime: loads a yaml + keystore from disk, seeds chain
// state from any existing log, and exposes emit() + read() that match
// the Python tn.logger flow byte-for-byte (modulo the random CEK/nonce
// inside each btn ciphertext).
//
// Only btn ceremonies are supported. A ceremony whose groups use jwe or
// bgw will throw on emit/read, pointing the caller at the Python path.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { Buffer } from "node:buffer";
import { createHash, randomBytes, randomUUID } from "node:crypto";

import { DeviceKey } from "../core/signing.js";

import { loadPolicyFile, type PolicyDocument } from "../agents_policy.js";
import { BtnPublisher, btnKitLeaf } from "../raw.js";
import { decryptGroup, type GroupKits } from "../core/decrypt.js";
import type { TNHandler } from "../handlers/index.js";

function readKitLeaf(kitBytes: Uint8Array): bigint {
  return btnKitLeaf(kitBytes);
}
import { canonicalize } from "../core/canonical.js";
import { ZERO_HASH, rowHash } from "../core/chain.js";
import { buildEnvelopeLine } from "../core/envelope.js";
import { deriveGroupKey, indexTokenFor } from "../core/indexing.js";
import { signatureB64, signatureFromB64, verify } from "../core/signing.js";
import { asDid, asRowHash, asSignatureB64, type RowHash } from "../core/types.js";
import { loadConfig, type CeremonyConfig, type GroupConfig } from "./config.js";
import { loadKeystore, type LoadedKeystore } from "./keystore.js";
import { scanAttestedEventRecords, yamlRecipientDids } from "./reconcile.js";

interface ChainSlot {
  seq: number;
  prevHash: RowHash;
}

/**
 * One decoded log entry — mirrors Python tn.reader._read() output exactly.
 *
 *   envelope  — the raw on-disk JSON object
 *   plaintext — per-group decrypted fields: { group_name: { field: value } }
 *               (matches Python shape; groups we cannot decrypt get
 *               { $no_read_key: true } or { $decrypt_error: true })
 *   valid     — integrity checks:
 *               signature — Ed25519 sig over row_hash verified against DID
 *               rowHash   — recomputed row_hash matches envelope
 *               chain     — prev_hash of this entry matches last row_hash seen
 */
import type { ReadEntry } from "../core/read_shape.js";
export type { ReadEntry };

// Envelope fields that are NOT public fields and NOT group payloads.
const _ENVELOPE_RESERVED = new Set([
  "did",
  "timestamp",
  "event_id",
  "event_type",
  "level",
  "prev_hash",
  "row_hash",
  "signature",
  "sequence",
]);

export interface EmitReceipt {
  eventId: string;
  rowHash: RowHash;
  sequence: number;
}

// ---------------------------------------------------------------------------
// Session-level signing override.
// ---------------------------------------------------------------------------
// `null` means "fall through to ceremony.sign in yaml" (Python-style default).
// `true` / `false` overrides every emit until reset via `setSigning(null)`.
// Per-call overrides on `emitOverrideSign` / `emitWithOverrideSign` win over
// this. Mirrors `tn._sign_override` and `tn.set_signing(...)` in Python's
// `python/tn/__init__.py`.
let _sessionSignOverride: boolean | null = null;

/** Session-level signing override. See doc on TNClient.setSigning. */
export function setSigning(enabled: boolean | null): void {
  _sessionSignOverride = enabled;
}

/** Read the active session-level signing override (test/debug helper). */
export function getSessionSignOverride(): boolean | null {
  return _sessionSignOverride;
}

/**
 * Load and run a ceremony from disk.
 *
 * Construction reads the yaml + keystore, opens the log, and seeds
 * chain state from any existing entries. All subsequent emit()/read()
 * calls are stateful.
 */
export class NodeRuntime {
  readonly config: CeremonyConfig;
  readonly keystore: LoadedKeystore;
  private chain = new Map<string, ChainSlot>();
  private publishers = new Map<string, BtnPublisher>();
  private handlers: TNHandler[] = [];
  /** Cached `tn.agents` policy doc for this ceremony. `null` means "no
   * `.tn/config/agents.md` present" — splice path no-ops. */
  agentPolicy: PolicyDocument | null = null;

  addHandler(h: TNHandler): void {
    this.handlers.push(h);
  }

  private constructor(config: CeremonyConfig, keystore: LoadedKeystore) {
    this.config = config;
    this.keystore = keystore;
    for (const [name, g] of keystore.groups) {
      const gcfg = config.groups.get(name);
      if (gcfg && gcfg.cipher !== "btn") continue;
      this.publishers.set(name, BtnPublisher.fromBytes(g.stateBytes));
    }
    this.seedChainFromLog();
    // Load `.tn/config/agents.md` (if present). Errors propagate so a
    // malformed policy fails init — caller fixes or removes the file.
    this.agentPolicy = loadPolicyFile(this.config.yamlDir);
  }

  /**
   * Load or auto-create the ceremony at `yamlPath`.
   *
   * If the yaml doesn't exist, generate a fresh btn ceremony (Ed25519
   * device key, btn publisher + self-kit, index master) and write
   * everything to disk. Mirror of Python's tn.init / create_fresh,
   * including the clobber guard: if the yaml is missing but
   * .tn/keys/local.private already exists, we refuse rather than silently
   * orphaning every prior log entry.
   */
  static init(yamlPath: string): NodeRuntime {
    if (!existsSync(yamlPath)) {
      createFreshCeremony(yamlPath);
    }
    const config = loadConfig(yamlPath);
    for (const [name, g] of config.groups) {
      if (g.cipher !== "btn") {
        throw new Error(
          `group ${name} uses cipher ${g.cipher}; NodeRuntime supports btn only. Run this ceremony from Python.`,
        );
      }
    }
    const keystore = loadKeystore(config.keystorePath);
    if (keystore.device.did !== config.me.did) {
      throw new Error(
        `keystore did (${keystore.device.did}) does not match yaml me.did (${config.me.did})`,
      );
    }
    const logDir = dirname(config.logPath);
    if (!existsSync(logDir)) mkdirSync(logDir, { recursive: true });
    // Session-start rotation. When the log file from a prior process
    // exists with content, roll it to `<name>.1` (shifting any older
    // numbered backups forward up to `backup_count`) so this session
    // writes a fresh file. Matches stdlib `logging` mental model and
    // the Python `FileRotatingHandler` / Rust `Runtime::init`
    // behavior. Honors yaml `handlers[*].rotate_on_init: false` to
    // opt out (e.g. for tests that need cross-init continuation).
    rotateLogOnSessionStart(config.logPath, config.handlers);
    const rt = new NodeRuntime(config, keystore);
    // Reconcile yaml-declared recipients with attested events. Any
    // DID listed in the yaml but with no matching
    // tn.recipient.added / tn.recipient.revoked event gets a freshly
    // minted kit, an outbox file, and an attested event. Matches
    // Python's _emit_missing_recipients behavior so init is
    // idempotent and yaml-drift-aware across both runtimes.
    try {
      rt.reconcileRecipients();
    } catch {
      // Best-effort. Any failure leaves state as-is; subsequent
      // inits will retry.
    }
    return rt;
  }

  get did(): string {
    return this.keystore.device.did;
  }

  /** Append one log entry. Matches Python's tn.logger.emit flow. */
  emit(level: string, eventType: string, fields: Record<string, unknown>): EmitReceipt {
    return this.emitInternal(level, eventType, fields, undefined, undefined, undefined);
  }

  /**
   * `emit` with explicit timestamp / event_id (deterministic tests, replay).
   * Matches Python's `_timestamp` / `_event_id` kwargs and Rust's
   * `Runtime::emit_with`. Either or both may be omitted to use defaults.
   */
  emitWith(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    opts: { timestamp?: string; eventId?: string } = {},
  ): EmitReceipt {
    return this.emitInternal(level, eventType, fields, opts.timestamp, opts.eventId, undefined);
  }

  /**
   * `emit` with a per-call signing override. `null` falls back to the
   * session/yaml default. Matches Python's `_sign=` kwarg + the
   * `sign` argument on Rust's `Runtime::emit_override_sign`.
   */
  emitOverrideSign(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    sign: boolean | null,
  ): EmitReceipt {
    return this.emitInternal(level, eventType, fields, undefined, undefined, sign);
  }

  /** Full-control emit: timestamp + event_id + sign override. */
  emitWithOverrideSign(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    opts: { timestamp?: string; eventId?: string; sign?: boolean | null } = {},
  ): EmitReceipt {
    return this.emitInternal(
      level,
      eventType,
      fields,
      opts.timestamp,
      opts.eventId,
      opts.sign ?? null,
    );
  }

  private emitInternal(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    timestampOverride: string | undefined,
    eventIdOverride: string | undefined,
    signOverride: boolean | null | undefined,
  ): EmitReceipt {
    validateEventType(eventType);

    // 0. tn.agents policy splice (per spec §2.6).
    //    Looks up `eventType` in the cached policy doc; if a template exists,
    //    fills the six tn.agents fields via "set if absent" so per-emit
    //    overrides still win. The yaml-declared `tn.agents` group routes
    //    those six field names automatically.
    fields = this._spliceAgentPolicy(eventType, fields);

    // 1. split public vs per-group.
    //
    // Multi-group routing: a field declared under N groups in yaml
    // (`groups[<g>].fields: [...]`) is encrypted into all N groups'
    // payloads. `fieldToGroups` is built and sorted alphabetically at
    // load time so envelope encoding stays canonical.
    const publicOut: Record<string, unknown> = {};
    const perGroup = new Map<string, Record<string, unknown>>();
    for (const [k, v] of Object.entries(fields)) {
      if (this.config.publicFields.has(k)) {
        publicOut[k] = v;
        continue;
      }
      let gnames = this.config.fieldToGroups.get(k);
      if (!gnames || gnames.length === 0) {
        // Field has no declared route. Fall back to the default group
        // when one exists; otherwise raise — silent fall-through is
        // exactly what multi-group routing was meant to fix.
        if (this.config.groups.has("default")) {
          gnames = ["default"];
        } else {
          throw new Error(
            `field ${JSON.stringify(k)} has no group route and is not in ` +
              "public_fields. Add it to `groups[<g>].fields` in tn.yaml, " +
              "list it under public_fields, or define a `default` group " +
              "to absorb unknowns.",
          );
        }
      }
      for (const gname of gnames) {
        if (!this.config.groups.has(gname)) {
          throw new Error(
            `field ${JSON.stringify(k)} routed to unknown group ` +
              `${JSON.stringify(gname)} ` +
              `(known groups: ${JSON.stringify([...this.config.groups.keys()].sort())})`,
          );
        }
        if (!perGroup.has(gname)) perGroup.set(gname, {});
        perGroup.get(gname)![k] = v;
      }
    }

    // 2. per-group index tokens + encrypt.
    // On-disk shape uses snake_case (`field_hashes`) so envelope JSON is
    // byte-identical with Python and Rust. In-memory variable name stays
    // `fieldHashes` (TS convention).
    const groupPayloadsForEnvelope: Record<
      string,
      { ciphertext: string; field_hashes: Record<string, string> }
    > = {};
    const groupHashInputs: Record<
      string,
      { ciphertext: Uint8Array; fieldHashes: Record<string, string> }
    > = {};
    for (const [gname, plainFields] of perGroup) {
      const publisher = this.publishers.get(gname);
      if (!publisher) continue; // not a publisher for this group: skip silently
      const gk = deriveGroupKey(this.keystore.indexMaster, this.config.ceremonyId, gname, 0);
      const fieldHashes: Record<string, string> = {};
      for (const [fname, fval] of Object.entries(plainFields)) {
        fieldHashes[fname] = indexTokenFor(gk, fname, fval);
      }
      const ptBytes = canonicalize(plainFields);
      const ctBytes = publisher.encrypt(ptBytes);
      groupPayloadsForEnvelope[gname] = {
        ciphertext: Buffer.from(ctBytes).toString("base64"),
        field_hashes: fieldHashes,
      };
      groupHashInputs[gname] = { ciphertext: ctBytes, fieldHashes };
    }

    // 3. chain advance.
    const slot = this.chain.get(eventType) ?? { seq: 0, prevHash: ZERO_HASH };
    slot.seq += 1;
    const seq = slot.seq;
    const prevHash = slot.prevHash;
    this.chain.set(eventType, slot);

    const timestamp = timestampOverride ?? isoNowMicro();
    const eventId = eventIdOverride ?? randomUUID();
    const levelNorm = level.toLowerCase();

    // 4. row_hash.
    const groupsForHash: Record<string, import("../core/types.js").GroupHashInput> = {};
    for (const [gname, g] of Object.entries(groupHashInputs)) {
      groupsForHash[gname] = {
        ciphertext: g.ciphertext,
        fieldHashes: g.fieldHashes,
      };
    }
    const rh = rowHash({
      did: asDid(this.did),
      timestamp,
      eventId,
      eventType,
      level: levelNorm,
      prevHash,
      publicFields: publicOut,
      groups: groupsForHash,
    });

    // 5. sign. Resolve precedence: per-call override > session override > yaml.
    //    Match Python's _resolve_sign() semantics in tn/__init__.py:411.
    const resolvedSign =
      signOverride !== null && signOverride !== undefined
        ? signOverride
        : (_sessionSignOverride ?? this.config.sign);
    const sigB64 = resolvedSign
      ? signatureB64(this.keystore.device.sign(new Uint8Array(Buffer.from(rh, "utf8"))))
      : ("" as import("../core/types.js").SignatureB64);

    // 6. build + append to primary log file.
    const line = buildEnvelopeLine({
      did: asDid(this.did),
      timestamp,
      eventId,
      eventType,
      level: levelNorm,
      sequence: seq,
      prevHash,
      rowHash: rh,
      signatureB64: sigB64,
      publicFields: publicOut,
      groupPayloads: groupPayloadsForEnvelope,
    });
    appendFileSync(this.config.logPath, line);

    // 7. fan out to registered handlers.
    if (this.handlers.length > 0) {
      // Reconstruct a plain envelope dict for handlers (mirrors Python shape).
      const envelope: Record<string, unknown> = {
        did: this.did,
        timestamp,
        event_id: eventId,
        event_type: eventType,
        level: levelNorm,
        sequence: seq,
        prev_hash: prevHash,
        row_hash: rh,
        signature: sigB64,
        ...publicOut,
        ...groupPayloadsForEnvelope,
      };
      for (const h of this.handlers) {
        if (!h.accepts(envelope)) continue;
        try {
          h.emit(envelope, line);
        } catch {
          // A failing handler must not take down the caller.
        }
      }
    }

    // 8. commit chain slot.
    slot.prevHash = rh;
    this.chain.set(eventType, slot);

    return { eventId, rowHash: rh, sequence: seq };
  }

  /** Emit-side splice (spec §2.6).
   *
   * If `agentPolicy` has a template for `eventType`, populate the six
   * tn.agents fields via "set if absent" semantics so per-emit overrides
   * still win. Returns a new fields dict (never mutates the caller's).
   */
  private _spliceAgentPolicy(
    eventType: string,
    fields: Record<string, unknown>,
  ): Record<string, unknown> {
    const doc = this.agentPolicy;
    if (doc === null) return fields;
    const template = doc.templates.get(eventType);
    if (template === undefined) return fields;
    const out: Record<string, unknown> = { ...fields };
    if (!("instruction" in out)) out["instruction"] = template.instruction;
    if (!("use_for" in out)) out["use_for"] = template.use_for;
    if (!("do_not_use_for" in out)) out["do_not_use_for"] = template.do_not_use_for;
    if (!("consequences" in out)) out["consequences"] = template.consequences;
    if (!("on_violation_or_error" in out)) {
      out["on_violation_or_error"] = template.on_violation_or_error;
    }
    if (!("policy" in out)) {
      out["policy"] =
        `${template.path}#${template.eventType}@${template.version}#${template.contentHash}`;
    }
    return out;
  }

  /**
   * Mint a fresh btn reader kit for `group`, write it to `outKitPath`,
   * persist the updated publisher state, and attest the event.
   *
   * When `recipientDid` is given, the emitted `tn.recipient.added` event
   * includes it. Either way, the event carries leaf_index + kit_sha256
   * so readers replaying the log can rebuild the recipient map.
   */
  addRecipient(group: string, outKitPath: string, recipientDid?: string): number {
    const pub = this.publishers.get(group);
    if (!pub) {
      throw new Error(`addRecipient: group ${group} is not a btn publisher in this runtime`);
    }
    const kitBytes = pub.mint();
    const actualLeaf = Number(readKitLeaf(kitBytes));

    // Persist state back to disk so restarts see the updated tree.
    const statePath = join(this.config.keystorePath, `${group}.btn.state`);
    writeFileSync(statePath, Buffer.from(pub.toBytes()));

    // Write the kit to the caller-specified path.
    const outDir = dirname(outKitPath);
    if (outDir && !existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(outKitPath, Buffer.from(kitBytes));

    // Attest the event. kit_sha256 is a hex digest prefixed with "sha256:"
    // to match the Rust runtime's format.
    const digest = createHash("sha256").update(Buffer.from(kitBytes)).digest("hex");
    this.emit("info", "tn.recipient.added", {
      group,
      leaf_index: actualLeaf,
      recipient_did: recipientDid ?? null,
      kit_sha256: `sha256:${digest}`,
      cipher: "btn",
    });

    return actualLeaf;
  }

  /**
   * Revoke the reader at `leafIndex` in `group`. Persists the updated
   * publisher state. Emits `tn.recipient.revoked` so readers replaying
   * the log see the removal.
   */
  revokeRecipient(group: string, leafIndex: number, recipientDid?: string): void {
    const pub = this.publishers.get(group);
    if (!pub) {
      throw new Error(`revokeRecipient: group ${group} is not a btn publisher in this runtime`);
    }
    pub.revokeByLeaf(BigInt(leafIndex));
    const statePath = join(this.config.keystorePath, `${group}.btn.state`);
    writeFileSync(statePath, Buffer.from(pub.toBytes()));

    this.emit("info", "tn.recipient.revoked", {
      group,
      leaf_index: leafIndex,
      recipient_did: recipientDid ?? null,
    });
  }

  /** Flush and close all registered handlers. Call on process exit. */
  close(): void {
    for (const h of this.handlers) {
      try {
        h.close();
      } catch {
        /* best-effort */
      }
    }
  }

  /** Number of revoked readers in this group. */
  revokedCount(group: string): number {
    const pub = this.publishers.get(group);
    if (!pub) {
      throw new Error(`revokedCount: group ${group} is not a btn publisher in this runtime`);
    }
    return pub.revokedCount();
  }

  /**
   * For each recipient DID declared in the yaml but with no matching
   * tn.recipient.added or tn.recipient.revoked event in any log file,
   * mint a kit via BtnPublisher, write it to
   * `<yamlDir>/.tn/outbox/<safe-did>.<group>.mykit`, and emit
   * tn.recipient.added. Idempotent. Mirror of Python's
   * _emit_missing_recipients.
   *
   * Called automatically by `NodeRuntime.init`.
   */
  reconcileRecipients(): void {
    const attested = new Set<string>();
    const addKey = (g: string, did: string) => attested.add(`${g}|${did}`);
    for (const et of ["tn.recipient.added", "tn.recipient.revoked"]) {
      for (const env of scanAttestedEventRecords(this.config, et)) {
        const g = env.group as string | undefined;
        const did = env.recipient_did as string | undefined;
        if (g && did) addKey(g, did);
      }
    }

    const recipients = yamlRecipientDids(this.config);
    const selfDid = this.did;
    const outbox = join(this.config.yamlDir, ".tn", "outbox");

    for (const [groupName, gcfg] of this.config.groups) {
      if (gcfg.cipher !== "btn") continue;
      const pub = this.publishers.get(groupName);
      if (!pub) continue;
      const dids = recipients.get(groupName) ?? [];
      for (const did of dids) {
        if (did === selfDid) continue;
        if (attested.has(`${groupName}|${did}`)) continue;
        if (!existsSync(outbox)) mkdirSync(outbox, { recursive: true });
        const safe = did.replace(/[:/]/g, "_");
        const outPath = join(outbox, `${safe}.${groupName}.mykit`);
        try {
          this.addRecipient(groupName, outPath, did);
        } catch {
          // A single DID's mint failure shouldn't abort the rest of the loop.
          continue;
        }
      }
    }
  }

  /**
   * Iterate decoded entries. Mirrors Python tn.reader._read() exactly:
   *   - Verifies Ed25519 signature against the DID's public key
   *   - Recomputes row_hash and checks it matches the envelope
   *   - Checks prev_hash chain continuity per event_type
   *   - Decrypts each group we hold a kit for (per-group in plaintext)
   */
  *read(logPath?: string): Generator<ReadEntry, void, void> {
    const path = logPath ?? this.config.logPath;
    if (!existsSync(path)) return;
    const text = readFileSync(path, "utf8");
    const prevHashByType = new Map<string, RowHash>();

    let lineno = 0;
    for (const rawLine of text.split(/\r?\n/)) {
      lineno += 1;
      if (!rawLine) continue;
      let env: Record<string, unknown>;
      try {
        env = JSON.parse(rawLine) as Record<string, unknown>;
      } catch (e) {
        // Match Python reader.py: raise on invalid JSON so callers cannot
        // silently skip tampered or truncated lines.
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`${path}:${lineno}: invalid JSON: ${msg}`, { cause: e });
      }

      const eventType = String(env["event_type"] ?? "");
      const envPrevHash = String(env["prev_hash"] ?? ZERO_HASH);
      const envRowHash = String(env["row_hash"] ?? "");
      const envSig = String(env["signature"] ?? "");
      const envDid = String(env["did"] ?? "");
      const envTs = String(env["timestamp"] ?? "");
      const envEventId = String(env["event_id"] ?? "");
      const envLevel = String(env["level"] ?? "");

      // 1. Chain continuity check (per event_type, matches Python).
      const lastHash = prevHashByType.get(eventType);
      const chainOk = lastHash === undefined || envPrevHash === lastHash;

      // 2. Identify group payloads in the envelope.
      const groupRaw = new Map<string, { ct: Uint8Array; fieldHashes: Record<string, string> }>();
      for (const [k, v] of Object.entries(env)) {
        if (isGroupPayload(v)) {
          const ct = new Uint8Array(Buffer.from(v.ciphertext, "base64"));
          // Rust serialiser may write field_hashes (snake) or fieldHashes (camel).
          const fh =
            ((v as Record<string, unknown>)["field_hashes"] as
              | Record<string, string>
              | undefined) ??
            ((v as Record<string, unknown>)["fieldHashes"] as Record<string, string> | undefined) ??
            {};
          groupRaw.set(k, { ct, fieldHashes: fh });
        }
      }

      // 3. Public fields: in config.publicFields, not reserved, not a group key.
      const publicFields: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(env)) {
        if (!_ENVELOPE_RESERVED.has(k) && !groupRaw.has(k) && this.config.publicFields.has(k)) {
          publicFields[k] = v;
        }
      }

      // 4. Recompute row_hash (Python: compute_row_hash).
      const groupsForHash: Record<string, import("../core/types.js").GroupHashInput> = {};
      for (const [gname, g] of groupRaw) {
        groupsForHash[gname] = { ciphertext: g.ct, fieldHashes: g.fieldHashes };
      }
      let rowHashOk: boolean;
      try {
        const recomputed = rowHash({
          did: asDid(envDid),
          timestamp: envTs,
          eventId: envEventId,
          eventType,
          level: envLevel,
          prevHash: asRowHash(envPrevHash),
          publicFields,
          groups: groupsForHash,
        });
        rowHashOk = recomputed === envRowHash;
      } catch {
        rowHashOk = false;
      }

      // 5. Signature verification (Python: DeviceKey.verify).
      let sigOk: boolean;
      try {
        const sig = signatureFromB64(asSignatureB64(envSig));
        sigOk = verify(asDid(envDid), new Uint8Array(Buffer.from(envRowHash, "utf8")), sig);
      } catch {
        sigOk = false;
      }

      // 6. Decrypt each group we hold kits for (Python: gcfg.cipher.decrypt).
      const plaintext: Record<string, Record<string, unknown>> = {};
      for (const [gname, g] of groupRaw) {
        const gk = this.keystore.groups.get(gname);
        const gcfg = this.config.groups.get(gname);
        const cipherKind = (gcfg?.cipher ?? "btn") as "btn" | "jwe";
        const kits: GroupKits = { cipher: cipherKind, kits: gk?.kits ?? [] };
        plaintext[gname] = decryptGroup({ ct: g.ct }, kits) as Record<string, unknown>;
      }

      // 7. Advance chain state.
      prevHashByType.set(eventType, asRowHash(envRowHash));

      yield {
        envelope: env,
        plaintext,
        valid: { signature: sigOk, rowHash: rowHashOk, chain: chainOk },
      };
    }
  }

  /** Seed chain slots by scanning the log for the last row_hash per event_type. */
  private seedChainFromLog(): void {
    const path = this.config.logPath;
    if (!existsSync(path)) return;
    const text = readFileSync(path, "utf8");
    for (const rawLine of text.split(/\r?\n/)) {
      if (!rawLine) continue;
      try {
        const env = JSON.parse(rawLine) as Record<string, unknown>;
        const et = env.event_type as string | undefined;
        const seq = env.sequence as number | undefined;
        const rh = env.row_hash as string | undefined;
        if (!et || typeof seq !== "number" || typeof rh !== "string") continue;
        const prev = this.chain.get(et);
        if (!prev || seq > prev.seq) {
          this.chain.set(et, { seq, prevHash: asRowHash(rh) });
        }
      } catch {
        // skip malformed lines
      }
    }
  }
}

function isGroupPayload(
  v: unknown,
): v is { ciphertext: string; field_hashes?: Record<string, string> } {
  return (
    typeof v === "object" &&
    v !== null &&
    "ciphertext" in v &&
    typeof (v as Record<string, unknown>).ciphertext === "string"
  );
}

function validateEventType(et: string): void {
  if (!et) throw new Error("event_type must be non-empty");
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(et)) {
    throw new Error(`invalid event_type: ${et}`);
  }
}

function isoNowMicro(): string {
  const now = new Date();
  // Python emits "...Z" with microsecond precision via
  // isoformat(timespec='microseconds'). Node's Date only has ms, so we
  // pad. Timestamps are covered by the row_hash regardless of whether
  // the other side sees identical microseconds; what matters is that
  // the timestamp string parses and is UTC.
  const ms = now.toISOString(); // e.g. 2026-04-23T12:34:56.789Z
  return ms.replace(/\.(\d{3})Z$/, ".$1000Z");
}

export function groupForField(_cfg: CeremonyConfig, _fieldName: string): GroupConfig | undefined {
  return undefined; // reserved for future classifier integration
}

/**
 * Roll an existing non-empty log file to `<name>.1`, shifting any
 * existing numbered backups forward (`.1` → `.2`, ..., up to
 * `backupCount`). Mirrors stdlib Python `RotatingFileHandler.doRollover`
 * semantics and the Rust `rotate_log_on_session_start` helper. Called
 * once per `NodeRuntime.init` so each session writes a fresh file.
 *
 * Looks for the first `kind: file.rotating` entry in the yaml's
 * `handlers:` block to read `rotate_on_init` (default true) and
 * `backupCount` (default 5). Best-effort: filesystem errors are
 * swallowed so a rotation hiccup never blocks `init()`.
 */
function rotateLogOnSessionStart(
  logPath: string,
  handlers: Array<Record<string, unknown>>,
): void {
  // Default: rotate, keep 5 backups. Yaml's first file.rotating entry
  // can override either knob.
  let rotateOnInit = true;
  let backupCount = 5;
  for (const h of handlers) {
    const kind = h["kind"];
    if (kind !== "file.rotating" && kind !== "file") continue;
    if (typeof h["rotate_on_init"] === "boolean") rotateOnInit = h["rotate_on_init"];
    if (typeof h["backup_count"] === "number") backupCount = h["backup_count"];
    break;
  }
  if (!rotateOnInit) return;
  if (!existsSync(logPath)) return;
  let size: number;
  try {
    size = statSync(logPath).size;
  } catch {
    return;
  }
  if (size === 0) return;

  const maxN = Math.max(backupCount, 1);
  // Drop the oldest, then shift each `.N` → `.N+1`.
  try {
    rmSync(`${logPath}.${maxN}`, { force: true });
  } catch {
    // ignore
  }
  for (let n = maxN - 1; n >= 1; n -= 1) {
    const from = `${logPath}.${n}`;
    const to = `${logPath}.${n + 1}`;
    if (existsSync(from)) {
      try {
        renameSync(from, to);
      } catch {
        // best-effort; keep going
      }
    }
  }
  try {
    renameSync(logPath, `${logPath}.1`);
  } catch {
    // best-effort; the new session will append to the existing file
  }
}

/**
 * Create a fresh btn ceremony at `yamlPath`. Matches Python's
 * `create_fresh` in shape: generates device key, btn publisher,
 * self-kit, index master; writes tn.yaml + .tn/keys/*; refuses to
 * clobber an existing keystore.
 */
export function createFreshCeremony(yamlPath: string): void {
  const yamlDir = dirname(yamlPath);
  // Namespace .tn/ by yaml stem so two yamls in the same directory don't
  // collide on the same keys/logs/admin paths (FINDINGS #2 — Python parity).
  // Stem == basename without the trailing .yaml/.yml.
  const yamlBasename = yamlPath.split(/[\\/]/).pop() ?? "tn.yaml";
  const yamlStem = yamlBasename.replace(/\.ya?ml$/i, "");
  const keysDir = join(yamlDir, ".tn", yamlStem, "keys");
  const privatePath = join(keysDir, "local.private");

  if (existsSync(privatePath)) {
    throw new Error(
      `refusing to create a fresh ceremony at ${yamlPath}: ` +
        `${privatePath} already exists. Either delete the keystore to start ` +
        `over, or restore the yaml from the existing material ` +
        `(local.public holds the DID; match cipher + ceremony_id to what ` +
        `the log expects).`,
    );
  }

  mkdirSync(keysDir, { recursive: true });

  // Fresh Ed25519 device seed.
  const seed = new Uint8Array(randomBytes(32));
  const dk = DeviceKey.fromSeed(seed);

  // Fresh btn publisher + self-kit (default group).
  const btnSeed = new Uint8Array(randomBytes(32));
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  const stateBytes = pub.toBytes();
  pub.free();

  // Auto-inject reserved `tn.agents` group per the 2026-04-25 read-ergonomics
  // spec §2.3. Always cipher: btn so kits can be bundled via
  // `client.export({kind: "kit_bundle"})` for LLM-runtime onboarding.
  // Pure-logging users pay nothing: with no policy file, the group's
  // plaintext is empty for every emit (zero-length ciphertext).
  const agentsBtnSeed = new Uint8Array(randomBytes(32));
  const agentsPub = new BtnPublisher(agentsBtnSeed);
  const agentsSelfKit = agentsPub.mint();
  const agentsStateBytes = agentsPub.toBytes();
  agentsPub.free();

  // Index master for HMAC-based field-hash tokens.
  const indexMaster = new Uint8Array(randomBytes(32));

  // Short local ceremony ID: "local_" + first 8 hex of random bytes.
  const cid = "local_" + Buffer.from(randomBytes(4)).toString("hex");

  // Write keystore files.
  writeFileSync(privatePath, Buffer.from(seed));
  writeFileSync(join(keysDir, "local.public"), dk.did, "utf8");
  writeFileSync(join(keysDir, "index_master.key"), Buffer.from(indexMaster));
  writeFileSync(join(keysDir, "default.btn.state"), Buffer.from(stateBytes));
  writeFileSync(join(keysDir, "default.btn.mykit"), Buffer.from(selfKit));
  writeFileSync(join(keysDir, "tn.agents.btn.state"), Buffer.from(agentsStateBytes));
  writeFileSync(join(keysDir, "tn.agents.btn.mykit"), Buffer.from(agentsSelfKit));

  // Write the yaml. Public fields list covers both the business
  // defaults and the entire admin-catalog field set so catalog events
  // never land in a group ciphertext by accident. Mirrors the
  // Python DEFAULT_PUBLIC_FIELDS set.
  const yaml = `ceremony:
  id: ${cid}
  mode: local
  cipher: btn
  sign: true
  admin_log_location: ./.tn/${yamlStem}/admin/admin.ndjson
  log_level: debug
logs:
  path: ./.tn/${yamlStem}/logs/tn.ndjson
keystore:
  path: ./.tn/${yamlStem}/keys
handlers:
- kind: file.rotating
  name: main
  path: ./.tn/${yamlStem}/logs/tn.ndjson
  max_bytes: 5242880
  backup_count: 5
  rotate_on_init: true
- kind: stdout
me:
  did: ${dk.did}
public_fields:
- timestamp
- event_id
- event_type
- level
- server_did
- user_did
- request_id
- method
- path
- ceremony_id
- cipher
- device_did
- created_at
- group
- publisher_did
- added_at
- leaf_index
- recipient_did
- kit_sha256
- slot
- to_did
- issued_to
- generation
- previous_kit_sha256
- old_pool_size
- new_pool_size
- rotated_at
- peer_did
- package_sha256
- compiled_at
- from_did
- absorbed_at
- vault_did
- project_id
- linked_at
- reason
- unlinked_at
- policy_uri
- content_hash
- event_types_covered
- policy_text
- envelope_event_id
- envelope_did
- envelope_event_type
- envelope_sequence
- invalid_reasons
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - did: ${dk.did}
  tn.agents:
    policy: private
    cipher: btn
    recipients:
    - did: ${dk.did}
    fields:
    - instruction
    - use_for
    - do_not_use_for
    - consequences
    - on_violation_or_error
    - policy
    auto_populated_by_policy: true
fields: {}
`;
  writeFileSync(yamlPath, yaml, "utf8");
}
