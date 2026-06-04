// Node-only runtime: loads a yaml + keystore from disk, seeds chain
// state from any existing log, and exposes emit() + read() that match
// the Python tn.logger flow byte-for-byte (modulo the random CEK/nonce
// inside each btn ciphertext).
//
// Only btn ceremonies are supported. A ceremony whose groups use jwe or
// bgw will throw on emit/read, pointing the caller at the Python path.

// Side-effect import: the nodejs target of tn-wasm self-instantiates
// its .wasm at module load time (see the bottom of pkg/tn_wasm.js).
// Mirrors the same import in src/index.ts; importing tn-wasm twice is
// a no-op. Required for callers that bypass index.ts (e.g. tests that
// import { Tn } from "../src/tn.js" directly).
//
// `initSync` is NOT exported by the nodejs-target glue — only by the
// web/bundler targets. The browser entry handles its own init via the
// inlined-bytes path.
import "tn-wasm";

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve as pathResolve } from "node:path";
import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";

import { DeviceKey } from "../core/signing.js";

import { loadPolicyFile, type PolicyDocument } from "../agents_policy.js";
import {
  KNOWN_KINDS,
  clockDominates,
  isManifestSignatureValid,
  newManifest,
  signManifest,
  type Manifest,
  type ManifestKind,
  type VectorClock,
} from "../core/tnpkg.js";
import { readTnpkg, writeTnpkg } from "../tnpkg_io.js";
import { encryptBodyBlob, BODY_CIPHER_SUITE, BODY_FRAME } from "../core/body_encryption.js";
import {
  appendAdminEnvelopes,
  existingRowHashes,
  isAdminEventType,
  resolveAdminLogPath,
} from "../admin/log.js";
import { BtnPublisher, btnKitLeaf } from "../raw.js";
import { ensureProcessRunId } from "../_run_id.js";
import { decryptGroup, type GroupKits } from "../core/decrypt.js";
import { getProfile, isKnownProfile } from "../profiles.js";
import { DEFAULT_VAULT_URL } from "../vault/url.js";
import type { TNHandler } from "../handlers/index.js";

function readKitLeaf(kitBytes: Uint8Array): bigint {
  return btnKitLeaf(kitBytes);
}
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { ZERO_HASH, rowHash } from "../core/chain.js";
import { signatureFromB64, verify } from "../core/signing.js";
import { asDid, asRowHash, asSignatureB64, type RowHash } from "../core/types.js";
import { authoritativeYamlFor, loadConfig, type CeremonyConfig, type GroupConfig } from "./config.js";
import { loadKeystore, type LoadedKeystore } from "./keystore.js";
import { scanAttestedEventRecords, yamlRecipientDids } from "./reconcile.js";
import { WasmRuntime } from "tn-wasm";
import { nodeStorageAdapter } from "./storage_node.js";
import { lastEmitReceipt, receiptFromLine } from "./wasm_shim.js";
// Re-export for callers that still consume it through this module.
export { lastEmitReceipt };

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
// 0.4.3a1 phase G: wire key flipped from `did` to `device_identity` so the
// reserved-keys set must follow. Otherwise the read-side row_hash recompute
// leaks `device_identity` into `publicFields`, double-hashes it, and every
// verify check fails. Matches python/tn/reader.py:_envelope_reserved post-flip.
const _ENVELOPE_RESERVED = new Set([
  "device_identity",
  "timestamp",
  "event_id",
  "event_type",
  "level",
  "prev_hash",
  "row_hash",
  "signature",
  "sequence",
]);

import type { AbsorbReceipt, EmitReceipt } from "../core/results.js";
export type { AbsorbReceipt, EmitReceipt };

import type { AdminState, RecipientEntry } from "../core/types.js";
import { AdminStateCache } from "../admin/cache.js";
import type { ChainConflict, LeafReuseAttempt } from "../core/admin/state.js";

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

/** True iff `s` contains a `{token}` substitution placeholder. */
function hasTemplateTokens(s: string): boolean {
  return /\{[^}]+\}/.test(s);
}

/**
 * Expand a templated `logs.path` (e.g. `./logs/{event_id}.ndjson`) into
 * the concrete files it could have produced, by replacing every
 * `{token}` with a `*` wildcard and matching existing files. Relative
 * patterns anchor to `yamlDir` (the ceremony directory), matching the
 * write side and Python's `_log_targets.resolve_log_target`.
 *
 * Generic over the token set: any `{...}` becomes `*`, so `{event_id}`
 * works the same as `{event_class}` / `{date}` without enumerating
 * tokens here. Returns existing files only (a non-templated path is
 * returned as-is so the caller's existence check is unchanged).
 */
function expandTemplatedLogPath(pattern: string, yamlDir: string): string[] {
  if (!hasTemplateTokens(pattern)) return [pattern];
  const globbed = pattern.replace(/\{[^}]+\}/g, "*");
  let abs = globbed;
  if (!isAbsolute(globbed)) {
    const rel = globbed.replace(/^\.[\\/]/, "");
    abs = join(yamlDir, rel);
  }
  // Walk segment-by-segment from the longest static prefix, expanding
  // each `*`-bearing segment via readdir. Handles tokens in the
  // basename (the common `{event_id}.ndjson` case) and in a single
  // directory level (`{event_class}/{date}.ndjson`).
  const segs = abs.split(/[\\/]+/);
  let bases: string[] = [segs[0]!.length > 0 ? segs[0]! : "/"];
  for (let i = 1; i < segs.length; i++) {
    const seg = segs[i]!;
    if (seg.length === 0) continue;
    const next: string[] = [];
    if (seg.includes("*") || seg.includes("?")) {
      const re = new RegExp(
        "^" + seg.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
      );
      for (const base of bases) {
        let entries: string[];
        try {
          entries = readdirSync(base);
        } catch {
          continue;
        }
        for (const e of entries) {
          if (re.test(e)) next.push(join(base, e));
        }
      }
    } else {
      for (const base of bases) next.push(join(base, seg));
    }
    bases = next;
  }
  return bases.filter((p) => {
    try {
      return statSync(p).isFile();
    } catch {
      return false;
    }
  });
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
  /** TS-side `BtnPublisher` instances per group. Owned here (not by
   *  wasm) because admin verbs that mint or rotate kits still execute
   *  in TS for now — `addRecipient`, `rotateGroup`, the agent-runtime
   *  bundle path. Once those migrate to wasm this can go. */
  private publishers = new Map<string, BtnPublisher>();
  private handlers: TNHandler[] = [];
  /**
   * Lazily-attached `WasmRuntime` companion. `null` until the first
   * `emit*` (or other wasm-routed verb) is invoked; subsequent calls
   * reuse the cached handle. The four public emit verbs always route
   * through this handle via `_emitViaWasm`; the TS-side envelope
   * pipeline (sign / chain / encrypt / handler fan-out / file append)
   * is fully owned by the wasm runtime.
   *
   * `attachWasm()` initialises wasm with `skipCeremonyInitEmit: true`
   * + `skipPolicyPublishedEmit: true` so the mid-session lazy attach
   * doesn't duplicate events the TS path has already taken
   * responsibility for.
   */
  private wasm: WasmRuntime | null = null;
  /** Cached `tn.agents` policy doc for this ceremony. `null` means "no
   * `.tn/config/agents.md` present" — splice path no-ops. */
  agentPolicy: PolicyDocument | null = null;

  addHandler(h: TNHandler): void {
    this.handlers.push(h);
    // If wasm is already attached, mirror immediately so this handler
    // catches subsequent emits (which fan out through wasm).
    if (this.wasm !== null) this._mirrorHandlerToWasm(h);
  }

  private constructor(config: CeremonyConfig, keystore: LoadedKeystore) {
    this.config = config;
    this.keystore = keystore;
    for (const [name, g] of keystore.groups) {
      const gcfg = config.groups.get(name);
      if (gcfg && gcfg.cipher !== "btn") continue;
      this.publishers.set(name, BtnPublisher.fromBytes(g.stateBytes));
    }
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
    if (keystore.device.did !== config.device.device_identity) {
      throw new Error(
        `keystore did (${keystore.device.did}) does not match yaml device.device_identity (${config.device.device_identity})`,
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
    // The wasm-side `WasmRuntime` companion (`rt.wasm`) is lazily
    // instantiated on first use via `rt.attachWasm()`. Eager attachment
    // is incompatible with the current TS implementation: `WasmRuntime.init`
    // walks the yaml's admin log path and emits its own `tn.ceremony.init`
    // bookkeeping, which would race the TS-side chain state and break
    // tests that rely on a single deterministic event sequence
    // (`admin.state rolls up ...`, `AdminStateCache flags fork ...`).
    // The slim-down plan in
    // `docs/superpowers/plans/2026-05-13-wasm-widen-and-fallback-deprecate.md`
    // §2.5 routes emit/read through wasm once the TS implementation is
    // deleted in the same change — keeping both eager today would
    // double-write. For now the field stays `null` and the TS impl is
    // authoritative.
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

  /** Append one log entry. Routes through `WasmRuntime.emit` so the
   *  full envelope build / sign / chain / write happens inside the
   *  Rust core. The TS-side `emitInternal` is dead (kept only until
   *  the slim-down deletion pass lands). See `_emitViaWasm` below. */
  emit(level: string, eventType: string, fields: Record<string, unknown>): EmitReceipt {
    return this._emitViaWasm(level, eventType, fields, undefined, undefined, undefined);
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
    return this._emitViaWasm(level, eventType, fields, opts.timestamp, opts.eventId, undefined);
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
    return this._emitViaWasm(level, eventType, fields, undefined, undefined, sign);
  }

  /** Full-control emit: timestamp + event_id + sign override. */
  emitWithOverrideSign(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    opts: { timestamp?: string; eventId?: string; sign?: boolean | null } = {},
  ): EmitReceipt {
    return this._emitViaWasm(
      level,
      eventType,
      fields,
      opts.timestamp,
      opts.eventId,
      opts.sign ?? null,
    );
  }

  /** Single dispatch point that delegates to `WasmRuntime.emit*` and
   *  synthesizes an `EmitReceipt` from the resulting on-disk envelope.
   *
   *  This is the ONLY emit path the four public verbs route through.
   *  The wasm runtime owns the envelope build, sign, chain advance,
   *  multi-group encrypt, row_hash, handler fan-out, and file append.
   *  TS-side concerns kept here: agents-policy splice (so PoliCy
   *  templates work even when the wasm runtime doesn't have its own
   *  copy of the policy doc), session-level sign override resolution,
   *  and PEL path resolution for the `lastEmitReceipt` shim. */
  private _emitViaWasm(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    timestampOverride: string | undefined,
    eventIdOverride: string | undefined,
    signOverride: boolean | null | undefined,
  ): EmitReceipt {
    validateEventType(eventType);
    // Apply the agents-policy splice on the TS side so the spec §2.6
    // template fields land in `fields` exactly as the prior TS emit
    // did. The wasm runtime independently performs its own splice on
    // top of this, which is a no-op when the same template values are
    // already present.
    const fieldsOut = this._spliceAgentPolicy(eventType, fields);
    // Honour the session-level signing override at the TS surface.
    // Per-call `signOverride` still wins.
    const resolvedSign =
      signOverride !== undefined && signOverride !== null
        ? signOverride
        : _sessionSignOverride;
    const w = this.attachWasm();
    // Build the receipt from the emit's own returned line rather than
    // reading the row back off disk. The read-back can't locate the row
    // for a templated `logs.path` (e.g. `./logs/{event_id}.ndjson`),
    // where each emit lands in its own per-event file rather than the
    // single main log. The returned line is the canonical envelope
    // regardless of which file the runtime wrote it to.
    const line = w.emitReturningLine(
      level,
      eventType,
      fieldsOut,
      timestampOverride ?? null,
      eventIdOverride ?? null,
      resolvedSign,
    );
    return receiptFromLine(line);
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
      recipient_identity: recipientDid ?? null,
      kit_sha256: `sha256:${digest}`,
      cipher: "btn",
    });

    return actualLeaf;
  }

  /**
   * Rotate the keys for a btn group. Mirrors the Python
   * ``tn.admin.rotate(group)`` semantics:
   *
   *   1. Hash the existing self-kit (for the ``previous_kit_sha256``
   *      field on the attestation event — readers replaying the log
   *      can audit the rotation lineage).
   *   2. Rename the old ``<group>.btn.state`` and ``<group>.btn.mykit``
   *      files to ``.revoked.<UTC_TS>`` so pre-rotation envelopes stay
   *      decryptable by holders of the old kit.
   *   3. Mint a fresh ``BtnPublisher`` with a new random seed; write
   *      its state + self-kit at the canonical paths.
   *   4. Swap the in-memory publisher (so subsequent ``emit`` /
   *      ``addRecipient`` calls use the new keys).
   *   5. Bump ``groups.<group>.index_epoch`` in the on-disk yaml.
   *   6. Emit ``tn.rotation.completed`` so the admin log records the
   *      rotation event with the new generation + the previous kit's
   *      sha256 (lineage chain).
   *
   * Recipients still appear in ``recipients(group)`` after rotation —
   * they're the surviving set whose new kits the publisher (or the
   * ``tn-js admin rotate`` CLI) needs to mint and ship via
   * ``addRecipient``.
   *
   * Returns ``{ generation, previousKitSha256 }``. Throws when the
   * group isn't a btn publisher in this runtime.
   */
  rotateGroup(group: string): {
    generation: number;
    previousKitSha256: string;
    newKitSha256: string;
    rotatedAt: string;
  } {
    const oldPub = this.publishers.get(group);
    if (!oldPub) {
      throw new Error(`rotateGroup: group ${group} is not a btn publisher in this runtime`);
    }

    const ks = this.config.keystorePath;
    const statePath = join(ks, `${group}.btn.state`);
    const mykitPath = join(ks, `${group}.btn.mykit`);

    // Hash the previous self-kit before renaming. If it's missing for
    // any reason (race, corruption), record "sha256:unknown" so the
    // lineage chain still has a deterministic placeholder rather than
    // crashing the rotation.
    let previousKitSha256 = "sha256:unknown";
    if (existsSync(mykitPath)) {
      try {
        const oldKit = readFileSync(mykitPath);
        previousKitSha256 = `sha256:${createHash("sha256").update(oldKit).digest("hex")}`;
      } catch {
        // Fall through to the "unknown" placeholder.
      }
    }

    // Rename old key material out of the way. UTC timestamp matches
    // the Python convention so cross-language ceremonies show
    // identical .revoked.<ts> filenames in the keystore.
    const ts = Math.floor(Date.now() / 1000);
    const renameIfExists = (src: string): void => {
      if (!existsSync(src)) return;
      try {
        renameSync(src, `${src}.revoked.${ts}`);
      } catch {
        // Best-effort: a Windows-side AV lock or open handle shouldn't
        // block the rotation. The new write below will overwrite
        // in place and the audit trail is preserved on the
        // tn.rotation.completed envelope.
      }
    };
    renameIfExists(statePath);
    renameIfExists(mykitPath);

    // Mint a fresh publisher + self-kit and write at the canonical
    // paths. The old publisher's bytes are released after the new
    // one is wired up so a transient failure here doesn't leave the
    // runtime with a dangling state.
    const newPub = new BtnPublisher(null);
    const newSelfKit = newPub.mint();
    const newStateBytes = newPub.toBytes();
    writeFileSync(statePath, Buffer.from(newStateBytes));
    writeFileSync(mykitPath, Buffer.from(newSelfKit));

    // Swap the in-memory handle. The runtime keeps a single
    // BtnPublisher per group and addRecipient / encrypt use it
    // directly; replacing the entry must happen before we attest the
    // event so the attestation itself is sealed under the new keys.
    this.publishers.set(group, newPub);
    try {
      oldPub.free();
    } catch {
      // free() is idempotent and best-effort; a double-free here
      // would only matter if Node and Rust disagreed on ownership.
    }

    // Mirror the on-disk swap into the in-memory keystore so the
    // read-decrypt path picks up the new self-kit immediately. Without
    // this, post-rotation entries (sealed by the new publisher) fail
    // to decrypt in the same process — the keystore was loaded once
    // at init time and only knows about the pre-rotation kits.
    //
    // The order is: prepend the new self-kit (so index 0 is current,
    // matching loadKeystore's invariant) and append the OLD self-kit
    // bytes so pre-rotation entries still decrypt via the previous
    // kit. Recipient kits added later via addRecipient flow through
    // their own write path and do not need a keystore reload.
    const groupKs = this.keystore.groups.get(group);
    if (groupKs) {
      // Stash the previous self-kit (index 0 by loadKeystore convention)
      // before we overwrite — it can still decrypt pre-rotation entries.
      const previousSelfKit = groupKs.kits[0];
      const newKits: Uint8Array[] = [new Uint8Array(newSelfKit)];
      if (previousSelfKit && previousSelfKit.length > 0) {
        newKits.push(previousSelfKit);
      }
      // Preserve any other rotation-preserved kits already loaded
      // (kits[1..] from a prior rotation — multi-rotation chains).
      for (let i = 1; i < groupKs.kits.length; i++) {
        const k = groupKs.kits[i];
        if (k && k.length > 0) newKits.push(k);
      }
      groupKs.kits = newKits;
      groupKs.stateBytes = new Uint8Array(newStateBytes);
    }

    // Bump groups.<group>.index_epoch in the on-disk yaml. TS doesn't
    // currently use the epoch for an HMAC-keyed field-search index
    // (Python does), but we still bump it so a future TS index
    // implementation, or a Python reader replaying the same log,
    // sees the same epoch progression.
    //
    // `groups` is parent-owned: under the multi-ceremony layout a named
    // stream's yaml carries `extends: ../default/tn.yaml` and inherits
    // `groups` from the project root. Writing the epoch into the stream
    // yaml (`this.config.yamlPath`) is silently discarded on the next
    // load ("child sets parent-owned key 'groups'; parent wins"), so the
    // bump never persists. Route the write to the yaml that
    // authoritatively owns `groups` (the head of the `extends:` chain).
    // For a no-extends ceremony this resolves back to `this.config.yamlPath`,
    // so the legacy single-file layout is unchanged. Mirrors Python's
    // tn.admin._update_authoritative_yaml(..., key="groups").
    const yamlPath = authoritativeYamlFor(this.config.yamlPath, "groups");
    let nextEpoch = 1;
    try {
      const text = readFileSync(yamlPath, "utf8");
      const doc = parseYaml(text) as Record<string, unknown>;
      const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
      const groupSpec = groups[group] ?? {};
      const cur = typeof groupSpec.index_epoch === "number" ? groupSpec.index_epoch : 0;
      nextEpoch = cur + 1;
      groupSpec.index_epoch = nextEpoch;
      groups[group] = groupSpec;
      doc.groups = groups;
      writeFileSync(yamlPath, stringifyYaml(doc), "utf8");
    } catch {
      // If yaml-write fails, the keystore swap already succeeded;
      // surface "unknown epoch increment" via the attestation but
      // don't unwind the rotation.
    }

    // Tear down the cached wasm runtime so the in-memory btn cipher
    // it holds — loaded once at attach time off the PRE-rotation
    // keystore — is dropped. The `this.emit(...)` call below will
    // lazily re-attach via `attachWasm`, which reads the freshly-
    // rotated `<group>.btn.state` + `<group>.btn.mykit` from disk.
    // The attestation event therefore lands under the new epoch's
    // cipher, and so does every subsequent emit on this NodeRuntime
    // instance — matching Python's `admin.rotate`, which replaces
    // `cfg.groups[group].cipher` in the active logger so the next
    // emit uses the rotated cipher without a re-init. Without this
    // reset, wasm would keep encrypting under the pre-rotation
    // publisher seed and a revoked recipient's old kit could still
    // unwrap post-rotation entries (C5 TS revoke regression).
    this._resetWasmAfterAdminWrite();

    // Attest the rotation. Catalog-validated fields only — anything
    // not listed in public_fields would be sealed away from auditors
    // who only have the public log.
    const rotatedAt = new Date().toISOString();
    const newKitSha256 = `sha256:${createHash("sha256").update(Buffer.from(newSelfKit)).digest("hex")}`;
    this.emit("info", "tn.rotation.completed", {
      group,
      cipher: "btn",
      generation: nextEpoch,
      previous_kit_sha256: previousKitSha256,
      old_pool_size: null,
      new_pool_size: null,
      rotated_at: rotatedAt,
    });

    return {
      generation: nextEpoch,
      previousKitSha256,
      newKitSha256,
      rotatedAt,
    };
  }

  /** Drop the cached `WasmRuntime` so the next emit / read re-attaches
   *  off the current on-disk keystore. Used by admin verbs that mutate
   *  publisher state (mint/revoke/rotate) — the wasm runtime caches its
   *  own copy of the btn cipher at attach time and has no reload API,
   *  so we force a fresh attach to pick up the disk write.
   *
   *  Idempotent: a no-op when wasm hasn't been attached yet. Close
   *  errors are swallowed (best-effort flush; the Drop impl will still
   *  release file handles). */
  private _resetWasmAfterAdminWrite(): void {
    if (this.wasm === null) return;
    try {
      this.wasm.close();
    } catch {
      // Best-effort: the Drop impl will still flush + release handles.
    }
    this.wasm = null;
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
      recipient_identity: recipientDid ?? null,
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
    if (this.wasm !== null) {
      try {
        this.wasm.close();
      } catch {
        /* best-effort; the Drop impl will still flush */
      }
      this.wasm = null;
    }
  }

  /** True iff a WasmRuntime companion is currently attached (the Rust/WASM
   *  core services the emit path). False before the first emit (wasm
   *  attaches lazily) and after teardown (_resetWasmAfterAdminWrite / close). */
  isWasmActive(): boolean {
    return this.wasm !== null;
  }

  /**
   * Lazily attach a `WasmRuntime` companion. Returns the cached handle
   * if one already exists; otherwise builds a fresh `WasmRuntime`
   * against this ceremony's yaml + the node `fs` storage adapter and
   * caches it on `this.wasm`. Idempotent.
   *
   * Constructs the wasm runtime with `skipCeremonyInitEmit: true` so
   * the lazy attach doesn't stray-emit `tn.ceremony.init` into the
   * admin log. The TS `NodeRuntime` has already initialized the
   * ceremony out-of-band; the wasm side only needs to inherit the
   * same chain state, not double-attest it.
   *
   * Throws if wasm initialization fails — callers that route through
   * wasm have no fallback path today.
   */
  attachWasm(): WasmRuntime {
    if (this.wasm !== null) return this.wasm;
    // Stamp $TN_RUN_ID before wasm reads env at init. The wasm side
    // reads via std::env::var("TN_RUN_ID") (see
    // crypto/tn-core/src/runtime.rs:860); if we don't set it first,
    // wasm mints its own fresh UUID and the JS / wasm sides stamp
    // mismatched run_ids on every emit — at which point `wasm.read()`'s
    // current-run filter silently drops every entry written via the
    // wasm path. Mirrors python/tn/__init__.py:268 (which writes the
    // env right before the Rust runtime sees it).
    ensureProcessRunId();
    try {
      this.wasm = WasmRuntime.initWith(
        this.config.yamlPath,
        nodeStorageAdapter(),
        { skipCeremonyInitEmit: true, skipPolicyPublishedEmit: true },
      );
    } catch (err) {
      throw new Error(
        `attachWasm: failed to initialize WasmRuntime for ${this.config.yamlPath}: ${
          (err as Error).message ?? String(err)
        }`,
        { cause: err },
      );
    }
    // Mirror every TS-registered handler into wasm so emit fan-out
    // (which now runs inside `WasmRuntime.emit`) catches them. Handlers
    // added BEFORE `attachWasm` register here in bulk; later
    // `addHandler` calls also mirror eagerly (see `addHandler`).
    for (const h of this.handlers) {
      this._mirrorHandlerToWasm(h);
    }
    return this.wasm;
  }

  /** Bridge a TS-side `TNHandler` to the wasm runtime's handler list.
   *  The wasm emit fan-out calls these with a `Uint8Array` rawLine;
   *  the TS `TNHandler.emit` contract expects a `string`, so we decode
   *  per call. No-op when `attachWasm()` hasn't been called yet. */
  private _mirrorHandlerToWasm(h: TNHandler): void {
    if (this.wasm === null) return;
    const decoder = new TextDecoder("utf-8");
    this.wasm.addHandler({
      name: h.name,
      accepts: (env: unknown) => {
        try {
          return h.accepts(env as Record<string, unknown>);
        } catch {
          return false;
        }
      },
      emit: (env: unknown, rawLine: unknown) => {
        try {
          const line =
            rawLine instanceof Uint8Array ? decoder.decode(rawLine) : String(rawLine ?? "");
          h.emit(env as Record<string, unknown>, line);
        } catch {
          // A failing handler must not abort the wasm emit pipeline.
        }
      },
      close: () => {
        try {
          h.close();
        } catch {
          /* best-effort */
        }
      },
    });
  }

  // ---------------------------------------------------------------------------
  // Handlers namespace accessors — used by HandlersNamespace (tn.handlers.*).
  // ---------------------------------------------------------------------------

  /** Return a defensive copy of the registered handler list. */
  listHandlers(): TNHandler[] {
    return [...this.handlers];
  }

  /** Flush any handler that exposes a `flush()` method; handlers without one
   * are skipped. Always resolves (errors are swallowed per the contract). */
  async flushHandlers(): Promise<void> {
    for (const h of this.handlers) {
      const withFlush = h as TNHandler & { flush?: () => Promise<void> | void };
      if (typeof withFlush.flush === "function") {
        try {
          await withFlush.flush();
        } catch {
          // A failing flush must not take down the caller.
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Agents namespace accessors — used by AgentsNamespace (tn.agents.*).
  // ---------------------------------------------------------------------------

  /** Return the cached agent policy doc (`null` when no agents.md is present). */
  getAgentPolicy(): PolicyDocument | null {
    return this.agentPolicy;
  }

  /** Re-read `.tn/config/agents.md`, refresh the cache, and emit
   * `tn.agents.policy_published` if the content hash changed. */
  reloadAgentPolicy(): PolicyDocument | null {
    const fresh = loadPolicyFile(this.config.yamlDir);
    const prev = this.agentPolicy;
    this.agentPolicy = fresh;
    if (fresh !== null && (prev === null || prev.contentHash !== fresh.contentHash)) {
      this.emit("info", "tn.agents.policy_published", {
        policy_uri: fresh.path,
        version: fresh.version,
        content_hash: fresh.contentHash,
        event_types_covered: [...fresh.templates.keys()].sort(),
        policy_text: fresh.body,
      });
    }
    return fresh;
  }

  // ---------------------------------------------------------------------------
  // Vault namespace helpers — used by VaultNamespace (tn.vault.*).
  // ---------------------------------------------------------------------------

  /** Emit a signed `tn.vault.linked` event by delegating to `WasmRuntime.vaultLink`.
   *
   *  The wasm runtime owns the envelope build, sign, chain advance,
   *  and write through its storage adapter. The receipt is synthesized
   *  by reading back the last entry from the admin log (see
   *  `lastEmitReceipt`); `tn.vault.*` events are admin-class so the
   *  receipt lives there per `protocol_events_location`. */
  vaultLink(vaultDid: string, projectId: string): EmitReceipt {
    const w = this.attachWasm();
    w.vaultLink(vaultDid, projectId);
    return lastEmitReceipt(w, resolveAdminLogPath(this.config));
  }

  /** Emit a signed `tn.vault.unlinked` event by delegating to `WasmRuntime.vaultUnlink`. */
  vaultUnlink(vaultDid: string, projectId: string, reason?: string): EmitReceipt {
    const w = this.attachWasm();
    w.vaultUnlink(vaultDid, projectId, reason ?? null);
    return lastEmitReceipt(w, resolveAdminLogPath(this.config));
  }

  // ---------------------------------------------------------------------------
  // Agent runtime kit bundler — used by AgentsNamespace.addRuntime.
  // ---------------------------------------------------------------------------

  /**
   * Mint reader kits for `opts.groups` (plus the implicit `tn.agents` group),
   * bundle them into a `.tnpkg` at `opts.outPath`, and return the written path.
   * Mirrors TNClient.adminAddAgentRuntime.
   */
  adminAddAgentRuntime(opts: {
    runtimeDid: string;
    groups: string[];
    outPath: string;
    label?: string;
  }): string {
    // Dedup: tn.agents is always added; skip duplicates.
    const seen = new Set<string>();
    const requested: string[] = [];
    for (const g of opts.groups) {
      if (g === "tn.agents") continue;
      if (seen.has(g)) continue;
      seen.add(g);
      requested.push(g);
    }
    requested.push("tn.agents");

    for (const gname of requested) {
      if (!this.config.groups.has(gname)) {
        throw new Error(
          `adminAddAgentRuntime: group ${JSON.stringify(gname)} is not ` +
            `declared in this ceremony's yaml ` +
            `(known: ${JSON.stringify([...this.config.groups.keys()].sort())})`,
        );
      }
    }

    const td = mkdtempSync(join(tmpdir(), "tn-agent-bundle-"));
    try {
      for (const gname of requested) {
        const kitPath = join(td, `${gname}.btn.mykit`);
        this.addRecipient(gname, kitPath, opts.runtimeDid);
      }

      const body: Record<string, Uint8Array> = {};
      const kitsMeta: Array<{ name: string; sha256: string; bytes: number }> = [];
      for (const gname of [...requested].sort()) {
        const name = `${gname}.btn.mykit`;
        const p = join(td, name);
        if (!existsSync(p)) continue;
        const data = new Uint8Array(readFileSync(p));
        body[`body/${name}`] = data;
        kitsMeta.push({
          name,
          sha256: "sha256:" + createHash("sha256").update(Buffer.from(data)).digest("hex"),
          bytes: data.length,
        });
      }
      if (kitsMeta.length === 0) {
        throw new Error(
          `adminAddAgentRuntime: no kits minted for groups ${JSON.stringify(requested)}`,
        );
      }

      const manifest = newManifest({
        kind: "kit_bundle",
        fromDid: this.config.device.device_identity,
        ceremonyId: this.config.ceremonyId,
        scope: "kit_bundle",
        toDid: opts.runtimeDid,
      });
      manifest.state = { kits: kitsMeta, kind: "readers-only" };
      signManifest(manifest, this.keystore.device);
      const out = writeTnpkg(opts.outPath, manifest, body);

      if (opts.label !== undefined) {
        try {
          writeFileSync(`${out}.label`, opts.label, "utf8");
        } catch {
          // Best-effort sidecar.
        }
      }

      return out;
    } finally {
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup.
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

  // ---------------------------------------------------------------------------
  // Admin-state helpers — used by AdminNamespace (tn.admin.*).
  // ---------------------------------------------------------------------------

  private _adminCache: AdminStateCache | null = null;

  /** Lazy-initialized AdminStateCache. */
  adminCache(): AdminStateCache {
    if (this._adminCache === null) {
      this._adminCache = new AdminStateCache(this.config);
    }
    return this._adminCache;
  }

  /** Return the full local admin state for this ceremony (or filtered to a
   * single group). Derived by replaying the log through AdminStateCache.
   *
   * When no `tn.ceremony.init` event has been written to the log yet (common
   * for btn ceremonies where Rust writes ceremony info to yaml rather than the
   * log), the ceremony record is auto-derived from the current config —
   * matching TNClient.adminState's fallback behavior. */
  adminState(group?: string): AdminState {
    const raw = this.adminCache().state();
    // Auto-derive ceremony + groups from config when the cache has not seen
    // the attesting events. A btn ceremony records ceremony/group info in the
    // yaml rather than the log, and the TS runtime (unlike Python's reconcile)
    // does not write synthetic tn.ceremony.init / tn.group.added records; so
    // without this fallback state() under-reports vs Python. Mirrors Python's
    // admin.state config fallback so the two SDKs agree (see
    // docs/sdk-unification-plan.md, adminState slice). No attesting event
    // exists, so the derived timestamp uses the yaml mtime as a stable proxy.
    let derivedAt: string;
    try {
      derivedAt = statSync(this.config.yamlPath).mtime.toISOString();
    } catch {
      derivedAt = new Date().toISOString();
    }
    const ceremony = raw.ceremony ?? {
      ceremonyId: this.config.ceremonyId,
      cipher: this.config.cipher,
      deviceDid: this.config.device.device_identity,
      createdAt: derivedAt,
    };
    const groups =
      raw.groups.length > 0
        ? raw.groups
        : [...this.config.groups.keys()].map((name) => ({
            group: name,
            cipher: this.config.cipher,
            publisherDid: this.config.device.device_identity,
            addedAt: derivedAt,
          }));
    const state: AdminState = { ...raw, ceremony, groups };
    if (group === undefined) return state;
    return {
      ...state,
      groups: state.groups.filter((g) => g.group === group),
      recipients: state.recipients.filter((r) => r.group === group),
      rotations: state.rotations.filter((r) => r.group === group),
      coupons: state.coupons.filter((c) => c.group === group),
      enrolments: state.enrolments.filter((e) => e.group === group),
    };
  }

  /** Return the recipient roster for a group via the AdminStateCache.
   * Sorted active-first (revoked === false), then by leafIndex ascending —
   * matching TNClient.recipients sort order. */
  recipients(group: string, opts?: { includeRevoked?: boolean }): RecipientEntry[] {
    const list = this.adminCache().recipients(group, opts);
    return list.slice().sort((a, b) => {
      if (a.revoked !== b.revoked) return a.revoked ? 1 : -1;
      return a.leafIndex - b.leafIndex;
    });
  }

  /** Add a group post-init and emit `tn.group.added`. Returns the emit
   * receipt. Caller is responsible for checking idempotency before calling.
   *
   * For btn (the only cipher NodeRuntime supports) this mirrors Python's
   * `tn.admin.ensure_group`: it mints the group's key material and persists
   * the `groups.<name>` block to the AUTHORITATIVE yaml so the group both
   * survives the next load and is routable. See {@link persistBtnGroup}.
   *
   * jwe groups stay log-only: NodeRuntime can't mint jwe key material, and
   * writing a jwe group to the yaml would break the next wasm attach (the
   * Rust/wasm runtime resolves `extends:` and errors when a resolved group
   * has no cipher state on disk). jwe ceremonies are Python-owned. */
  adminEnsureGroup(group: string, cipher: "btn" | "jwe"): EmitReceipt {
    if (cipher === "btn") {
      this.persistBtnGroup(group);
    }
    const addedAt = new Date().toISOString();
    return this.emit("info", "tn.group.added", {
      group,
      cipher,
      publisher_identity: this.did,
      added_at: addedAt,
    });
  }

  /** Mint a fresh btn group and persist it AUTHORITATIVELY.
   *
   * Mirrors Python's `tn.admin.ensure_group` (btn branch) +
   * `_update_authoritative_yaml(..., key="groups")`:
   *
   *   1. Mint a `BtnPublisher` and write `<group>.btn.state` +
   *      `<group>.btn.mykit` into the keystore (skipped when a state file
   *      already exists, so a re-ensure never discards an existing tree).
   *   2. Register the publisher + a `GroupConfig` in the in-memory config so
   *      same-process emit / addRecipient route through the new group
   *      without a re-init.
   *   3. Write the `groups.<name>` block to the yaml that AUTHORITATIVELY
   *      owns `groups` — the head of the `extends:` chain. Under the
   *      multi-ceremony layout a named stream's yaml carries
   *      `extends: ../default/tn.yaml` and `groups` is parent-owned:
   *      writing it into the stream yaml (`this.config.yamlPath`) is
   *      silently discarded on the next load ("child sets parent-owned key
   *      'groups'; parent wins"), so the group vanishes and a fresh-process
   *      load can't route through it. {@link authoritativeYamlFor} walks to
   *      the chain root; for a no-extends ceremony it resolves back to
   *      `this.config.yamlPath`, leaving the legacy single-file layout
   *      unchanged.
   *   4. Drop the cached wasm runtime so the next emit / read re-attaches
   *      off the updated yaml + keystore and sees the new group. */
  private persistBtnGroup(group: string): void {
    const keystore = this.config.keystorePath;
    const statePath = join(keystore, `${group}.btn.state`);
    const mykitPath = join(keystore, `${group}.btn.mykit`);

    if (!existsSync(statePath)) {
      if (!existsSync(keystore)) mkdirSync(keystore, { recursive: true });
      const pub = new BtnPublisher(new Uint8Array(randomBytes(32)));
      const selfKit = pub.mint();
      writeFileSync(statePath, Buffer.from(pub.toBytes()));
      writeFileSync(mykitPath, Buffer.from(selfKit));
      this.publishers.set(group, pub);
    } else if (!this.publishers.has(group)) {
      this.publishers.set(group, BtnPublisher.fromBytes(new Uint8Array(readFileSync(statePath))));
    }

    // Keep the in-memory config consistent so same-process routing sees the
    // new group immediately (matches Python's `cfg.groups[group] = ...`).
    if (!this.config.groups.has(group)) {
      this.config.groups.set(group, {
        name: group,
        policy: "private",
        cipher: "btn",
        recipients: this.did ? [{ did: this.did }] : [],
      });
    }

    // Persist the group block to the yaml that authoritatively owns
    // `groups` (head of the extends chain). See the method doc above.
    const target = authoritativeYamlFor(this.config.yamlPath, "groups");
    const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
    const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
    if (!groups[group]) {
      groups[group] = {
        policy: "private",
        cipher: "btn",
        recipients: [{ recipient_identity: this.did }],
      };
      doc.groups = groups;
      writeFileSync(target, stringifyYaml(doc), "utf8");
    }

    // Force the next emit/read to re-attach wasm off the freshly-written
    // yaml + keystore so it builds the new group's cipher.
    this._resetWasmAfterAdminWrite();
  }

  // ---------------------------------------------------------------------------
  // AdminState wire-format conversion helpers
  // ---------------------------------------------------------------------------

  private static readonly _ADMIN_STATE_FIELD_MAP: Record<string, string> = {
    ceremonyId: "ceremony_id",
    deviceDid: "device_identity",
    createdAt: "created_at",
    publisherDid: "publisher_identity",
    addedAt: "added_at",
    leafIndex: "leaf_index",
    recipientDid: "recipient_identity",
    kitSha256: "kit_sha256",
    mintedAt: "minted_at",
    activeStatus: "active_status",
    revokedAt: "revoked_at",
    retiredAt: "retired_at",
    previousKitSha256: "previous_kit_sha256",
    rotatedAt: "rotated_at",
    toDid: "recipient_identity",
    issuedTo: "issued_to",
    issuedAt: "issued_at",
    peerDid: "peer_identity",
    packageSha256: "package_sha256",
    compiledAt: "compiled_at",
    absorbedAt: "absorbed_at",
    vaultDid: "vault_identity",
    projectId: "project_id",
    linkedAt: "linked_at",
    unlinkedAt: "unlinked_at",
    vaultLinks: "vault_links",
  };

  private static readonly _ADMIN_STATE_FIELD_MAP_REVERSE: Record<string, string> =
    Object.fromEntries(Object.entries(NodeRuntime._ADMIN_STATE_FIELD_MAP).map(([k, v]) => [v, k]));

  private static _convertKeysDeep(value: unknown, map: Record<string, string>): unknown {
    if (Array.isArray(value)) return value.map((v) => NodeRuntime._convertKeysDeep(v, map));
    if (value !== null && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[map[k] ?? k] = NodeRuntime._convertKeysDeep(v, map);
      }
      return out;
    }
    return value;
  }

  private adminStateToWire(state: AdminState): Record<string, unknown> {
    return NodeRuntime._convertKeysDeep(state, NodeRuntime._ADMIN_STATE_FIELD_MAP) as Record<
      string,
      unknown
    >;
  }

  private adminStateFromWire(wire: unknown): AdminState | null {
    if (wire === null || typeof wire !== "object") return null;
    return NodeRuntime._convertKeysDeep(
      wire,
      NodeRuntime._ADMIN_STATE_FIELD_MAP_REVERSE,
    ) as unknown as AdminState;
  }

  // ---------------------------------------------------------------------------
  // .tnpkg export / absorb — lifted from TNClient (Task 2.12).
  // ---------------------------------------------------------------------------

  /** Pack a `.tnpkg` from local ceremony state. Mirrors Python `tn.export`. */
  exportPkg(opts: ExportPkgOptions, outPath: string): string {
    const { kind } = opts;
    if (!KNOWN_KINDS.has(kind as ManifestKind)) {
      throw new Error(
        `export: unknown kind ${JSON.stringify(kind)}; expected one of ` +
          JSON.stringify([...KNOWN_KINDS].sort()),
      );
    }
    if ((kind === "full_keystore" || kind === "project_seed") && !opts.confirmIncludesSecrets) {
      throw new Error(
        `export(kind='${kind}') writes the publisher's raw private keys. ` +
          "Pass confirmIncludesSecrets=true to acknowledge.",
      );
    }
    if (kind === "recipient_invite") {
      throw new Error(`export(kind=${JSON.stringify(kind)}) is reserved but not implemented yet.`);
    }

    let body: Record<string, Uint8Array> = {};
    const extras: {
      clock?: VectorClock;
      eventCount?: number;
      headRowHash?: string;
      state?: Record<string, unknown>;
      scope?: string;
    } = {};

    if (kind === "admin_log_snapshot") {
      const built = this._buildAdminLogSnapshotBody();
      body = built.body;
      extras.clock = built.clock;
      extras.eventCount = built.eventCount;
      if (built.headRowHash !== undefined) extras.headRowHash = built.headRowHash;
      extras.state = this.adminStateToWire(this.adminCache().state());
    } else if (kind === "offer" || kind === "enrolment") {
      if (!opts.packageBody) {
        throw new Error(`export(kind=${JSON.stringify(kind)}) requires packageBody=<bytes>.`);
      }
      body["body/package.json"] = opts.packageBody;
    } else if (kind === "kit_bundle" || kind === "full_keystore") {
      const built = this._buildKitBundleBody({
        full: kind === "full_keystore",
        groups: opts.groups,
      });
      body = built.body;
      extras.state = built.state;
      extras.scope = kind === "full_keystore" ? "full" : "kit_bundle";
    } else if (kind === "project_seed") {
      const built = this._buildProjectSeedBody({ groups: opts.groups });
      body = built.body;
      extras.state = built.state;
      extras.scope = "project";
    }

    const manifestArgs: {
      kind: ManifestKind | string;
      fromDid: string;
      ceremonyId: string;
      scope: string;
      toDid?: string;
    } = {
      kind,
      fromDid: this.config.device.device_identity,
      ceremonyId: this.config.ceremonyId,
      scope: opts.scope ?? extras.scope ?? _defaultScope(kind),
    };
    if (kind === "project_seed") {
      manifestArgs.toDid = this.config.device.device_identity;
    } else if (opts.toDid !== undefined) {
      manifestArgs.toDid = opts.toDid;
    }
    const manifest = newManifest(manifestArgs);
    if (extras.clock) manifest.clock = extras.clock;
    if (extras.eventCount !== undefined) manifest.eventCount = extras.eventCount;
    if (extras.headRowHash !== undefined) manifest.headRowHash = extras.headRowHash;
    if (extras.state !== undefined) manifest.state = extras.state;

    signManifest(manifest, this.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  /**
   * Export an AES-256-GCM-encrypted `full_keystore` tnpkg (BYOK / BEK).
   *
   * Mirrors Python's `export(kind="full_keystore", encrypt_body_with=bek)`
   * (the init-upload / pending-claim path, D-19 / D-5). The body files are
   * packed, AES-GCM-encrypted under `bek` into a single
   * `body/encrypted.bin` member, and the manifest's `state.body_encryption`
   * block records the cipher suite + frame + ciphertext hash so a consumer
   * can verify the blob without holding the key.
   *
   * The browser claim page (`static/claim/claim.js::decryptBody`) unzips
   * the outer tnpkg, pulls `body/encrypted.bin`, and AES-GCM-decrypts with
   * the BEK delivered in the claim URL fragment. The blob layout
   * (`nonce || ciphertext+tag`, empty AAD) is produced by
   * {@link encryptBodyBlob} and matches that consumer byte-for-byte.
   *
   * Async because `encryptBodyBlob` uses the WebCrypto SubtleCrypto API.
   *
   * @param bek - 32-byte AES-256 body encryption key (caller-minted).
   * @param outPath - where to write the `.tnpkg`.
   * @param opts - optional group filter (defaults to all groups).
   * @returns the written path.
   */
  async exportFullKeystoreEncrypted(
    bek: Uint8Array,
    outPath: string,
    opts: { groups?: string[] } = {},
  ): Promise<string> {
    if (bek.length !== 32) {
      throw new Error(
        `exportFullKeystoreEncrypted: bek must be 32 bytes (AES-256); got ${bek.length}`,
      );
    }
    const built = this._buildKitBundleBody({ full: true, groups: opts.groups });
    const encrypted = await encryptBodyBlob(built.body, bek);
    const ciphertextSha = "sha256:" + createHash("sha256").update(Buffer.from(encrypted)).digest("hex");

    // Replace the plaintext body members with the single encrypted blob and
    // merge the body_encryption descriptor into the existing state (which
    // carries the kit metadata). Mirrors Python `_encrypt_body_in_place`.
    const body: Record<string, Uint8Array> = { "body/encrypted.bin": encrypted };
    const state: Record<string, unknown> = {
      ...built.state,
      body_encryption: {
        cipher_suite: BODY_CIPHER_SUITE,
        nonce_bytes: 12,
        frame: BODY_FRAME,
        ciphertext_sha256: ciphertextSha,
      },
    };

    const manifest = newManifest({
      kind: "full_keystore",
      fromDid: this.config.device.device_identity,
      ceremonyId: this.config.ceremonyId,
      scope: "full",
    });
    manifest.state = state;
    signManifest(manifest, this.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  /** Apply a `.tnpkg` to local state. Idempotent. Mirrors Python `tn.absorb`. */
  absorbPkg(source: string | Uint8Array): AbsorbReceipt {
    let manifest: Manifest;
    let body: Map<string, Uint8Array>;
    try {
      const parsed = readTnpkg(source);
      manifest = parsed.manifest;
      body = parsed.body;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        kind: "unknown",
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `absorb: not a valid \`.tnpkg\` zip: ${msg}`,
      };
    }

    if (!isManifestSignatureValid(manifest)) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `manifest signature does not verify against from_did ` +
          `${JSON.stringify(manifest.fromDid)}. The package is corrupt, truncated, or tampered.`,
      };
    }

    const kind = manifest.kind;
    let receipt: AbsorbReceipt;
    if (kind === "admin_log_snapshot") {
      receipt = this._absorbAdminLogSnapshot(manifest, body);
    } else if (kind === "kit_bundle" || kind === "full_keystore") {
      receipt = this._absorbKitBundle(manifest, body);
    } else if (kind === "identity_seed") {
      receipt = this._absorbIdentitySeed(manifest, body);
    } else if (kind === "project_seed") {
      receipt = this._absorbProjectSeed(manifest, body);
    } else if (kind === "offer" || kind === "enrolment") {
      receipt = {
        kind,
        acceptedCount: body.has("body/package.json") ? 1 : 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
      };
    } else {
      receipt = {
        kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `absorb: unsupported manifest kind ${JSON.stringify(kind)}`,
      };
    }

    if (this._adminCache !== null) this._adminCache.refresh();
    return receipt;
  }

  /**
   * Mint kits for `recipientDid` across the specified groups and bundle them
   * into a `.tnpkg` at `outPath`. Returns the absolute path. Mirrors
   * TNClient.bundleForRecipient (avoids FINDINGS #5).
   */
  bundleForRecipient(
    recipientDid: string,
    outPath: string,
    opts: { groups?: string[] } = {},
  ): string {
    const cfg = this.config;
    let requested: string[];
    if (opts.groups === undefined) {
      requested = [...cfg.groups.keys()].filter((g) => g !== "tn.agents");
    } else {
      const seen = new Set<string>();
      requested = [];
      for (const g of opts.groups) {
        if (seen.has(g)) continue;
        seen.add(g);
        requested.push(g);
      }
    }
    if (requested.length === 0) {
      throw new Error("bundleForRecipient: no groups to bundle. Declare a regular group first.");
    }
    const unknown = requested.filter((g) => !cfg.groups.has(g));
    if (unknown.length > 0) {
      throw new Error(
        `bundleForRecipient: unknown groups ${JSON.stringify(unknown)}; ` +
          `this ceremony declares ${JSON.stringify([...cfg.groups.keys()].sort())}.`,
      );
    }

    const td = mkdtempSync(join(tmpdir(), "tn-bundle-"));
    try {
      for (const gname of requested) {
        const kitPath = join(td, `${gname}.btn.mykit`);
        this.addRecipient(gname, kitPath, recipientDid);
      }
      return this._buildAgentRuntimeBundle(outPath, td, requested, recipientDid);
    } finally {
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        // Best-effort tempdir cleanup.
      }
    }
  }

  /** Pack a kit_bundle `.tnpkg` from a directory of `*.btn.mykit` files. */
  private _buildAgentRuntimeBundle(
    outPath: string,
    kitsDir: string,
    groups: string[],
    runtimeDid: string,
  ): string {
    const body: Record<string, Uint8Array> = {};
    const kitsMeta: Array<{ name: string; sha256: string; bytes: number }> = [];
    for (const gname of [...groups].sort()) {
      const name = `${gname}.btn.mykit`;
      const p = join(kitsDir, name);
      if (!existsSync(p)) continue;
      const data = new Uint8Array(readFileSync(p));
      body[`body/${name}`] = data;
      kitsMeta.push({
        name,
        sha256: "sha256:" + createHash("sha256").update(Buffer.from(data)).digest("hex"),
        bytes: data.length,
      });
    }
    if (kitsMeta.length === 0) {
      throw new Error(`_buildAgentRuntimeBundle: no kits for groups ${JSON.stringify(groups)}`);
    }
    const manifest = newManifest({
      kind: "kit_bundle",
      fromDid: this.config.device.device_identity,
      ceremonyId: this.config.ceremonyId,
      scope: "kit_bundle",
      toDid: runtimeDid,
    });
    manifest.state = { kits: kitsMeta, kind: "readers-only" };
    signManifest(manifest, this.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  private _buildAdminLogSnapshotBody(): {
    body: Record<string, Uint8Array>;
    clock: VectorClock;
    eventCount: number;
    headRowHash: string | undefined;
  } {
    const seen = new Set<string>();
    const lines: string[] = [];
    const clock: VectorClock = {};
    let headRowHash: string | undefined;
    const main = this.config.logPath;
    const adminLog = resolveAdminLogPath(this.config);
    const sources = [main];
    if (adminLog !== main) sources.push(adminLog);

    for (const path of sources) {
      if (!existsSync(path)) continue;
      const text = readFileSync(path, "utf8");
      for (const rawLine of text.split(/\r?\n/)) {
        const stripped = rawLine.trim();
        if (!stripped) continue;
        let env: Record<string, unknown>;
        try {
          env = JSON.parse(stripped) as Record<string, unknown>;
        } catch {
          continue;
        }
        const et = env["event_type"];
        if (!isAdminEventType(et)) continue;
        const rh = env["row_hash"];
        if (typeof rh !== "string" || seen.has(rh)) continue;
        const did = env["device_identity"];
        const seq = env["sequence"];
        if (typeof did !== "string" || typeof seq !== "number") continue;
        seen.add(rh);
        lines.push(stripped);
        const slot = clock[did] ?? {};
        const cur = slot[et as string] ?? 0;
        if (seq > cur) slot[et as string] = seq;
        clock[did] = slot;
        headRowHash = rh;
      }
    }

    const body: Record<string, Uint8Array> = {
      "body/admin.ndjson": new TextEncoder().encode(
        lines.length > 0 ? lines.join("\n") + "\n" : "",
      ),
    };
    return { body, clock, eventCount: lines.length, headRowHash };
  }

  private _buildKitBundleBody(opts: { full: boolean; groups: string[] | undefined }): {
    body: Record<string, Uint8Array>;
    state: Record<string, unknown>;
  } {
    const keystore = this.config.keystorePath;
    if (!existsSync(keystore) || !statSync(keystore).isDirectory()) {
      throw new Error(`kit_bundle: keystore directory not found: ${keystore}`);
    }
    const groupFilter = opts.groups && opts.groups.length > 0 ? new Set(opts.groups) : null;
    const kitRe = /^(.+?)\.btn\.(mykit|mykit\.revoked\.\d+)$/;
    const body: Record<string, Uint8Array> = {};
    const kitsMeta: Array<{ name: string; sha256: string; bytes: number }> = [];

    for (const entry of readdirSync(keystore).sort()) {
      const m = kitRe.exec(entry);
      if (m) {
        const group = m[1]!;
        if (groupFilter && !groupFilter.has(group)) continue;
        const data = new Uint8Array(readFileSync(join(keystore, entry)));
        body[`body/${entry}`] = data;
        kitsMeta.push({
          name: entry,
          sha256: "sha256:" + createHash("sha256").update(Buffer.from(data)).digest("hex"),
          bytes: data.length,
        });
      } else if (opts.full) {
        if (entry === "local.private" || entry === "local.public" || entry === "index_master.key") {
          body[`body/${entry}`] = new Uint8Array(readFileSync(join(keystore, entry)));
        } else if (entry.endsWith(".btn.state")) {
          const group = entry.slice(0, -".btn.state".length);
          if (!groupFilter || groupFilter.has(group)) {
            body[`body/${entry}`] = new Uint8Array(readFileSync(join(keystore, entry)));
          }
        }
      }
    }

    if (kitsMeta.length === 0) {
      const suffix = groupFilter ? ` matching groups [${[...groupFilter].sort().join(", ")}]` : "";
      throw new Error(`kit_bundle: no *.btn.mykit files in ${keystore}${suffix}`);
    }

    if (opts.full) {
      const yamlPath = this.config.yamlPath;
      if (existsSync(yamlPath)) {
        body["body/tn.yaml"] = new Uint8Array(readFileSync(yamlPath));
      }
      body["body/WARNING_CONTAINS_PRIVATE_KEYS"] = new Uint8Array(0);
    }

    return {
      body,
      state: {
        kits: kitsMeta,
        kind: opts.full ? "full-keystore" : "readers-only",
      },
    };
  }

  private _buildProjectSeedBody(opts: { groups: string[] | undefined }): {
    body: Record<string, Uint8Array>;
    state: Record<string, unknown>;
  } {
    const keystore = this.config.keystorePath;
    if (!existsSync(keystore) || !statSync(keystore).isDirectory()) {
      throw new Error(`project_seed: keystore directory not found: ${keystore}`);
    }
    const yamlPath = this.config.yamlPath;
    if (!existsSync(yamlPath)) {
      throw new Error(`project_seed: yaml path does not exist: ${yamlPath}`);
    }

    const groupFilter = opts.groups && opts.groups.length > 0 ? new Set(opts.groups) : null;
    const keyRe = /^(.+?)\.btn\.(mykit|state)$/;
    const body: Record<string, Uint8Array> = {
      "body/tn.yaml": new Uint8Array(readFileSync(yamlPath)),
    };
    const keysMeta: string[] = [];

    for (const entry of readdirSync(keystore).sort()) {
      const p = join(keystore, entry);
      if (!statSync(p).isFile()) continue;
      if (entry === "local.private" || entry === "local.public" || entry === "index_master.key") {
        body[`body/keys/${entry}`] = new Uint8Array(readFileSync(p));
        keysMeta.push(entry);
        continue;
      }
      const m = keyRe.exec(entry);
      if (m) {
        const group = m[1]!;
        if (groupFilter && !groupFilter.has(group)) continue;
        body[`body/keys/${entry}`] = new Uint8Array(readFileSync(p));
        keysMeta.push(entry);
      }
    }

    for (const required of ["body/keys/local.private", "body/keys/local.public"]) {
      if (!(required in body)) {
        throw new Error(`project_seed: keystore is missing ${required.slice("body/keys/".length)}`);
      }
    }

    body["body/WARNING_CONTAINS_PRIVATE_KEYS"] = new Uint8Array(0);
    return {
      body,
      state: {
        project: {
          ceremony_id: this.config.ceremonyId,
          project_name: this.config.projectName,
          keys: keysMeta.slice().sort(),
        },
        kind: "project-seed",
      },
    };
  }

  private _absorbAdminLogSnapshot(
    manifest: Manifest,
    body: Map<string, Uint8Array>,
  ): AbsorbReceipt {
    const adminLog = resolveAdminLogPath(this.config);
    const localClock: VectorClock = {};
    const seenRowHashes = existingRowHashes(adminLog);
    if (existsSync(adminLog)) {
      for (const rawLine of readFileSync(adminLog, "utf8").split(/\r?\n/)) {
        const s = rawLine.trim();
        if (!s) continue;
        try {
          const env = JSON.parse(s) as Record<string, unknown>;
          const did = env["device_identity"];
          const et = env["event_type"];
          const seq = env["sequence"];
          if (typeof did === "string" && typeof et === "string" && typeof seq === "number") {
            const slot = localClock[did] ?? {};
            const cur = slot[et] ?? 0;
            if (seq > cur) slot[et] = seq;
            localClock[did] = slot;
          }
        } catch {
          /* skip */
        }
      }
    }

    if (clockDominates(localClock, manifest.clock)) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: true,
        derivedState: this.adminStateFromWire(manifest.state),
        conflicts: [],
      };
    }

    const raw = body.get("body/admin.ndjson");
    if (raw === undefined) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: "admin_log_snapshot body missing `body/admin.ndjson`",
      };
    }

    const revokedLeaves = new Map<string, string | null>();
    if (existsSync(adminLog)) {
      for (const rawLine of readFileSync(adminLog, "utf8").split(/\r?\n/)) {
        const s = rawLine.trim();
        if (!s) continue;
        try {
          const env = JSON.parse(s) as Record<string, unknown>;
          if (env["event_type"] === "tn.recipient.revoked") {
            const g = env["group"];
            const li = env["leaf_index"];
            const rh = env["row_hash"];
            if (typeof g === "string" && typeof li === "number") {
              revokedLeaves.set(`${g} ${li}`, typeof rh === "string" ? rh : null);
            }
          }
        } catch {
          /* skip */
        }
      }
    }

    const acceptedEnvs: Record<string, unknown>[] = [];
    const conflicts: ChainConflict[] = [];
    let deduped = 0;
    const text = new TextDecoder("utf-8").decode(raw);
    for (const rawLine of text.split(/\r?\n/)) {
      const s = rawLine.trim();
      if (!s) continue;
      let env: Record<string, unknown>;
      try {
        env = JSON.parse(s) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (!_envelopeWellFormed(env)) continue;
      if (!_verifyEnvelopeSignature(env)) continue;

      const rh = env["row_hash"];
      if (typeof rh !== "string") continue;
      if (seenRowHashes.has(rh)) {
        deduped += 1;
        continue;
      }

      if (env["event_type"] === "tn.recipient.added") {
        const g = env["group"];
        const li = env["leaf_index"];
        if (typeof g === "string" && typeof li === "number") {
          const k = `${g} ${li}`;
          if (revokedLeaves.has(k)) {
            const reuse: LeafReuseAttempt = {
              type: "leaf_reuse_attempt",
              group: g,
              leafIndex: li,
              attemptedRowHash: rh,
              originallyRevokedAtRowHash: revokedLeaves.get(k) ?? null,
            };
            conflicts.push(reuse);
          }
        }
      }
      if (env["event_type"] === "tn.recipient.revoked") {
        const g = env["group"];
        const li = env["leaf_index"];
        if (typeof g === "string" && typeof li === "number") {
          revokedLeaves.set(`${g} ${li}`, rh);
        }
      }
      acceptedEnvs.push(env);
      seenRowHashes.add(rh);
    }

    if (acceptedEnvs.length > 0) appendAdminEnvelopes(adminLog, acceptedEnvs);

    return {
      kind: manifest.kind,
      acceptedCount: acceptedEnvs.length,
      dedupedCount: deduped,
      noop: false,
      derivedState: (manifest.state as unknown as AdminState) ?? null,
      conflicts,
    };
  }

  /**
   * Count user-emitted entries in the local main log. A "user event"
   * is anything whose ``event_type`` does NOT start with ``tn.`` —
   * the ``tn.*`` namespace is reserved for admin / protocol bookkeeping
   * which the runtime emits at init time.
   *
   * Used by the bootstrap-kind handlers (`_absorbIdentitySeed`,
   * `_absorbProjectSeed`) to distinguish "fresh ceremony just minted"
   * from "real user activity already exists" when deciding whether
   * to overwrite an existing identity (Bug 3 in the 0.4.0a2 brief).
   */
  private _userEventCount(): number {
    // Walk the main log plus any rotated backups (.1, .2, ...). The
    // session-start rotation in `rotateLogOnSessionStart` moves the
    // previous session's content to `<logPath>.1`, so just looking at
    // `<logPath>` after a re-init undercounts.
    const candidates: string[] = [this.config.logPath];
    for (let n = 1; n <= 10; n += 1) {
      const p = `${this.config.logPath}.${n}`;
      if (!existsSync(p)) break;
      candidates.push(p);
    }
    let count = 0;
    for (const path of candidates) {
      if (!existsSync(path)) continue;
      try {
        for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/)) {
          const s = rawLine.trim();
          if (!s) continue;
          let env: Record<string, unknown>;
          try {
            env = JSON.parse(s) as Record<string, unknown>;
          } catch {
            continue;
          }
          const et = env["event_type"];
          if (typeof et === "string" && !et.startsWith("tn.")) count += 1;
        }
      } catch {
        continue;
      }
    }
    return count;
  }

  private _projectSeedVaultYamlPatch(
    existingYaml: Uint8Array,
    incomingYaml: Uint8Array,
  ): { patched?: Uint8Array; vaultOnly: boolean } {
    const nonEmpty = (value: unknown): string | undefined =>
      typeof value === "string" && value.trim() ? value.trim() : undefined;
    let existingDoc: Record<string, unknown>;
    let incomingDoc: Record<string, unknown>;
    try {
      existingDoc = (parseYaml(Buffer.from(existingYaml).toString("utf8")) as Record<string, unknown>) ?? {};
      incomingDoc = (parseYaml(Buffer.from(incomingYaml).toString("utf8")) as Record<string, unknown>) ?? {};
    } catch {
      return { vaultOnly: false };
    }
    if (typeof existingDoc !== "object" || typeof incomingDoc !== "object") {
      return { vaultOnly: false };
    }
    const existingVault = existingDoc["vault"] as Record<string, unknown> | undefined;
    const incomingVault = incomingDoc["vault"] as Record<string, unknown> | undefined;
    if (!existingVault || !incomingVault || typeof existingVault !== "object" || typeof incomingVault !== "object") {
      return { vaultOnly: false };
    }
    if (existingVault["enabled"] === false) return { vaultOnly: false };

    const patchedDoc = structuredClone(existingDoc);
    const patchedVault = patchedDoc["vault"] as Record<string, unknown>;
    let changed = false;
    for (const field of ["url", "linked_project_id"] as const) {
      if (!nonEmpty(patchedVault[field])) {
        const incomingValue = nonEmpty(incomingVault[field]);
        if (incomingValue) {
          patchedVault[field] = incomingValue;
          changed = true;
        }
      }
    }
    if (changed) {
      patchedVault["enabled"] = true;
      if (patchedVault["autosync"] === undefined) patchedVault["autosync"] = true;
      if (patchedVault["sync_interval_seconds"] === undefined) {
        patchedVault["sync_interval_seconds"] = incomingVault["sync_interval_seconds"] ?? 600;
      }
      const ceremony = patchedDoc["ceremony"] as Record<string, unknown> | undefined;
      const incomingCeremony = incomingDoc["ceremony"] as Record<string, unknown> | undefined;
      if (ceremony && incomingCeremony && typeof ceremony === "object" && typeof incomingCeremony === "object") {
        if (!nonEmpty(ceremony["linked_vault"])) {
          const incomingUrl = nonEmpty(incomingCeremony["linked_vault"]);
          if (incomingUrl) ceremony["linked_vault"] = incomingUrl;
        }
        if (!nonEmpty(ceremony["linked_project_id"])) {
          const incomingProjectId = nonEmpty(incomingCeremony["linked_project_id"]);
          if (incomingProjectId) ceremony["linked_project_id"] = incomingProjectId;
        }
      }
      const encoded = new TextEncoder().encode(stringifyYaml(patchedDoc));
      return Buffer.from(encoded).equals(Buffer.from(existingYaml))
        ? { vaultOnly: true }
        : { patched: encoded, vaultOnly: true };
    }

    const blankVaultMetadata = (doc: Record<string, unknown>): Record<string, unknown> => {
      const clone = structuredClone(doc);
      const vault = clone["vault"] as Record<string, unknown> | undefined;
      if (vault && typeof vault === "object") {
        vault["url"] = "";
        vault["linked_project_id"] = "";
      }
      const ceremony = clone["ceremony"] as Record<string, unknown> | undefined;
      if (ceremony && typeof ceremony === "object") {
        ceremony["linked_vault"] = "";
        ceremony["linked_project_id"] = "";
      }
      return clone;
    };
    return {
      vaultOnly:
        JSON.stringify(blankVaultMetadata(existingDoc)) ===
        JSON.stringify(blankVaultMetadata(incomingDoc)),
    };
  }

  /**
   * Install an identity_seed (`tn.export(kind="identity_seed")`)
   * bundle. Body shape:
   *
   *   body/local.private  — 32-byte Ed25519 seed
   *   body/local.public   — utf-8 did:key:z...
   *   body/tn.yaml        — minimal stub
   *
   * Mirrors Python's `_absorb_identity_seed`:
   * 1. Validates required body members.
   * 2. Cross-checks: manifest.fromDid == manifest.toDid;
   *    body/local.public == manifest.fromDid; the DID derived from
   *    body/local.private agrees with both. Catches a tampered body
   *    that swaps in a different key.
   * 3. Writes local.private + local.public + tn.yaml. Idempotent if
   *    bytes match. Refuses to overwrite an existing different
   *    identity unless `_userEventCount() === 0` (the dirt-easy
   *    "I just initialized empty" case — Bug 3).
   */
  private _absorbIdentitySeed(manifest: Manifest, body: Map<string, Uint8Array>): AbsorbReceipt {
    const priv = body.get("body/local.private");
    const pub = body.get("body/local.public");
    const yamlBytes = body.get("body/tn.yaml");
    const missing: string[] = [];
    if (priv === undefined) missing.push("body/local.private");
    if (pub === undefined) missing.push("body/local.public");
    if (yamlBytes === undefined) missing.push("body/tn.yaml");
    if (priv === undefined || pub === undefined || yamlBytes === undefined) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `identity_seed body is missing required members: ${JSON.stringify(missing)}`,
      };
    }

    if (priv.length !== 32) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `identity_seed body/local.private must be 32 bytes (Ed25519 seed); got ${priv.length}`,
      };
    }

    const derivedKey = DeviceKey.fromSeed(priv);
    const bundleDid = new TextDecoder("utf-8").decode(pub).trim();
    if (derivedKey.did !== bundleDid || derivedKey.did !== manifest.fromDid) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `identity_seed integrity check failed: manifest.fromDid=${JSON.stringify(manifest.fromDid)}, ` +
          `body/local.public=${JSON.stringify(bundleDid)}, derived-from-private=${JSON.stringify(derivedKey.did)}. ` +
          `The bundle's body and manifest disagree about which identity this is — refuse to install.`,
      };
    }
    if (manifest.fromDid !== manifest.toDid) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `identity_seed must be self-addressed (fromDid === toDid); ` +
          `got fromDid=${JSON.stringify(manifest.fromDid)}, toDid=${JSON.stringify(manifest.toDid)}.`,
      };
    }

    const keystore = this.config.keystorePath;
    if (!existsSync(keystore)) mkdirSync(keystore, { recursive: true });
    const privPath = pathResolve(keystore, "local.private");
    const pubPath = pathResolve(keystore, "local.public");
    const yamlTarget = this.config.yamlPath;
    const ts = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";

    if (existsSync(privPath)) {
      const existing = readFileSync(privPath);
      if (Buffer.from(existing).equals(Buffer.from(priv))) {
        return {
          kind: manifest.kind,
          acceptedCount: 0,
          dedupedCount: 0,
          noop: true,
          derivedState: null,
          conflicts: [],
        };
      }
      // Bug 3: differ + zero user events → fresh-ceremony, overwrite.
      if (this._userEventCount() === 0) {
        try {
          renameSync(privPath, pathResolve(keystore, `local.private.previous.${ts}`));
        } catch {
          /* best effort */
        }
        try {
          if (existsSync(pubPath)) {
            renameSync(pubPath, pathResolve(keystore, `local.public.previous.${ts}`));
          }
        } catch {
          /* best effort */
        }
      } else {
        return {
          kind: manifest.kind,
          acceptedCount: 0,
          dedupedCount: 0,
          noop: false,
          derivedState: null,
          conflicts: [],
          rejectedReason:
            `refusing to overwrite existing identity at ${privPath}. The keystore already ` +
            `has a different device key and the local log already contains user-emitted ` +
            `entries signed by it. To replace, delete the keystore directory first.`,
        };
      }
    }

    writeFileSync(privPath, Buffer.from(priv));
    writeFileSync(pubPath, bundleDid, "utf8");

    if (!existsSync(yamlTarget)) {
      mkdirSync(dirname(yamlTarget), { recursive: true });
      writeFileSync(yamlTarget, Buffer.from(yamlBytes));
    } else if (
      this._userEventCount() === 0 &&
      !Buffer.from(readFileSync(yamlTarget)).equals(Buffer.from(yamlBytes))
    ) {
      try {
        renameSync(yamlTarget, `${yamlTarget}.previous.${ts}`);
      } catch {
        /* best effort */
      }
      mkdirSync(dirname(yamlTarget), { recursive: true });
      writeFileSync(yamlTarget, Buffer.from(yamlBytes));
    }

    return {
      kind: manifest.kind,
      acceptedCount: 1,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
    };
  }

  /**
   * Install a project_seed bundle (dashboard "Create Project" flow).
   *
   * Body shape (nested under `body/keys/`, NOT flat under `body/`
   * like `kit_bundle`):
   *
   *   body/tn.yaml
   *   body/keys/local.private
   *   body/keys/local.public
   *   body/keys/index_master.key
   *   body/keys/<group>.btn.mykit
   *   body/keys/<group>.btn.state
   *
   * Mirrors Python's `_absorb_project_seed`. Same tamper guard as
   * identity_seed (manifest.fromDid == manifest.toDid; body's
   * local.public agrees; DID derived from body's local.private
   * agrees). Flat-only nesting under `body/keys/` — `body/keys/foo/bar`
   * is silently skipped.
   */
  private _absorbProjectSeed(manifest: Manifest, body: Map<string, Uint8Array>): AbsorbReceipt {
    const yamlBytes = body.get("body/tn.yaml");
    const priv = body.get("body/keys/local.private");
    const pub = body.get("body/keys/local.public");
    const missing: string[] = [];
    if (yamlBytes === undefined) missing.push("body/tn.yaml");
    if (priv === undefined) missing.push("body/keys/local.private");
    if (pub === undefined) missing.push("body/keys/local.public");
    if (yamlBytes === undefined || priv === undefined || pub === undefined) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `project_seed body is missing required members: ${JSON.stringify(missing)}`,
      };
    }

    if (priv.length !== 32) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `project_seed body/keys/local.private must be 32 bytes; got ${priv.length}`,
      };
    }

    const derivedKey = DeviceKey.fromSeed(priv);
    const bundleDid = new TextDecoder("utf-8").decode(pub).trim();
    if (derivedKey.did !== bundleDid || derivedKey.did !== manifest.fromDid) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `project_seed integrity check failed: manifest.fromDid=${JSON.stringify(manifest.fromDid)}, ` +
          `body/keys/local.public=${JSON.stringify(bundleDid)}, derived-from-private=${JSON.stringify(derivedKey.did)}.`,
      };
    }
    if (manifest.fromDid !== manifest.toDid) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `project_seed must be self-addressed (fromDid === toDid).`,
      };
    }

    let accepted = 0;
    let deduped = 0;
    const replaced: string[] = [];
    const ts = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";

    // Step A: tn.yaml.
    const yamlTarget = this.config.yamlPath;
    if (existsSync(yamlTarget)) {
      const existing = readFileSync(yamlTarget);
      if (Buffer.from(existing).equals(Buffer.from(yamlBytes))) {
        deduped += 1;
      } else {
        const patch = this._projectSeedVaultYamlPatch(existing, yamlBytes);
        if (patch.patched !== undefined) {
          writeFileSync(yamlTarget, Buffer.from(patch.patched));
          accepted += 1;
        } else if (patch.vaultOnly) {
          deduped += 1;
        } else if (this._userEventCount() === 0) {
          try {
            renameSync(yamlTarget, `${yamlTarget}.previous.${ts}`);
          } catch {
            /* best effort */
          }
          replaced.push(yamlTarget);
          mkdirSync(dirname(yamlTarget), { recursive: true });
          writeFileSync(yamlTarget, Buffer.from(yamlBytes));
          accepted += 1;
        } else {
          return {
            kind: manifest.kind,
            acceptedCount: 0,
            dedupedCount: 0,
            noop: false,
            derivedState: null,
            conflicts: [],
            rejectedReason:
              `refusing to overwrite existing tn.yaml at ${yamlTarget}: contents differ and the local ` +
              `log already contains user-emitted entries.`,
          };
        }
      }
    } else {
      mkdirSync(dirname(yamlTarget), { recursive: true });
      writeFileSync(yamlTarget, Buffer.from(yamlBytes));
      accepted += 1;
    }

    // Step B: keys.
    const keystore = this.config.keystorePath;
    if (!existsSync(keystore)) mkdirSync(keystore, { recursive: true });

    // Existing local.private guard.
    const existingPriv = pathResolve(keystore, "local.private");
    if (existsSync(existingPriv)) {
      const existingBytes = readFileSync(existingPriv);
      if (!Buffer.from(existingBytes).equals(Buffer.from(priv)) && this._userEventCount() > 0) {
        return {
          kind: manifest.kind,
          acceptedCount: 0,
          dedupedCount: 0,
          noop: false,
          derivedState: null,
          conflicts: [],
          rejectedReason:
            `refusing to overwrite existing identity at ${existingPriv}: a different device key is ` +
            `already installed and the local log contains user events signed by it.`,
        };
      }
    }

    for (const [name, data] of body) {
      if (!name.startsWith("body/keys/")) continue;
      const rel = name.slice("body/keys/".length);
      if (!rel) continue;
      if (rel.includes("/") || rel.includes("\\")) continue; // flat only
      const dest = pathResolve(keystore, rel);
      if (existsSync(dest)) {
        const existing = readFileSync(dest);
        if (Buffer.from(existing).equals(Buffer.from(data))) {
          deduped += 1;
          continue;
        }
        try {
          renameSync(dest, pathResolve(keystore, `${rel}.previous.${ts}`));
        } catch {
          /* best effort */
        }
        replaced.push(dest);
      }
      writeFileSync(dest, Buffer.from(data));
      accepted += 1;
    }

    return {
      kind: manifest.kind,
      acceptedCount: accepted,
      dedupedCount: deduped,
      noop: false,
      derivedState: null,
      conflicts: [],
      replacedKitPaths: replaced,
    };
  }

  private _absorbKitBundle(manifest: Manifest, body: Map<string, Uint8Array>): AbsorbReceipt {
    const keystore = this.config.keystorePath;
    if (!existsSync(keystore)) mkdirSync(keystore, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";
    let accepted = 0;
    let skipped = 0;
    const replaced: string[] = [];
    for (const [name, data] of body) {
      if (!name.startsWith("body/")) continue;
      const rel = name.slice("body/".length);
      if (!rel) continue;
      if (rel.includes("/") || rel.includes("\\")) continue;
      const dest = pathResolve(keystore, rel);
      if (existsSync(dest)) {
        const existing = readFileSync(dest);
        if (existing.length === data.length && Buffer.from(existing).equals(Buffer.from(data))) {
          skipped += 1;
          continue;
        }
        const backup = pathResolve(keystore, `${rel}.previous.${ts}`);
        renameSync(dest, backup);
        replaced.push(dest);
      }
      writeFileSync(dest, Buffer.from(data));
      accepted += 1;
    }
    return {
      kind: manifest.kind,
      acceptedCount: accepted,
      dedupedCount: skipped,
      noop: false,
      derivedState: null,
      conflicts: [],
      replacedKitPaths: replaced,
    };
  }

  // ---------------------------------------------------------------------------

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
        const did = env.recipient_identity as string | undefined;
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
   *
   * When the caller does not pass an explicit `logPath`, the runtime
   * merges the main log + the admin log (when distinct) and yields
   * entries in timestamp order. This matches Python's `tn.read` /
   * Rust's "read both logs" surface so `tn.*` events (which the Rust
   * core routes to the admin log) are visible to TS readers.
   *
   * When `logPath` is supplied explicitly, only that file is walked
   * (preserves the existing `read(path)` contract for cross-publisher
   * reads where the caller chose the file).
   */
  *read(logPath?: string): Generator<ReadEntry, void, void> {
    // Source lines (with origin path for error messages). Single-path
    // when the caller specified one, otherwise main+admin merged.
    type SourceLine = { path: string; lineno: number; line: string; ts: string };
    const sources: SourceLine[] = [];
    const collect = (path: string): void => {
      if (!existsSync(path)) return;
      const text = readFileSync(path, "utf8");
      let lineno = 0;
      for (const rawLine of text.split(/\r?\n/)) {
        lineno += 1;
        if (!rawLine) continue;
        // Extract timestamp for stable cross-file ordering without
        // re-parsing twice — JSON.parse below will re-validate.
        let ts = "";
        try {
          const env = JSON.parse(rawLine) as Record<string, unknown>;
          const t = env["timestamp"];
          if (typeof t === "string") ts = t;
        } catch {
          // Leave ts = "" so the line sorts to the front and the main
          // loop below surfaces the JSON parse error with the correct
          // path:lineno (matches the prior single-file behavior).
        }
        sources.push({ path, lineno, line: rawLine, ts });
      }
    };

    if (logPath !== undefined) {
      // A templated `log` (e.g. `./logs/{event_id}.ndjson`) glob-expands
      // to every rendered file and merges them — symmetric with the
      // write side that fanned them out. Non-templated paths collect
      // the single file as before.
      if (hasTemplateTokens(logPath)) {
        const yamlDir = dirname(this.config.yamlPath);
        for (const f of expandTemplatedLogPath(logPath, yamlDir)) collect(f);
      } else {
        collect(logPath);
      }
    } else {
      collect(this.config.logPath);
      const adminPath = resolveAdminLogPath(this.config);
      if (adminPath !== this.config.logPath) collect(adminPath);
    }

    // Stable sort by timestamp. Lines from the same file retain their
    // original order (so chain-continuity per event_type still walks
    // forward).
    sources.sort((a, b) => a.ts.localeCompare(b.ts));

    const prevHashByType = new Map<string, RowHash>();

    for (const src of sources) {
      const { path, lineno, line: rawLine } = src;
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
      const envPrevHash = String(env["prev_hash"] ?? ZERO_HASH());
      const envRowHash = String(env["row_hash"] ?? "");
      const envSig = String(env["signature"] ?? "");
      const envDid = String(env["device_identity"] ?? "");
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
          device_identity: asDid(envDid),
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

  /**
   * Parse a single ndjson line into a ReadEntry without chain-continuity
   * tracking. Returns null when the line is empty or malformed JSON.
   *
   * Used by tn.watch to decode incremental tail bytes without re-reading
   * the full log. The `verify` option controls whether signature and
   * row_hash checks are applied (the validity flags are always populated;
   * `verify` only controls whether a failed check surfaces a warning).
   */
  parseEnvelopeLine(line: string, opts: { verify: boolean }): ReadEntry | null {
    const trimmed = line.trim();
    if (!trimmed) return null;
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      return null;
    }

    const eventType = String(env["event_type"] ?? "");
    const envPrevHash = String(env["prev_hash"] ?? ZERO_HASH);
    const envRowHash = String(env["row_hash"] ?? "");
    const envSig = String(env["signature"] ?? "");
    const envDid = String(env["device_identity"] ?? "");
    const envTs = String(env["timestamp"] ?? "");
    const envEventId = String(env["event_id"] ?? "");
    const envLevel = String(env["level"] ?? "");

    // Chain continuity is unknown for a single out-of-context line.
    const chainOk = true;

    // Identify group payloads in the envelope.
    const groupRaw = new Map<string, { ct: Uint8Array; fieldHashes: Record<string, string> }>();
    for (const [k, v] of Object.entries(env)) {
      if (isGroupPayload(v)) {
        const ct = new Uint8Array(Buffer.from(v.ciphertext, "base64"));
        const fh =
          ((v as Record<string, unknown>)["field_hashes"] as Record<string, string> | undefined) ??
          ((v as Record<string, unknown>)["fieldHashes"] as Record<string, string> | undefined) ??
          {};
        groupRaw.set(k, { ct, fieldHashes: fh });
      }
    }

    // Public fields.
    const publicFields: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(env)) {
      if (!_ENVELOPE_RESERVED.has(k) && !groupRaw.has(k) && this.config.publicFields.has(k)) {
        publicFields[k] = v;
      }
    }

    // Recompute row_hash.
    const groupsForHash: Record<string, import("../core/types.js").GroupHashInput> = {};
    for (const [gname, g] of groupRaw) {
      groupsForHash[gname] = { ciphertext: g.ct, fieldHashes: g.fieldHashes };
    }
    let rowHashOk: boolean;
    try {
      const recomputed = rowHash({
          device_identity: asDid(envDid),
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

    // Signature verification.
    let sigOk: boolean;
    if (opts.verify) {
      try {
        const sig = signatureFromB64(asSignatureB64(envSig));
        sigOk = verify(asDid(envDid), new Uint8Array(Buffer.from(envRowHash, "utf8")), sig);
      } catch {
        sigOk = false;
      }
    } else {
      sigOk = true;
    }

    // Decrypt each group we hold kits for.
    const plaintext: Record<string, Record<string, unknown>> = {};
    for (const [gname, g] of groupRaw) {
      const gk = this.keystore.groups.get(gname);
      const gcfg = this.config.groups.get(gname);
      const cipherKind = (gcfg?.cipher ?? "btn") as "btn" | "jwe";
      const kits: GroupKits = { cipher: cipherKind, kits: gk?.kits ?? [] };
      plaintext[gname] = decryptGroup({ ct: g.ct }, kits) as Record<string, unknown>;
    }

    return {
      envelope: env,
      plaintext,
      valid: { signature: sigOk, rowHash: rowHashOk, chain: chainOk },
    };
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
function rotateLogOnSessionStart(logPath: string, handlers: Array<Record<string, unknown>>): void {
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

// ---------------------------------------------------------------------------
// ExportPkgOptions — public type for NodeRuntime.exportPkg
// ---------------------------------------------------------------------------

export interface ExportPkgOptions {
  kind: ManifestKind;
  toDid?: string;
  scope?: string;
  confirmIncludesSecrets?: boolean;
  groups?: string[];
  packageBody?: Uint8Array;
}

// ---------------------------------------------------------------------------
// Local helpers for exportPkg / absorbPkg
// ---------------------------------------------------------------------------

function _defaultScope(kind: ManifestKind | string): string {
  switch (kind) {
    case "admin_log_snapshot":
      return "admin";
    case "kit_bundle":
      return "kit_bundle";
    case "full_keystore":
      return "full";
    case "project_seed":
      return "project";
    default:
      return "admin";
  }
}

function _envelopeWellFormed(env: Record<string, unknown>): boolean {
  for (const k of [
    "device_identity",
    "timestamp",
    "event_id",
    "event_type",
    "row_hash",
    "signature",
  ]) {
    if (typeof env[k] !== "string") return false;
  }
  return true;
}

function _verifyEnvelopeSignature(env: Record<string, unknown>): boolean {
  try {
    const did = String(env["device_identity"]);
    const rh = String(env["row_hash"]);
    const sigB64 = String(env["signature"]);
    const sig = signatureFromB64(asSignatureB64(sigB64));
    return verify(asDid(did), new Uint8Array(Buffer.from(rh, "utf8")), sig);
  } catch {
    return false;
  }
}

/**
 * Create a fresh btn ceremony at `yamlPath`. Matches Python's
 * `create_fresh` in shape: generates device key, btn publisher,
 * self-kit, index master; writes tn.yaml + .tn/keys/*; refuses to
 * clobber an existing keystore.
 */
export interface CreateFreshOptions {
  /** Explicit keystore directory. Overrides the stem-derived default
   *  (``./.tn/<stem>/keys`` relative to the yaml). Used by the multi-
   *  ceremony layout to point at a flat ``.tn/<name>/keys`` instead. */
  keystoreDir?: string;
  /** Explicit log file path. Overrides the stem-derived default
   *  (``./.tn/<stem>/logs/tn.ndjson``). */
  logPath?: string;
  /** Explicit admin log path. Overrides the stem-derived default. */
  adminLogPath?: string;
  /** Optional ``ceremony.profile`` to stamp into the freshly-written
   *  yaml. Mirrors Python's profile catalog. */
  profile?: string;
  /** Optional ``ceremony.project_name`` — the operator-chosen project
   *  label. The vault uses it to name the bound project (instead of the
   *  random ceremony_id) when this ceremony links/claims. Mirrors
   *  Python's `_stamp_project_labels`. */
  projectName?: string;
  /** Optional 32-byte Ed25519 seed. If set, the ceremony binds to
   *  that key (so the DID written into tn.yaml matches a previously
   *  installed identity). If omitted, a fresh random seed is generated.
   *  Used by the dirt-easy ``identity_seed`` bootstrap path: the
   *  caller has the absorbed device key and wants to mint a real
   *  ceremony around it. */
  devicePrivateBytes?: Uint8Array;
}

export function createFreshCeremony(yamlPath: string, opts: CreateFreshOptions = {}): void {
  const yamlDir = dirname(yamlPath);
  // Namespace .tn/ by yaml stem so two yamls in the same directory don't
  // collide on the same keys/logs/admin paths (FINDINGS #2 — Python parity).
  // Stem == basename without the trailing .yaml/.yml.
  const yamlBasename = yamlPath.split(/[\\/]/).pop() ?? "tn.yaml";
  const yamlStem = yamlBasename.replace(/\.ya?ml$/i, "");
  const keysDir = opts.keystoreDir ?? join(yamlDir, ".tn", yamlStem, "keys");
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

  // Ed25519 device seed: caller-supplied (identity_seed bootstrap path)
  // or freshly minted.
  let seed: Uint8Array;
  if (opts.devicePrivateBytes !== undefined) {
    if (opts.devicePrivateBytes.length !== 32) {
      throw new Error(
        `createFreshCeremony: devicePrivateBytes must be 32 bytes ` +
          `(Ed25519 seed); got ${opts.devicePrivateBytes.length}`,
      );
    }
    seed = new Uint8Array(opts.devicePrivateBytes);
  } else {
    seed = new Uint8Array(randomBytes(32));
  }
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

  // Resolve all four path slots. When opts override the stem-
  // derived defaults, write the override paths into the yaml as
  // *relative* (rooted at yamlDir) so the on-disk record stays
  // portable.
  function rel(absOrRel: string, fallback: string): string {
    if (!absOrRel) return fallback;
    const target = absOrRel;
    // Already relative-looking: pass through, normalizing separators.
    if (!target.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(target)) {
      const norm = target.replace(/\\/g, "/");
      return norm.startsWith("./") ? norm : `./${norm}`;
    }
    // Absolute input: relativize against yamlDir. On Windows this can return
    // an absolute drive-letter path (cross-drive), because path.relative does
    // NOT throw across drives; it returns the absolute target. A drive-letter,
    // UNC, or POSIX-absolute result must never be serialized into yaml; it is
    // machine-local and leaks the author's filesystem layout.
    const r = relative(yamlDir, target).replace(/\\/g, "/");
    if (r === "") return "./";
    if (/^[A-Za-z]:[\\/]/.test(r) || r.startsWith("/") || r.startsWith("//")) {
      throw new Error(
        `createFreshCeremony: cannot write a portable yaml path for ${JSON.stringify(target)} ` +
          `relative to ceremony dir ${JSON.stringify(yamlDir)} (different drive or volume). ` +
          `Place the keystore/log/admin path on the same drive as the ceremony yaml, ` +
          `or pass a path relative to it.`,
      );
    }
    return `./${r}`;
  }
  const _keystorePathStr = opts.keystoreDir
    ? rel(opts.keystoreDir, `./.tn/${yamlStem}/keys`)
    : `./.tn/${yamlStem}/keys`;
  const _logPathStr = opts.logPath
    ? rel(opts.logPath, `./.tn/${yamlStem}/logs/tn.ndjson`)
    : `./.tn/${yamlStem}/logs/tn.ndjson`;
  const _adminLogStr = opts.adminLogPath
    ? rel(opts.adminLogPath, `./.tn/${yamlStem}/admin/admin.ndjson`)
    : `./.tn/${yamlStem}/admin/admin.ndjson`;
  const _profileLine = opts.profile ? `\n  profile: ${opts.profile}` : "";
  const _projectNameLine = opts.projectName ? `\n  project_name: ${opts.projectName}` : "";
  // Derive the chain flag from the profile catalog so the Rust/wasm core
  // honours it (secure_log / telemetry -> chains=false). An absent or
  // unknown profile keeps the conservative default (transaction chains).
  // Mirrors python/tn/_multi.py:_stamp_profile_into_yaml.
  const _chains =
    opts.profile && isKnownProfile(opts.profile) ? getProfile(opts.profile).chains : true;

  // Write the yaml. Public fields list covers both the business
  // defaults and the entire admin-catalog field set so catalog events
  // never land in a group ciphertext by accident. Mirrors the
  // Python DEFAULT_PUBLIC_FIELDS set.
  const yaml = `ceremony:
  id: ${cid}
  mode: local
  linked_vault: ''
  linked_project_id: ''
  sync_logs: false
  cipher: btn
  sign: true${_profileLine}
  admin_log_location: ${_adminLogStr}
  log_level: debug
  chain: ${_chains}${_projectNameLine}
vault:
  enabled: true
  url: ${DEFAULT_VAULT_URL}
  linked_project_id: ''
  autosync: true
  sync_interval_seconds: 600
logs:
  path: ${_logPathStr}
keystore:
  path: ${_keystorePathStr}
handlers:
- kind: file.rotating
  name: main
  path: ${_logPathStr}
  max_bytes: 5242880
  backup_count: 5
  # Match Python's default: do NOT rotate on every init. Rotation
  # mid-process when max_bytes is reached is fine (it picks up where
  # it left off), but rotating at session-start breaks the admin
  # cache for short-lived CLI processes that each open a fresh
  # runtime — every invocation would shove the canonical log to
  # .ndjson.1 and the cache (which only scans the canonical path)
  # would observe an empty log.
  rotate_on_init: false
- kind: stdout
device:
  device_identity: ${dk.did}
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
- device_identity
- created_at
- group
- publisher_identity
- added_at
- leaf_index
- recipient_identity
- kit_sha256
- slot
- issued_to
- generation
- previous_kit_sha256
- old_pool_size
- new_pool_size
- rotated_at
- peer_identity
- package_sha256
- compiled_at
- absorbed_at
- vault_identity
- project_id
- linked_at
- reason
- unlinked_at
- policy_uri
- content_hash
- event_types_covered
- policy_text
- envelope_event_id
- envelope_device_identity
- envelope_event_type
- envelope_sequence
- invalid_reasons
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
  tn.agents:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
    fields:
    - instruction
    - use_for
    - do_not_use_for
    - consequences
    - on_violation_or_error
    - policy
    auto_populated_by_policy: true
fields: {}
llm_classifier:
  enabled: false
  provider: ''
  model: ''
`;
  writeFileSync(yamlPath, yaml, "utf8");
}
