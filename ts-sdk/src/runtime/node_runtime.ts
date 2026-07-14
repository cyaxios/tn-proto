// Node-only runtime: loads a yaml + keystore from disk, seeds chain
// state from any existing log, and exposes emit()/emitAsync() + read()/readAsync()
// that match the Python tn.logger flow byte-for-byte (modulo the random CEK/nonce
// inside each ciphertext).
//
// All three ciphers are first-class. btn runs through the complete wasm Rust
// runtime; hibe uses the TS ceremony adapter; jwe cryptography runs through
// the synchronous Rust/WASM bridge from both the sync and async verb surfaces.

// tn-wasm is loaded LAZILY (see `loadWasm()` below), not via a static
// side-effect import. The nodejs target self-instantiates its .wasm at
// require time, and that can throw — missing .wasm after a serverless
// bundle, no `fs` on an edge runtime, an init panic. A throw at module
// load is unrecoverable and takes down the host process. Deferring the
// require into a guarded loader means an unavailable logger degrades
// gracefully instead of crashing the program that imported us
// (architectural law: the SDK never crashes user space).

import {
  appendFileSync,
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
import { createHash, randomBytes, randomUUID } from "node:crypto";

import { DeviceKey } from "../core/signing.js";

import { loadPolicyFile, type PolicyDocument } from "../agents_policy.js";
import {
  KNOWN_KINDS,
  clockDominates,
  reuseIsInformed,
  isManifestSignatureValid,
  newManifest,
  nowIsoMillis,
  signManifestWithBody,
  type Manifest,
  type ManifestKind,
  type VectorClock,
} from "../core/tnpkg.js";
import { readTnpkg, readTnpkgVerified, writeTnpkg } from "../tnpkg_io.js";
import { encryptBodyBlob, BODY_CIPHER_SUITE, BODY_FRAME } from "../core/body_encryption.js";
import {
  sealBundleForRecipient,
  recipientKeyIsResolvable,
  absorbSealedKitBundle,
} from "../seal_bundle_producer.js";
import {
  appendAdminEnvelopes,
  existingRowHashes,
  isAdminEventType,
  resolveAdminLogPath,
} from "../admin/log.js";
import { BtnPublisher, btnKitLeaf, canonicalBytes, computeRowHash } from "../raw.js";
import { ensureProcessRunId } from "../_run_id.js";
import {
  aadBytesFor,
  decryptGroup,
  decryptGroupAsync,
  type CipherKind,
  type GroupKits,
} from "../core/decrypt.js";
import { jweSeal, jweSealSync } from "../core/jwe.js";
import { buildEnvelopeLine } from "../core/envelope.js";
import {
  createJweGroup,
  jweAddRecipient,
  jweRevokeRecipient,
  jweRotateGroup,
  type JweRecipientTrust,
} from "./jwe_group.js";
import { deriveGroupKey, indexTokenFor } from "../core/indexing.js";
import {
  createHibeGroup,
  hibeBumpPath,
  hibeCandidateKeys,
  hibeEncrypt,
  hibeGroupMpkMaxDepth,
  hibeAuthorityEpoch,
  hibeMintReaderKey,
  hibeRotateIdPath,
  loadHibeGroup,
  loadPinnedHibeAuthority,
  pinHibeAuthority,
  type HibeGroupMaterial,
} from "./hibe_group.js";
import {
  EnrollmentStore,
  UNSAFE_OPERATION_EVENT_TYPE,
  enrollmentCeremonyFromConfig,
  installEnrollmentResponse,
  recordVerifiedKitBundlePublisher,
} from "./enrollment.js";
import { reconcileTrustedOffers } from "./reconcile.js";
import {
  TrustError,
  formatTrustTimestamp,
  parseKeyBindingProof,
  sha256Digest,
  signKeyBindingProof,
  verifyKeyBindingProof,
  type EnrollmentChallengeV1,
  type KeyBindingProofV1,
} from "../core/trust.js";
import { parseTnPackage, verifyTnPackageSignature, type TnPackage } from "../core/tnpkg.js";
import {
  canonicalUnsafeOperationPayload,
  normalizeUnsafeOperationNotice,
  type UnsafeOperationNotice,
} from "../core/unsafe_operation.js";
import { getProfile, isKnownProfile } from "../profiles.js";
import { DEFAULT_VAULT_URL } from "../vault/url.js";
import type { TNHandler } from "../handlers/index.js";

function readKitLeaf(kitBytes: Uint8Array): bigint {
  return btnKitLeaf(kitBytes);
}

function packageArtifactDigest(source: string | Uint8Array): string {
  const bytes = typeof source === "string" ? new Uint8Array(readFileSync(source)) : source;
  return sha256Digest(bytes);
}
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { ZERO_HASH, rowHash, sha256HexBytes, verifyChainLink } from "../core/chain.js";
import { signatureB64, signatureFromB64, verify } from "../core/signing.js";
import { asDid, asRowHash, asSignatureB64 } from "../core/types.js";
import {
  authoritativeYamlFor,
  loadConfig,
  type CeremonyConfig,
  type GroupConfig,
} from "./config.js";
import { commitGroupKeys, loadJweKeys, loadKeystore, type LoadedKeystore } from "./keystore.js";
import { scanAttestedEventRecords, yamlRecipientDids } from "./reconcile.js";
import { createRequire } from "node:module";
import type { WasmRuntime } from "tn-wasm";
import { nodeStorageAdapter } from "./storage_node.js";
import { lastEmitReceipt, receiptFromLine } from "./wasm_shim.js";
import {
  atomicWriteKitMember,
  kitBundleInstallRejection,
  kitMemberIsSecret,
} from "./kit_bundle_members.js";

// ── tn-wasm lazy loader (SDK never crashes user space) ──────────────────────
// The nodejs-target tn-wasm module self-instantiates its .wasm on require,
// which can throw (missing .wasm after a serverless bundle, no `fs` on edge,
// an init panic). Defer the require to first use and contain any failure, so
// importing tn-proto never crashes the host and a wasm-load failure degrades
// to "logging disabled" rather than aborting the process.
// Cache the instantiated wasm module on a process-global slot (Symbol.for) so a
// dev-server hot-reload — which re-evaluates this module and resets its
// module-local state — reuses the existing instance instead of re-instantiating
// the .wasm. Repeated re-instantiation on every reload is what pressured the
// Vercel dev server; one instance per process removes that.
const WASM_SLOT = Symbol.for("cyaxios.tn-proto.wasm-module");
// Self-heal policy for the wasm logger: re-init after a transient fault, bounded
// so a permanent fault doesn't thrash on every log call. Tuned for serverless
// (Vercel) where cold starts / one-off aborts are the faults worth retrying.
const WASM_MAX_REINIT = 3; // consecutive immediate re-inits before backing off
const WASM_COOLDOWN_MS = 30_000; // back-off window, then one retry (warm-instance self-heal)
let _wasmFailureSurfaced = false;

/** Report a contained logger failure once per process, without throwing. */
function surfaceWasmFailure(phase: string, err: unknown): void {
  if (_wasmFailureSurfaced) return;
  _wasmFailureSurfaced = true;
  const msg = err instanceof Error ? err.message : String(err);
  process.emitWarning(`tn-proto logging disabled — tn-wasm ${phase} failed: ${msg}`);
}

/** Load the tn-wasm module lazily, at most once. Returns null (never throws)
 *  when the wasm core is unavailable, so the log path can no-op safely. */
function loadWasm(): typeof import("tn-wasm") | null {
  const g = globalThis as Record<symbol, unknown>;
  const cached = g[WASM_SLOT] as typeof import("tn-wasm") | undefined;
  if (cached) return cached;
  try {
    const req = createRequire(import.meta.url);
    const mod = req("tn-wasm") as typeof import("tn-wasm");
    g[WASM_SLOT] = mod;
    return mod;
  } catch (err) {
    // Not latched: a later call retries (the per-runtime back-off bounds the
    // frequency), so a transient cold-start load glitch can recover.
    surfaceWasmFailure("load", err);
    return null;
  }
}

/** True when a wasm-boundary error is an INFRASTRUCTURE failure — the core is
 *  unavailable, failed to initialize, or trapped/panicked — versus an
 *  application error (e.g. schema validation on a malformed event). Infra
 *  failures are contained so the host process never crashes (SDK never crashes
 *  user space); application errors propagate so callers can handle them and a
 *  real data bug is never silently swallowed. */
function isWasmInfraFailure(err: unknown): boolean {
  const e = err as { name?: unknown; message?: unknown } | null | undefined;
  // A wasm trap (Rust panic→abort / unreachable) is a WebAssembly.RuntimeError,
  // whose `.name` is "RuntimeError". Keyed by name to avoid referencing the
  // WebAssembly global type (not in this file's TS lib).
  if (e?.name === "RuntimeError") return true;
  const msg = typeof e?.message === "string" ? e.message : String(err);
  return (
    /tn-wasm is unavailable/.test(msg) || // loadWasm() sentinel (edge/serverless)
    /failed to initialize WasmRuntime/.test(msg) || // attachWasm() init failure
    /\b(unreachable|wasm trap|rust panic|panicked|RuntimeError)\b/i.test(msg)
  );
}
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
// 0.4.3a1: wire key flipped from `did` to `device_identity` so the
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

import type { AbsorbReceipt, EmitReceipt, RotateGroupResult } from "../core/results.js";
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
        "^" +
          seg
            .replace(/[.+^${}()|[\]\\]/g, "\\$&")
            .replace(/\*/g, ".*")
            .replace(/\?/g, ".") +
          "$",
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

/** Own-property read of a parsed-yaml mapping. A bare `map[name]` read on a
 *  plain object resolves inherited Object.prototype members when no own key
 *  exists, so a group named "toString" or "constructor" reads as a Function —
 *  truthy and non-nullish — and a `??=` / `if (!...)` guard then mutates the
 *  shared prototype member instead of the document while the real block is
 *  never written. Python dict keys have no such collision, so yaml authored
 *  there can carry these names; treat only own keys as present. */
function ownEntry<T>(map: Record<string, T>, name: string): T | undefined {
  return Object.hasOwn(map, name) ? map[name] : undefined;
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
  /** Self-heal bookkeeping for the wasm logger. `_wasmFailures` counts
   *  consecutive contained failures (drives the re-init cap); while
   *  `_wasmRetryAfter` is in the future the logger is backing off and emits
   *  fail fast (no re-init thrash). A successful emit clears both. */
  private _wasmFailures = 0;
  private _wasmRetryAfter = 0;
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
      if (g.stateBytes === undefined) continue; // hibe-only or reader-only group
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
  static init(yamlPath: string, opts: { cipher?: "btn" | "hibe" | "jwe" } = {}): NodeRuntime {
    if (!existsSync(yamlPath)) {
      const freshOpts: CreateFreshOptions = {};
      if (opts.cipher !== undefined) freshOpts.cipher = opts.cipher;
      createFreshCeremony(yamlPath, freshOpts);
    }
    const config = loadConfig(yamlPath);
    for (const [name, g] of config.groups) {
      if (g.cipher !== "btn" && g.cipher !== "hibe" && g.cipher !== "jwe") {
        throw new Error(`group ${name} uses an unknown cipher ${g.cipher}.`);
      }
    }
    // btn is the default cipher; hibe and jwe are first-class options. jwe
    // seal/open operations run through the synchronous Rust/WASM bridge.
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
    // instantiated on first wasm-routed use via `rt.attachWasm()`.
    // Eager attachment would let `WasmRuntime.init` emit its own
    // bookkeeping before TS-side init/reconcile finishes, which can
    // double-attest ceremony/admin events. Public emits attach lazily;
    // read decoding and init reconciliation remain TS-owned here.
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

  /**
   * The default Node BTN runtime has no TS emit fallback: public emit
   * verbs attach `WasmRuntime` lazily and then execute in Rust/WASM.
   * Read decoding is still implemented in this wrapper.
   */
  usingRust(): boolean {
    return true;
  }

  /** Append one log entry. Routes through `WasmRuntime.emit` so the
   *  full envelope build / sign / chain / write happens inside the
   *  Rust core. The TS-side `emitInternal` is dead (kept only until
   *  the slim-down deletion pass lands). See `_emitViaWasm` below. */
  emit(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    aad?: Record<string, unknown> | null,
  ): EmitReceipt {
    return this._emitViaWasm(level, eventType, fields, undefined, undefined, undefined, aad);
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
    aadOverride?: Record<string, unknown> | null,
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
      signOverride !== undefined && signOverride !== null ? signOverride : _sessionSignOverride;
    // Non-btn ceremonies (any hibe group) run the TS-side pipeline: the
    // Rust/wasm core deliberately carries no hibe cipher (contract D1 —
    // tn-core stays scheme-free), so WasmRuntime.init would reject the
    // ceremony. Mirrors Python's dispatch rule (`should_use_rust` is true
    // only for btn-only ceremonies; everything else runs the pure-Python
    // TNRuntime pipeline).
    if (!this._ceremonyIsBtnOnly()) {
      return this._emitViaTs(
        level,
        eventType,
        fieldsOut,
        timestampOverride,
        eventIdOverride,
        aadOverride ?? undefined,
      );
    }
    // Per-emit aad is bound by the native (wasm) tn-core runtime, byte-
    // identical to the pure pipeline; an empty/absent marker binds nothing.
    const aadArg = aadOverride && Object.keys(aadOverride).length > 0 ? aadOverride : null;
    // SDK never crashes user space: an INFRASTRUCTURE failure in the wasm
    // boundary — the core is unavailable (edge/serverless), init fails, or a
    // Rust panic traps/aborts during the emit — is contained here and surfaced
    // once (process warning), never thrown into the host program; the caller
    // gets a zero receipt and keeps running. APPLICATION errors (e.g. schema
    // validation on a malformed event) still propagate so callers can handle
    // them and a real data bug is never silently swallowed.
    // (Explicit operations like tn.vault.* still throw; they don't route here.)
    try {
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
        aadArg,
      );
      // Success — clear any self-heal back-off state.
      if (this._wasmFailures !== 0 || this._wasmRetryAfter !== 0) {
        this._wasmFailures = 0;
        this._wasmRetryAfter = 0;
      }
      return receiptFromLine(line);
    } catch (err) {
      if (isWasmInfraFailure(err)) {
        surfaceWasmFailure("emit", err);
        // Self-heal, bounded. While already backing off, just no-op (don't
        // extend the window). Otherwise drop the (possibly poisoned) runtime so
        // the next call re-inits a fresh one — recovering from a transient
        // Vercel fault. After WASM_MAX_REINIT consecutive failures, back off for
        // WASM_COOLDOWN_MS so a permanent fault can't thrash on re-init.
        if (this._wasmRetryAfter <= Date.now()) {
          this.wasm = null;
          this._wasmFailures += 1;
          if (this._wasmFailures >= WASM_MAX_REINIT) {
            this._wasmRetryAfter = Date.now() + WASM_COOLDOWN_MS;
            this._wasmFailures = 0;
          }
        }
        return receiptFromLine(null);
      }
      throw err;
    }
  }

  /** True iff every declared group uses `cipher: btn` — the precondition
   *  for routing emits through the Rust/wasm core. Mirrors Python's
   *  `tn._dispatch._ceremony_is_btn_only`. */
  private _ceremonyIsBtnOnly(): boolean {
    for (const [, g] of this.config.groups) {
      if (g.cipher !== "btn") return false;
    }
    return true;
  }

  /** Per-event-type chain state for the TS-side emit pipeline. `null`
   *  until the first TS-path emit; seeded from the on-disk logs then. */
  private _tsChain: Map<string, { seq: number; prevHash: string }> | null = null;

  /** Seed the TS chain from every ndjson file in the main-log directory
   *  plus the admin log (mirrors Python `_seed_chain_from_logs` +
   *  `_seed_chain_from_pel`): the last (sequence, row_hash) per event_type
   *  wins, so a restart continues each chain instead of restarting it. */
  private _tsChainState(): Map<string, { seq: number; prevHash: string }> {
    if (this._tsChain !== null) return this._tsChain;
    const chain = new Map<string, { seq: number; prevHash: string }>();
    const lastByType = new Map<string, { seq: number; row: string }>();
    const scanFile = (path: string): void => {
      if (!existsSync(path)) return;
      let text: string;
      try {
        text = readFileSync(path, "utf8");
      } catch {
        return;
      }
      for (const rawLine of text.split(/\r?\n/)) {
        const s = rawLine.trim();
        if (!s) continue;
        let env: Record<string, unknown>;
        try {
          env = JSON.parse(s) as Record<string, unknown>;
        } catch {
          continue;
        }
        const et = env["event_type"];
        const seq = env["sequence"];
        const row = env["row_hash"];
        if (typeof et !== "string" || typeof seq !== "number" || typeof row !== "string") continue;
        const prior = lastByType.get(et);
        if (prior === undefined || seq > prior.seq) lastByType.set(et, { seq, row });
      }
    };
    const logDir = dirname(this.config.logPath);
    if (existsSync(logDir)) {
      for (const entry of readdirSync(logDir).sort()) {
        if (entry.endsWith(".ndjson")) scanFile(join(logDir, entry));
      }
    }
    const adminPath = resolveAdminLogPath(this.config);
    if (dirname(adminPath) !== logDir) scanFile(adminPath);
    for (const [et, { seq, row }] of lastByType) {
      chain.set(et, { seq, prevHash: row });
    }
    this._tsChain = chain;
    return chain;
  }

  /** TS-side emit pipeline for ceremonies the wasm core cannot run (any
   *  non-btn group — today: hibe). Byte-faithful port of Python's
   *  `TNRuntime._emit_locked` (python/tn/logger.py):
   *
   *    1. classify each field public vs group-routed (multi-group aware,
   *       unrouted fields fall back to the `default` group);
   *    2. HMAC index token per private field under the group's index key;
   *    3. seal each group's canonical plaintext with the group's cipher
   *       (hibe: hibeSeal under mpk+idpath; btn: the group's publisher) —
   *       a group this party can't seal is skipped with a warning;
   *    4. advance the per-event-type chain, compute row_hash, sign;
   *    5. route `tn.*` events to the admin log when configured, else
   *       append to the main log and fan out to the registered handlers.
   *
   *  Note: the pure pipeline always signs (matching Python's TNRuntime,
   *  which carries no per-emit sign override at this layer). */
  private _emitViaTs(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    timestampOverride: string | undefined,
    eventIdOverride: string | undefined,
    aadOverride: Record<string, unknown> | undefined,
    // Optional pre-sealed group ciphertexts retained for the async-compatible
    // emit surface. Ordinary synchronous emit seals jwe groups inline.
    preSealed?: Map<string, Uint8Array>,
  ): EmitReceipt {
    const cfg = this.config;
    // 1. classify public vs group buckets.
    const publicOut: Record<string, unknown> = {};
    const perGroup = new Map<string, Record<string, unknown>>();
    for (const [k, v] of Object.entries(fields)) {
      if (cfg.publicFields.has(k)) {
        publicOut[k] = v;
        continue;
      }
      let gnames = cfg.fieldToGroups.get(k);
      if (!gnames || gnames.length === 0) {
        if (cfg.groups.has("default")) {
          gnames = ["default"];
        } else {
          throw new Error(
            `field ${JSON.stringify(k)} has no group route and is not in ` +
              `public_fields. Add it to \`groups[<g>].fields\` in tn.yaml, list ` +
              `it under public_fields, or define a \`default\` group to absorb unknowns.`,
          );
        }
      }
      for (const gname of gnames) {
        if (!cfg.groups.has(gname)) {
          throw new Error(
            `field ${JSON.stringify(k)} routed to unknown group ${JSON.stringify(gname)} ` +
              `(known groups: ${JSON.stringify([...cfg.groups.keys()].sort())})`,
          );
        }
        const bucket = perGroup.get(gname) ?? {};
        bucket[k] = v;
        perGroup.set(gname, bucket);
      }
    }

    // 2 + 3. index tokens + per-group seal.
    // Effective additional-authenticated-data per group: the group's yaml
    // ``aad`` default overridden by any per-emit aad. The merged dict is
    // canonicalized (same routine as the group plaintext / row_hash) and
    // bound to the seal; the non-empty ones are echoed into the public
    // ``tn_aad`` block so a reader reconstructs byte-identical aad. An empty
    // merged dict binds nothing and adds no echo — aad-free records stay
    // byte-identical to the pre-aad wire shape.
    const aadEcho: Record<string, Record<string, unknown>> = {};
    const groupPayloads = new Map<
      string,
      { ct: Uint8Array; fieldHashes: Record<string, string> }
    >();
    for (const [gname, plainFields] of perGroup) {
      const gcfg = cfg.groups.get(gname)!;
      const indexKey = deriveGroupKey(
        this.keystore.indexMaster,
        cfg.ceremonyId,
        gname,
        gcfg.indexEpoch,
      );
      const fieldHashes: Record<string, string> = {};
      for (const [fname, fval] of Object.entries(plainFields)) {
        fieldHashes[fname] = indexTokenFor(indexKey, fname, fval);
      }
      const effectiveAad: Record<string, unknown> = {
        ...(gcfg.aadDefault ?? {}),
        ...(aadOverride ?? {}),
      };
      const hasAad = Object.keys(effectiveAad).length > 0;
      if (hasAad && gcfg.cipher === "btn") {
        // Reject before the seal try/catch (which would otherwise swallow
        // this as a "not a publisher" skip). The wasm btn path can't bind
        // aad; fail loudly, identical to the native-btn limitation.
        throw new Error(
          "per-emit aad is not yet wired through the native (btn) runtime; " +
            "use a hibe/jwe ceremony, a group-level aad in config is likewise " +
            "native-limited, or bind at the group-cipher level.",
        );
      }
      const aadBytes = hasAad ? canonicalBytes(effectiveAad) : new Uint8Array(0);
      const plaintextBytes = canonicalBytes(plainFields);
      let ct: Uint8Array;
      try {
        const pre = preSealed?.get(gname);
        ct =
          pre !== undefined ? pre : this._sealGroupTs(gname, gcfg.cipher, plaintextBytes, aadBytes);
      } catch (e) {
        // JWE recipient configuration is the publisher's access-control list.
        // A missing/malformed list or a Rust seal failure must abort the write;
        // emitting a signed row without this private group would lose data and
        // falsely attest that the requested record was published.
        if (gcfg.cipher === "jwe") throw e;
        // Not a publisher for this group — skip it, exactly like Python's
        // NotAPublisherError branch (warn, drop the group, keep the emit).
        process.emitWarning(
          `tn-proto: skipping group ${JSON.stringify(gname)} for ${eventType}: ` +
            `${e instanceof Error ? e.message : String(e)}`,
        );
        continue;
      }
      groupPayloads.set(gname, { ct, fieldHashes });
      if (hasAad) aadEcho[gname] = effectiveAad;
    }

    // Echo the effective aad into the public section under the reserved
    // ``tn_aad`` key so a reader reconstructs byte-identical binding data.
    // It rides in ``publicOut`` so it feeds the row_hash (and thus the
    // signature) — an authenticated echo. Absent when no group bound aad,
    // keeping aad-free records byte-identical to the pre-aad wire shape.
    //
    // Stored as the CANONICAL JSON STRING of the {group: dict} map, not a
    // raw object: a string public field hashes identically in the pure,
    // wasm, and native row_hash (str(s) == s), whereas an object would hash
    // as Python str(dict) vs compact JSON — a cross-impl mismatch. Mirrors
    // Python tn.logger.
    if (Object.keys(aadEcho).length > 0) {
      publicOut["tn_aad"] = new TextDecoder().decode(canonicalBytes(aadEcho));
    }

    // 4. chain + row_hash + signature.
    const chain = this._tsChainState();
    const slot = chain.get(eventType) ?? { seq: 0, prevHash: String(ZERO_HASH()) };
    const seq = slot.seq + 1;
    const prevHash = slot.prevHash;
    const timestamp =
      timestampOverride ?? new Date().toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");
    const eventId = eventIdOverride ?? randomUUID();
    const levelNorm = level.toLowerCase();

    const groupsForHash: Record<string, import("../core/types.js").GroupHashInput> = {};
    for (const [gname, g] of groupPayloads) {
      groupsForHash[gname] = { ciphertext: g.ct, fieldHashes: g.fieldHashes };
    }
    const rh = rowHash({
      device_identity: asDid(cfg.device.device_identity),
      timestamp,
      eventId,
      eventType,
      level: levelNorm,
      prevHash: asRowHash(prevHash),
      publicFields: publicOut,
      groups: groupsForHash,
    });
    const sig = this.keystore.device.sign(new Uint8Array(Buffer.from(rh, "ascii")));

    // 5. build + write the envelope line.
    const groupPayloadsWire: Record<
      string,
      { ciphertext: string; field_hashes: Record<string, string> }
    > = {};
    for (const [gname, g] of groupPayloads) {
      groupPayloadsWire[gname] = {
        ciphertext: Buffer.from(g.ct).toString("base64"),
        field_hashes: g.fieldHashes,
      };
    }
    const line = buildEnvelopeLine({
      device_identity: asDid(cfg.device.device_identity),
      timestamp,
      eventId,
      eventType,
      level: levelNorm,
      sequence: seq,
      prevHash: asRowHash(prevHash),
      rowHash: rh,
      signatureB64: signatureB64(sig),
      publicFields: publicOut,
      groupPayloads: groupPayloadsWire,
    });

    const isProtocolEvent =
      eventType.startsWith("tn.") && cfg.protocolEventsLocation !== "main_log";
    if (isProtocolEvent) {
      // Route protocol events to the configured admin location (with
      // {event_type}/{event_id} template support, mirroring Python's
      // resolve_protocol_events_path).
      const pelPath = this._resolveProtocolEventsPath(eventType, eventId);
      mkdirSync(dirname(pelPath), { recursive: true });
      appendFileSync(pelPath, line);
    } else {
      mkdirSync(dirname(cfg.logPath), { recursive: true });
      appendFileSync(cfg.logPath, line);
      // Handler fan-out (stdout, custom sinks). Failures never abort the
      // emit — the entry is already sealed on disk.
      let envForHandlers: Record<string, unknown> | null = null;
      for (const h of this.handlers) {
        try {
          if (envForHandlers === null) {
            envForHandlers = JSON.parse(line) as Record<string, unknown>;
          }
          if (!h.accepts(envForHandlers)) continue;
          h.emit(envForHandlers, line);
        } catch {
          /* a failing handler must not abort the emit */
        }
      }
    }
    chain.set(eventType, { seq, prevHash: rh });
    return { eventId, rowHash: rh, sequence: seq };
  }

  /** Seal one group's plaintext under its declared cipher (TS pipeline).
   *  ``aad`` is bound (authenticated, not encrypted); empty binds nothing
   *  and is byte-identical to a plain seal. Throws when this keystore holds
   *  no publisher-side material. */
  private _sealGroupTs(
    gname: string,
    cipher: string,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Uint8Array {
    if (cipher === "hibe") {
      const mat = this.keystore.groups.get(gname)?.hibe;
      if (!mat) {
        throw new Error("HIBE: no authority mpk / identity path in this keystore");
      }
      return hibeEncrypt(mat, plaintext, aad);
    }
    if (cipher === "btn") {
      const pub = this.publishers.get(gname);
      if (!pub) {
        throw new Error("btn: no state file in this keystore");
      }
      if (aad.length > 0) {
        // A btn group reached here inside a mixed (non-btn-only) ceremony.
        // The wasm BtnPublisher.encrypt has no aad parameter, so binding it
        // would silently drop the aad. Reject rather than diverge — matches
        // the native-btn limitation raised for btn-only ceremonies and the
        // Python pure-pipeline btn guard.
        throw new Error(
          "per-emit aad is not yet wired through the native (btn) runtime; " +
            "use a hibe/jwe ceremony, a group-level aad in config is likewise " +
            "native-limited, or bind at the group-cipher level.",
        );
      }
      return pub.encrypt(plaintext);
    }
    if (cipher === "jwe") {
      return jweSealSync(
        this._jweRecipientPubs(gname),
        plaintext,
        aad.length > 0 ? aad : undefined,
      );
    }
    throw new Error(`cipher ${JSON.stringify(cipher)} has no TS publisher path`);
  }

  /** Load a jwe group's recipient X25519 public keys (raw 32-byte) from
   *  `<group>.jwe.recipients` in the keystore. */
  private _jweRecipientPubs(gname: string): Uint8Array[] {
    const path = join(this.config.keystorePath, `${gname}.jwe.recipients`);
    if (!existsSync(path)) {
      throw new Error(`jwe: no recipients file for group ${JSON.stringify(gname)} at ${path}`);
    }
    const doc = JSON.parse(readFileSync(path, "utf8")) as { pub_b64: string }[];
    return doc.map((e) => new Uint8Array(Buffer.from(e.pub_b64, "base64")));
  }

  /** Async-compatible sibling of {@link emit}. jwe groups are sealed through
   *  the same Rust/WASM primitive, then injected into the shared envelope /
   *  signature / chain pipeline. */
  async emitAsync(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    aad?: Record<string, unknown> | null,
  ): Promise<EmitReceipt> {
    validateEventType(eventType);
    const fieldsOut = this._spliceAgentPolicy(eventType, fields);
    const cfg = this.config;
    // Route fields to jwe groups exactly as _emitViaTs does (jwe-only) so we
    // can seal them off the sync pipeline before it runs.
    const jwePer = new Map<string, Record<string, unknown>>();
    for (const [k, v] of Object.entries(fieldsOut)) {
      if (cfg.publicFields.has(k)) continue;
      let gnames = cfg.fieldToGroups.get(k);
      if (!gnames || gnames.length === 0) gnames = cfg.groups.has("default") ? ["default"] : [];
      for (const gname of gnames) {
        if (cfg.groups.get(gname)?.cipher !== "jwe") continue;
        const bucket = jwePer.get(gname) ?? {};
        bucket[k] = v;
        jwePer.set(gname, bucket);
      }
    }
    const preSealed = new Map<string, Uint8Array>();
    for (const [gname, plainFields] of jwePer) {
      const gcfg = cfg.groups.get(gname)!;
      const effectiveAad = { ...(gcfg.aadDefault ?? {}), ...(aad ?? {}) };
      const aadBytes =
        Object.keys(effectiveAad).length > 0 ? canonicalBytes(effectiveAad) : new Uint8Array(0);
      preSealed.set(
        gname,
        await jweSeal(this._jweRecipientPubs(gname), canonicalBytes(plainFields), aadBytes),
      );
    }
    return this._emitViaTs(
      level,
      eventType,
      fieldsOut,
      undefined,
      undefined,
      aad ?? undefined,
      preSealed,
    );
  }

  /** jwe add_recipient: append a raw 32-byte X25519 public key to the group's
   *  recipients (keystore file + authoritative yaml) so the next seal wraps a
   *  CEK for it, then emit `tn.recipient.added`. Idempotent per DID. Mirrors
   *  Python `_add_recipient_jwe_impl`. */
  addRecipientJwe(
    group: string,
    recipientDid: string,
    pub: Uint8Array,
    trust?: JweRecipientTrust,
  ): void {
    jweAddRecipient(this.config.keystorePath, group, recipientDid, pub, trust);
    this._yamlMutateJweRecipients(group, (recips) => {
      const next = recips.filter((r) => r?.recipient_identity !== recipientDid);
      next.push({ recipient_identity: recipientDid, pub_b64: Buffer.from(pub).toString("base64") });
      return next;
    });
    this.emit("info", "tn.recipient.added", { group, recipient_identity: recipientDid });
  }

  /** jwe revoke_recipient: drop a recipient from the keystore list + yaml so the
   *  next seal omits it, then emit `tn.recipient.revoked`. O(1), idempotent.
   *  Mirrors Python `_revoke_recipient_jwe_impl`. */
  revokeRecipientJwe(group: string, recipientDid: string): void {
    jweRevokeRecipient(this.config.keystorePath, group, recipientDid);
    this._yamlMutateJweRecipients(group, (recips) =>
      recips.filter((r) => r?.recipient_identity !== recipientDid),
    );
    this.emit("info", "tn.recipient.revoked", { group, recipient_identity: recipientDid });
  }

  /** Read-modify-write the `recipients` list of a jwe group in the yaml that
   *  authoritatively owns `groups` (head of the extends chain). */
  private _yamlMutateJweRecipients(
    group: string,
    fn: (recips: Record<string, unknown>[]) => Record<string, unknown>[],
  ): void {
    const target = authoritativeYamlFor(this.config.yamlPath, "groups");
    const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
    const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
    let g = ownEntry(groups, group);
    if (g == null) {
      g = { policy: "private", cipher: "jwe", recipients: [] };
      groups[group] = g;
    }
    const recips = (Array.isArray(g.recipients) ? g.recipients : []) as Record<string, unknown>[];
    g.recipients = fn(recips);
    doc.groups = groups;
    writeFileSync(target, stringifyYaml(doc), "utf8");
  }

  /** jwe rotate: archive the current sender/recipients/mykey as `.revoked.<ts>`,
   *  mint fresh material (prior recipients must re-enroll), bump the group
   *  epoch, mirror the fresh recipients into the yaml, and emit
   *  tn.rotation.completed. Mirrors Python's jwe rotate. */
  rotateGroupJwe(group: string): RotateGroupResult {
    const keystore = this.config.keystorePath;
    const prevMk = join(keystore, `${group}.jwe.mykey`);
    const previousKitSha256 = existsSync(prevMk)
      ? sha256HexBytes(new Uint8Array(readFileSync(prevMk)))
      : "";

    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    jweRotateGroup(keystore, group, this.did, ts);

    // Refresh the in-memory keystore + bump the group epoch. loadJweKeys
    // picks up the fresh mykey plus the just-archived `.revoked.<ts>` keys,
    // so a same-process read still spans the rotation boundary.
    const mk = join(keystore, `${group}.jwe.mykey`);
    const newKitSha256 = sha256HexBytes(new Uint8Array(readFileSync(mk)));
    const gk = this.keystore.groups.get(group) ?? { kits: [] };
    gk.jweKeys = loadJweKeys(keystore, group);
    this.keystore.groups.set(group, gk);
    const gcfg = this.config.groups.get(group);
    const generation = (gcfg?.indexEpoch ?? 0) + 1;
    if (gcfg) gcfg.indexEpoch = generation;

    // Mirror the fresh (self-only) recipients + new epoch into the yaml.
    const recips = JSON.parse(
      readFileSync(join(keystore, `${group}.jwe.recipients`), "utf8"),
    ) as Record<string, unknown>[];
    const target = authoritativeYamlFor(this.config.yamlPath, "groups");
    const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
    const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
    let g = ownEntry(groups, group);
    if (g == null) {
      g = { policy: "private", cipher: "jwe" };
      groups[group] = g;
    }
    g.recipients = recips;
    g.group_epoch = generation;
    doc.groups = groups;
    writeFileSync(target, stringifyYaml(doc), "utf8");

    const rotatedAt = new Date().toISOString();
    this.emit("info", "tn.rotation.completed", {
      group,
      cipher: "jwe",
      generation,
      previous_kit_sha256: previousKitSha256,
      rotated_at: rotatedAt,
    });
    return { group, cipher: "jwe", generation, previousKitSha256, newKitSha256, rotatedAt };
  }

  /** Render the yaml's protocol-events location for one event. Supports the
   *  `{yaml_dir}` / `{event_type}` / `{event_id}` tokens Python honors. */
  private _resolveProtocolEventsPath(eventType: string, eventId: string): string {
    let pel = this.config.protocolEventsLocation;
    pel = pel
      .replace(/\{yaml_dir\}/g, this.config.yamlDir)
      .replace(/\{event_type\}/g, eventType)
      .replace(/\{event_id\}/g, eventId);
    return isAbsolute(pel) ? pel : pathResolve(this.config.yamlDir, pel);
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

  // ---------------------------------------------------------------------------
  // hibe reader admin — grant / rotate / revoke. Mirrors Python's
  // tn.admin.grant_reader / rotate_reader_path / revoke_reader
  // (python/tn/admin/__init__.py).
  // ---------------------------------------------------------------------------

  /** Load a group's hibe material fresh from disk, with the group-and-cipher
   *  guards shared by every hibe admin verb. */
  private _requireHibeGroup(verb: string, group: string): HibeGroupMaterial {
    const gcfg = this.config.groups.get(group);
    if (gcfg === undefined) {
      throw new Error(`unknown group: ${JSON.stringify(group)}`);
    }
    if (gcfg.cipher !== "hibe") {
      throw new Error(
        `tn.admin.${verb}: group ${JSON.stringify(group)} uses cipher ` +
          `${JSON.stringify(gcfg.cipher)}; ${verb} is hibe-only. Use ` +
          `addRecipient/revokeRecipient for btn/jwe groups.`,
      );
    }
    const mat = loadHibeGroup(this.config.keystorePath, group);
    if (mat === null) {
      throw new Error(
        `HIBE: keystore is missing ${group}.hibe.mpk/.idpath; ` +
          `was this group minted (or its kit absorbed) here?`,
      );
    }
    return mat;
  }

  /** Authority-side grant registry path: who was granted which path. Lives
   *  next to the group's key files, never rides a kit (the export collector
   *  only matches `.hibe.{mpk,idpath,sk}`). */
  private _hibeGrantsPath(group: string): string {
    return join(this.config.keystorePath, `${group}.hibe.grants`);
  }

  private _hibeGrantsLoad(group: string): Array<{ reader_did: string; id_path: string }> {
    const p = this._hibeGrantsPath(group);
    if (!existsSync(p)) return [];
    return JSON.parse(readFileSync(p, "utf8")) as Array<{ reader_did: string; id_path: string }>;
  }

  private _hibeGrantsWrite(
    group: string,
    grants: Array<{ reader_did: string; id_path: string }>,
  ): void {
    // indent=1 matches Python's `json.dumps(grants, indent=1)` byte layout.
    writeFileSync(this._hibeGrantsPath(group), JSON.stringify(grants, null, 1), "utf8");
  }

  /**
   * HIBE's add_recipient: mint a delegated identity key and package it as
   * an absorbable `.tnpkg` kit (authority mpk + the group's identity path +
   * a fresh identity key — BBG re-randomizes KeyGen, so each grantee holds
   * distinct key material for the same path). The authority master secret
   * NEVER rides a kit. Records the grant in the `<group>.hibe.grants`
   * registry when `readerDid` is given.
   */
  grantReader(
    group: string,
    opts: {
      readerDid?: string;
      idPath?: string;
      outPath?: string;
      /** Required to mint an ANCESTOR of the group's current sealing path —
       * such a key delegates the whole subtree below it. */
      allowSubauthority?: boolean;
      /** Trust metadata recorded with the grant registry entry. */
      grantTrust?: { verified: boolean; proofDigest?: string; proofExpiresAt?: string };
      /** Label the kit manifest as explicit unsafe plaintext delivery. */
      unsafePlaintextLabel?: boolean;
      /** Internal staging only: the Admin surface will recipient-seal this
       * temporary package before exposing the requested final path. */
      recipientSealStaging?: boolean;
    } = {},
  ): { kitPath: string; idPath: string; subtreeDelegation: boolean } {
    if (opts.unsafePlaintextLabel !== true && opts.recipientSealStaging !== true) {
      throw new TrustError(
        "binding_invalid",
        "NodeRuntime.grantReader only mints plaintext staging artifacts; use " +
          "tn.admin.grantReader for sealed delivery or mark explicit unsafe plaintext delivery",
      );
    }
    const mat = this._requireHibeGroup("grantReader", group);
    const safeStem = (opts.readerDid ?? "reader")
      .split(":")
      .pop()!
      .replace(/[^A-Za-z0-9._-]/g, "_");
    const outPath = pathResolve(opts.outPath ?? join(process.cwd(), `${safeStem}.tnpkg`));
    const targetPath = opts.idPath ?? mat.idPath;
    // Exact-path grants are the default. A proper ancestor of the current
    // sealing path is a subtree delegation within the remaining depth and
    // must be requested explicitly.
    const currentLabels = mat.idPath.split("/");
    const targetLabels = targetPath.split("/");
    const isProperAncestor =
      targetLabels.length < currentLabels.length &&
      targetLabels.every((label, index) => label === currentLabels[index]);
    if (isProperAncestor && opts.allowSubauthority !== true) {
      throw new Error(
        `tn.admin.grantReader: id_path ${JSON.stringify(targetPath)} is an ANCESTOR of the ` +
          `group's sealing path ${JSON.stringify(mat.idPath)} — the key would delegate the ` +
          `whole subtree below it. Pass allowSubauthority: true to mint a subauthority grant.`,
      );
    }
    const sk = hibeMintReaderKey(mat, targetPath);

    const files: Array<[string, Uint8Array]> = [
      [`${group}.hibe.idpath`, new Uint8Array(Buffer.from(mat.idPath, "utf8"))],
      [`${group}.hibe.mpk`, mat.mpk],
      [`${group}.hibe.sk`, sk],
    ];
    const body: Record<string, Uint8Array> = {};
    const kitsMeta: Array<{ name: string; sha256: string; bytes: number }> = [];
    for (const [name, data] of files) {
      body[`body/${name}`] = data;
      kitsMeta.push({
        name,
        sha256: "sha256:" + createHash("sha256").update(Buffer.from(data)).digest("hex"),
        bytes: data.length,
      });
    }
    const manifestArgs: {
      kind: ManifestKind;
      fromDid: string;
      ceremonyId: string;
      scope: string;
      toDid?: string;
    } = {
      kind: "kit_bundle",
      fromDid: this.config.device.device_identity,
      ceremonyId: this.config.ceremonyId,
      scope: "kit_bundle",
    };
    if (opts.readerDid !== undefined) manifestArgs.toDid = opts.readerDid;
    const manifest = newManifest(manifestArgs);
    const manifestState: Record<string, unknown> = { kits: kitsMeta, kind: "readers-only" };
    if (isProperAncestor) manifestState["subtree_delegation"] = true;
    if (opts.unsafePlaintextLabel === true) manifestState["unsafe_plaintext_delivery"] = true;
    manifest.state = manifestState;
    signManifestWithBody(manifest, body, this.keystore.device);
    writeTnpkg(outPath, manifest, body);

    if (opts.readerDid) {
      const grants = this._hibeGrantsLoad(group).filter((g) => g.reader_did !== opts.readerDid);
      const entry: Record<string, unknown> = { reader_did: opts.readerDid, id_path: targetPath };
      if (opts.grantTrust !== undefined) {
        entry["verified"] = opts.grantTrust.verified;
        if (opts.grantTrust.proofDigest !== undefined)
          entry["proof_digest"] = opts.grantTrust.proofDigest;
        if (opts.grantTrust.proofExpiresAt !== undefined) {
          entry["proof_expires_at"] = opts.grantTrust.proofExpiresAt;
        }
      }
      if (isProperAncestor) entry["subtree_delegation"] = true;
      grants.push(entry as { reader_did: string; id_path: string });
      this._hibeGrantsWrite(group, grants);
    }
    return { kitPath: outPath, idPath: targetPath, subtreeDelegation: isProperAncestor };
  }

  /**
   * Rotate a hibe group's identity path so FUTURE seals use `newPath`.
   * Admission rotation, not btn-grade revocation: pre-rotation entries stay
   * open forever for prior grantees (delegated keys are permanent), and a
   * grantee holding a key for an ANCESTOR of the new path keeps access to
   * new seals too. Authority-only. Returns the new path.
   */
  rotateReaderPath(group: string, newPath: string): string {
    const mat = this._requireHibeGroup("rotateReaderPath", group);
    hibeRotateIdPath(this.config.keystorePath, group, mat, newPath);
    this._refreshHibeKeystore(group);
    return newPath;
  }

  // ── trusted enrollment + HIBE authority trust ─────────────────────

  /** The receiver-local trusted-enrollment state store for this ceremony. */
  enrollmentStore(): EnrollmentStore {
    return new EnrollmentStore(enrollmentCeremonyFromConfig(this.config), this.keystore.device);
  }

  /** Guards {@link recordUnsafeOperation} against audit-emission recursion. */
  private _unsafeOperationActive = false;

  /**
   * Emit the common unsafe-operation observability pair: exactly one
   * structured `TnSecurityWarning` language warning (synchronous) plus one
   * best-effort `tn.security.unsafe_operation` admin audit event. The audit
   * rides the async emit pipeline so it works on every ceremony cipher
   * (jwe seals cannot run on the sync path); audit failure never changes
   * the result of the requested operation. Callers that can await the
   * returned promise get a durably appended event; fire-and-forget callers
   * stay best-effort.
   */
  recordUnsafeOperation(notice: UnsafeOperationNotice): Promise<void> {
    if (this._unsafeOperationActive) return Promise.resolve();
    this._unsafeOperationActive = true;
    let normalized: UnsafeOperationNotice;
    try {
      normalized = normalizeUnsafeOperationNotice(notice);
      process.emitWarning(
        `explicit TN security weakening requested: ${canonicalUnsafeOperationPayload(normalized)}`,
        "TnSecurityWarning",
      );
    } catch (err) {
      this._unsafeOperationActive = false;
      throw err;
    }
    const audit = this.emitAsync("warning", UNSAFE_OPERATION_EVENT_TYPE, {
      artifact_digest: normalized.artifact_digest,
      group: normalized.group,
      operation: normalized.operation,
      relaxations: [...normalized.relaxations],
      subject_did: normalized.subject_did,
    })
      .then(() => undefined)
      .catch(() => undefined) // audit observability is deliberately best effort
      .finally(() => {
        this._unsafeOperationActive = false;
      });
    return audit;
  }

  /**
   * Pre-authorize `readerDid` for `group` and issue a signed one-time
   * enrollment challenge. Naming the exact reader DID is the publisher's
   * pre-authorization act; reconcile later auto-promotes only offers that
   * answer a retained challenge from a preauthorized reader.
   */
  issueEnrollmentChallenge(readerDid: string, group: string, ttlMs: number): EnrollmentChallengeV1 {
    const store = this.enrollmentStore();
    store.preauthorize(readerDid, group);
    return store.issueChallenge(readerDid, group, ttlMs);
  }

  /** Sign this authority's current MPK/depth/path/epoch binding for one
   * audience (defaults to a self-addressed assertion). */
  issueHibeAuthorityAssertion(
    group: string,
    ttlMs: number,
    opts: { audienceDid?: string } = {},
  ): KeyBindingProofV1 {
    const mat = this._requireHibeGroup("issueHibeAuthorityAssertion", group);
    if (mat.msk === undefined) {
      throw new TrustError(
        "untrusted_principal",
        "only the authority (msk holder) can issue authority assertions",
      );
    }
    if (typeof ttlMs !== "number" || !Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new TrustError("statement_invalid", "assertion ttl must be positive");
    }
    const nowMicros = Date.now() * 1000;
    const proof: KeyBindingProofV1 = {
      version: 1,
      purpose: "hibe-authority",
      subject_did: this.did,
      audience_did: opts.audienceDid ?? this.did,
      ceremony_id: this.config.ceremonyId,
      group,
      issued_at: formatTrustTimestamp(nowMicros),
      expires_at: formatTrustTimestamp(nowMicros + Math.round(ttlMs) * 1000),
      nonce_b64: Buffer.from(randomBytes(32)).toString("base64"),
      binding: {
        algorithm: "TN-BBG-HIBE-BLS12-381",
        mpk_sha256: sha256Digest(mat.mpk),
        max_depth: hibeGroupMpkMaxDepth(mat.mpk),
        id_path: mat.idPath,
        path_epoch: hibeAuthorityEpoch(mat),
      },
      signature_b64: "",
    };
    return signKeyBindingProof(proof, this.keystore.device);
  }

  /**
   * External-writer accept/pin/update for a HIBE authority assertion.
   *
   * Verifies the authority DID and signature, the MPK bytes against the
   * asserted digest, the encoded MPK depth, the path depth, the exact scope,
   * and the monotonic path epoch — then atomically persists the pinned
   * record and installs/updates the group's public sealing material
   * (`.hibe.mpk` + `.hibe.idpath`). No mutation happens before validation.
   */
  installHibeAuthorityAssertion(opts: {
    group: string;
    mpk: Uint8Array;
    assertion: KeyBindingProofV1;
    expectedAuthorityDid: string;
    now?: string;
  }): void {
    const assertion = parseKeyBindingProof(opts.assertion);
    if (assertion.subject_did !== opts.expectedAuthorityDid) {
      throw new TrustError(
        "did_signer_mismatch",
        "assertion subject does not match the expected authority DID",
      );
    }
    if (assertion.group !== opts.group) {
      throw new TrustError("scope_mismatch", "assertion names a different group");
    }
    const pinned = loadPinnedHibeAuthority(this.config.keystorePath, opts.group);
    if (pinned !== null && pinned.ceremonyId !== assertion.ceremony_id) {
      throw new TrustError("scope_mismatch", "assertion names a different authority ceremony");
    }
    const now = opts.now ?? formatTrustTimestamp(Date.now() * 1000);
    const principal = verifyKeyBindingProof(assertion, {
      purpose: "hibe-authority",
      audienceDid: this.did,
      ceremonyId: assertion.ceremony_id,
      group: opts.group,
      now,
    });
    const mpk = new Uint8Array(opts.mpk);
    if (sha256Digest(mpk) !== assertion.binding["mpk_sha256"]) {
      throw new TrustError("binding_invalid", "MPK bytes do not match the asserted digest");
    }
    let encodedDepth: number;
    try {
      encodedDepth = hibeGroupMpkMaxDepth(mpk);
    } catch {
      throw new TrustError("binding_invalid", "MPK bytes are not a valid authority public key");
    }
    if (encodedDepth !== assertion.binding["max_depth"]) {
      throw new TrustError(
        "binding_invalid",
        "encoded MPK depth does not match the asserted max_depth",
      );
    }
    const idPath = String(assertion.binding["id_path"]);
    const pathEpoch = Number(assertion.binding["path_epoch"]);

    // Pin first (fails closed on rollback/conflict), then install material.
    pinHibeAuthority(this.config.keystorePath, opts.group, {
      authorityDid: principal.did,
      ceremonyId: assertion.ceremony_id,
      group: opts.group,
      mpkSha256: sha256Digest(mpk),
      maxDepth: encodedDepth,
      idPath,
      pathEpoch,
      assertionDigest: principal.proofDigest,
    });

    const keystore = this.config.keystorePath;
    const existing = loadHibeGroup(keystore, opts.group);
    if (existing === null) {
      createHibeGroup(keystore, opts.group, { idPath, authorityMpk: mpk });
      this._registerHibeGroupInYaml(opts.group);
    } else {
      // Update both public sealing files via pending + rename so a crash
      // mid-update never leaves a torn mpk or idpath behind.
      const mpkPath = join(keystore, `${opts.group}.hibe.mpk`);
      const mpkPending = `${mpkPath}.pending`;
      writeFileSync(mpkPending, Buffer.from(mpk));
      renameSync(mpkPending, mpkPath);
      const idpathPath = join(keystore, `${opts.group}.hibe.idpath`);
      const idpathPending = `${idpathPath}.pending`;
      writeFileSync(idpathPending, idPath, "utf8");
      renameSync(idpathPending, idpathPath);
    }
    this._refreshHibeKeystore(opts.group);
  }

  /** Register an installed external-authority hibe group in the yaml +
   * in-memory config so seals can route through it. */
  private _registerHibeGroupInYaml(group: string): void {
    if (!this.config.groups.has(group)) {
      this.config.groups.set(group, {
        name: group,
        cipher: "hibe",
        policy: "private",
        recipients: [],
        indexEpoch: 0,
        aadDefault: {},
      });
    }
    const target = authoritativeYamlFor(this.config.yamlPath, "groups");
    const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
    const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
    const existing = groups[group];
    if (existing !== undefined && existing !== null && existing["cipher"] !== "hibe") {
      throw new TrustError(
        "scope_mismatch",
        `group ${JSON.stringify(group)} already exists with cipher ${JSON.stringify(existing["cipher"])}`,
      );
    }
    if (existing === undefined || existing === null) {
      groups[group] = { policy: "private", cipher: "hibe" };
      doc.groups = groups;
      writeFileSync(target, stringifyYaml(doc), "utf8");
    }
  }

  /**
   * Rotate this authority's identity path and return the new higher-epoch
   * signed assertion in one step.
   */
  rotateHibePathWithAssertion(
    group: string,
    newPath: string,
    opts: { ttlMs?: number; audienceDid?: string } = {},
  ): { group: string; idPath: string; pathEpoch: number; assertion: KeyBindingProofV1 } {
    this.rotateReaderPath(group, newPath);
    const mat = this._requireHibeGroup("rotateHibePathWithAssertion", group);
    const assertionOpts: { audienceDid?: string } = {};
    if (opts.audienceDid !== undefined) assertionOpts.audienceDid = opts.audienceDid;
    const assertion = this.issueHibeAuthorityAssertion(
      group,
      opts.ttlMs ?? 10 * 60_000,
      assertionOpts,
    );
    return { group, idPath: mat.idPath, pathEpoch: hibeAuthorityEpoch(mat), assertion };
  }

  /** Look up a retained, unexpired verified grant record for a reader. */
  retainedVerifiedGrant(
    group: string,
    readerDid: string,
    now?: string,
  ): { proofDigest: string | null } | null {
    const grants = this._hibeGrantsLoad(group) as Array<Record<string, unknown>>;
    const entry = grants.find((g) => g["reader_did"] === readerDid);
    if (entry === undefined || entry["verified"] !== true) return null;
    const expiresAt = entry["proof_expires_at"];
    if (typeof expiresAt === "string") {
      const nowText = now ?? formatTrustTimestamp(Date.now() * 1000);
      try {
        if (
          Date.parse(nowText.replace(/\.\d+Z$/, "Z")) >=
          Date.parse(expiresAt.replace(/\.\d+Z$/, "Z"))
        ) {
          return null;
        }
      } catch {
        return null;
      }
    }
    const proofDigest = entry["proof_digest"];
    return { proofDigest: typeof proofDigest === "string" ? proofDigest : null };
  }

  /**
   * Remove a hibe reader going FORWARD: rotate the group's identity path
   * (default: a `~r<n>`-bumped sibling of the current path) and re-issue
   * kits to every other granted reader. The revoked reader keeps everything
   * sealed before the revocation — delegated keys are permanent; what this
   * guarantees is that entries sealed AFTER it are closed to them.
   */
  revokeReader(
    group: string,
    readerDid: string,
    opts: { newPath?: string; outDir?: string } = {},
  ): { revoked: boolean; newPath: string; kitPaths: string[]; remaining: string[] } {
    const mat = this._requireHibeGroup("revokeReader", group);
    const grants = this._hibeGrantsLoad(group);
    if (!grants.some((g) => g.reader_did === readerDid)) {
      throw new Error(
        `tn.admin.revokeReader: ${JSON.stringify(readerDid)} has no recorded grant on ` +
          `group ${JSON.stringify(group)}. Grants made through tn.admin.grantReader are ` +
          `recorded in ${group}.hibe.grants.`,
      );
    }
    const remaining = grants.filter((g) => g.reader_did !== readerDid);

    const target = opts.newPath ?? hibeBumpPath(mat.idPath);
    hibeRotateIdPath(this.config.keystorePath, group, mat, target);
    this._hibeGrantsWrite(group, remaining);
    this._refreshHibeKeystore(group);

    const ts = new Date()
      .toISOString()
      .replace(/[-:]/g, "")
      .replace(/\.\d+Z$/, "Z");
    const outDir = pathResolve(opts.outDir ?? join(process.cwd(), `hibe_regrant_${ts}`));
    mkdirSync(outDir, { recursive: true });

    const kitPaths: string[] = [];
    for (const g of remaining) {
      const safeStem = g.reader_did
        .split(":")
        .pop()!
        .replace(/[^A-Za-z0-9._-]/g, "_");
      const kit = join(outDir, `${safeStem}.tnpkg`);
      this.grantReader(group, {
        readerDid: g.reader_did,
        outPath: kit,
        unsafePlaintextLabel: true,
      });
      kitPaths.push(kit);
    }

    return {
      revoked: true,
      newPath: target,
      kitPaths,
      remaining: remaining.map((g) => g.reader_did),
    };
  }

  /** Re-read a group's hibe material from disk into the loaded keystore so
   *  same-process emits/reads see a rotation immediately. */
  private _refreshHibeKeystore(group: string): void {
    const mat = loadHibeGroup(this.config.keystorePath, group);
    if (mat === null) return;
    const entry = this.keystore.groups.get(group) ?? { kits: [] };
    entry.hibe = mat;
    entry.hibeKits = hibeCandidateKeys(mat);
    this.keystore.groups.set(group, entry);
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
    if (this.config.groups.get(group)?.cipher === "hibe") {
      throw new Error(
        `rotateGroup: group ${group} uses cipher 'hibe'; this rotation is btn-only. ` +
          `hibe groups rotate their identity path via tn.admin.rotateReaderPath ` +
          `(or revokeReader, which rotates and re-kits the survivors).`,
      );
    }
    const oldPub = this.publishers.get(group);
    if (!oldPub) {
      throw new Error(`rotateGroup: group ${group} is not a btn publisher in this runtime`);
    }

    const ks = this.config.keystorePath;
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

    // Mint a fresh publisher + self-kit. UTC timestamp matches the Python
    // convention so cross-language ceremonies show identical .revoked.<ts>
    // filenames in the keystore.
    const ts = Math.floor(Date.now() / 1000);
    const newPub = new BtnPublisher(null);
    const newSelfKit = newPub.mint();
    const newStateBytes = newPub.toBytes();

    // Crash-safe commit: stage the new state+kit to `.pending`, archive the
    // old pair as loadable `.revoked.<ts>`, then promote pending -> active. A
    // crash mid-rotation is repaired on the next loadKeystore - the publisher
    // is never left with no writable state. (Was an in-place overwrite that
    // could destroy the only copy if it crashed between the rename and write.)
    commitGroupKeys(ks, group, {
      stateBytes: new Uint8Array(newStateBytes),
      selfKit: new Uint8Array(newSelfKit),
      archiveTs: String(ts),
    });

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
      const groupSpec = ownEntry(groups, group) ?? {};
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

  /** Async teardown that drains buffering handlers before release. A handler
   * exposing `closeAsync({ timeoutMs })` is awaited with that bound (parity
   * with Python `flush_and_close`'s per-handler outbox-drain timeout); handlers
   * without it fall back to the synchronous `close()`. The wasm core is
   * released last. */
  async closeAsync(opts: { timeoutMs?: number } = {}): Promise<void> {
    for (const h of this.handlers) {
      const ah = h as TNHandler & {
        closeAsync?: (o: { timeoutMs?: number }) => Promise<void>;
      };
      try {
        if (typeof ah.closeAsync === "function") {
          await ah.closeAsync(opts);
        } else {
          h.close();
        }
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
   * Throws when the wasm core is unavailable or init fails. The log path
   * (`_emitViaWasm`) catches that and degrades to a no-op so a logging
   * failure can never crash the host (SDK never crashes user space);
   * explicit callers (tn.vault.*) still surface the failure by throwing.
   */
  attachWasm(): WasmRuntime {
    if (this.wasm !== null) return this.wasm;
    if (this._wasmRetryAfter > Date.now()) {
      // Backing off after repeated failures — fail fast instead of re-initing on
      // every call. The log path contains this; a post-cooldown call retries.
      throw new Error("tn-wasm is unavailable (backing off after repeated failures)");
    }
    const mod = loadWasm();
    if (mod === null) {
      // loadWasm() already surfaced the reason once. Throw so the log path's
      // guard can no-op and explicit callers see the failure — without ever
      // aborting the host process with an uncaught wasm error.
      throw new Error("tn-wasm is unavailable (see prior tn-proto warning)");
    }
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
      this.wasm = mod.WasmRuntime.initWith(this.config.yamlPath, nodeStorageAdapter(), {
        skipCeremonyInitEmit: true,
        skipPolicyPublishedEmit: true,
      });
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
    // Idempotency (parity with Python `_vault_link_impl`): if an active link to
    // the same (vaultDid, projectId) already exists (unlinkedAt === null), this
    // is a no-op and emits no second `tn.vault.linked` event.
    try {
      for (const l of this.adminState().vaultLinks) {
        if (l.vaultDid === vaultDid && l.projectId === projectId && l.unlinkedAt === null) {
          return lastEmitReceipt(w, resolveAdminLogPath(this.config));
        }
      }
    } catch {
      // admin.state can fail on a corrupt log; fall through and emit (parity).
    }
    w.vaultLink(vaultDid, projectId);
    const receipt = lastEmitReceipt(w, resolveAdminLogPath(this.config));
    // Parity with Python `_vault_link_impl`, which calls
    // `tn._refresh_admin_cache_if_present()` after the emit. The wasm runtime
    // writes the `tn.vault.linked` envelope through its own storage adapter, so
    // a previously-instantiated AdminStateCache would otherwise serve stale
    // vault_links to a subsequent `tn.admin.state()` / `recipients()`. Only
    // refresh when the cache already exists (mirrors Python's "if present").
    if (this._adminCache !== null) this._adminCache.refresh();
    return receipt;
  }

  /** Emit a signed `tn.vault.unlinked` event by delegating to `WasmRuntime.vaultUnlink`. */
  vaultUnlink(vaultDid: string, projectId: string, reason?: string): EmitReceipt {
    const w = this.attachWasm();
    w.vaultUnlink(vaultDid, projectId, reason ?? null);
    const receipt = lastEmitReceipt(w, resolveAdminLogPath(this.config));
    // Parity with Python `_vault_unlink_impl` (post-emit
    // `tn._refresh_admin_cache_if_present()`); see `vaultLink` above.
    if (this._adminCache !== null) this._adminCache.refresh();
    return receipt;
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
      signManifestWithBody(manifest, body, this.keystore.device);
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
    // admin.state config fallback so the two SDKs agree. No attesting event
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

  /** Register a group in the in-memory config so same-process routing sees it
   *  immediately (matches Python's `cfg.groups[group] = ...`). No-op if present. */
  private _registerGroupInConfig(group: string, cipher: "btn" | "hibe" | "jwe"): void {
    if (this.config.groups.has(group)) return;
    this.config.groups.set(group, {
      name: group,
      policy: "private",
      cipher,
      recipients: this.did ? [{ did: this.did }] : [],
      indexEpoch: 0,
      aadDefault: {},
    });
  }

  /** Persist a group's `groups.<name>` block (policy/cipher/recipients) + field
   *  routing to the yaml that authoritatively owns `groups`. When `liveRouting`,
   *  also updates the in-memory `fieldToGroups` so same-process emits route
   *  without a wasm reload (btn relies on the wasm reattach instead). */
  private _persistGroupYaml(
    group: string,
    cipher: "btn" | "hibe" | "jwe",
    fields: string[] | undefined,
    liveRouting: boolean,
  ): void {
    const target = authoritativeYamlFor(this.config.yamlPath, "groups");
    const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
    const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
    let dirty = false;
    let gspec = ownEntry(groups, group);
    if (!gspec) {
      gspec = { policy: "private", cipher, recipients: [{ recipient_identity: this.did }] };
      groups[group] = gspec;
      dirty = true;
    }
    if (fields && fields.length > 0) {
      const existingRaw = gspec.fields;
      const routed: string[] = Array.isArray(existingRaw)
        ? (existingRaw as unknown[]).map((f) => String(f))
        : [];
      const seen = new Set(routed);
      for (const f of fields) {
        if (!seen.has(f)) {
          routed.push(f);
          seen.add(f);
        }
      }
      gspec.fields = routed;
      const flat = (doc.fields ?? {}) as Record<string, unknown>;
      for (const f of fields) flat[f] = { group };
      doc.fields = flat;
      if (liveRouting) {
        for (const f of fields) {
          const list = this.config.fieldToGroups.get(f) ?? [];
          if (!list.includes(group)) list.push(group);
          this.config.fieldToGroups.set(f, [...list].sort());
        }
      }
      dirty = true;
    }
    if (dirty) {
      doc.groups = groups;
      writeFileSync(target, stringifyYaml(doc), "utf8");
    }
  }

  /** Add a group post-init and emit `tn.group.added`. Returns the emit
   * receipt. Caller is responsible for checking idempotency before calling.
   *
   * For btn groups this mirrors Python's
   * `tn.admin.ensure_group`: it mints the group's key material and persists
   * the `groups.<name>` block to the AUTHORITATIVE yaml so the group both
   * survives the next load and is routable. See {@link persistBtnGroup}.
   *
   * btn/hibe mint through the wasm / tn-hibe cores; jwe mints its reader-local
   * keystore through the TS lifecycle adapter (see {@link persistJweGroup}). A
   * ceremony containing jwe uses TS orchestration backed by the Rust/Wasm JWE
   * primitives, and persists the group to yaml like the others. */
  adminEnsureGroup(group: string, cipher: "btn" | "jwe" | "hibe", fields?: string[]): EmitReceipt {
    if (cipher === "btn") {
      this.persistBtnGroup(group, fields);
    } else if (cipher === "hibe") {
      this.persistHibeGroup(group, fields);
    } else {
      this.persistJweGroup(group, fields);
    }
    const addedAt = new Date().toISOString();
    return this.emit("info", "tn.group.added", {
      group,
      cipher,
      publisher_identity: this.did,
      added_at: addedAt,
    });
  }

  /** Route `fields` into an already-attested group WITHOUT re-emitting
   * `tn.group.added`. Mirrors Python's `ensure_group(..., fields=[...])` on a
   * group that already exists: it only updates the authoritative yaml routing
   * and re-attaches wasm so same-process emits pick up the new routes. */
  adminRouteFields(group: string, fields: string[]): void {
    if (fields.length === 0) return;
    this.persistBtnGroup(group, fields);
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
  private persistBtnGroup(group: string, fields?: string[]): void {
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

    this._registerGroupInConfig(group, "btn");
    this._persistGroupYaml(group, "btn", fields, false);
    // Force the next emit/read to re-attach wasm off the freshly-written yaml +
    // keystore so it builds the new group's cipher and routing.
    this._resetWasmAfterAdminWrite();
  }

  /** Mint a fresh hibe group (this keystore becomes its own authority) and
   *  persist it AUTHORITATIVELY. hibe sibling of {@link persistBtnGroup}:
   *  key material is minted only when `<group>.hibe.mpk` is absent
   *  (mirrors Python `ensure_group`'s hibe key_exists check), the group is
   *  registered in the in-memory config, and the `groups.<name>` block is
   *  written to the yaml that authoritatively owns `groups`. */
  private persistHibeGroup(group: string, fields?: string[]): void {
    const keystore = this.config.keystorePath;
    const mpkPath = join(keystore, `${group}.hibe.mpk`);
    if (!existsSync(mpkPath)) {
      createHibeGroup(keystore, group);
    }
    this._refreshHibeKeystore(group);

    this._registerGroupInConfig(group, "hibe");
    this._persistGroupYaml(group, "hibe", fields, true);
  }

  /** Mint a fresh jwe group (recipient keystore + self-recipient) and persist
   *  it AUTHORITATIVELY. jwe sibling of {@link persistHibeGroup}: mirrors
   *  Python's `ensure_group` jwe branch. */
  private persistJweGroup(group: string, fields?: string[]): void {
    const keystore = this.config.keystorePath;
    if (!existsSync(join(keystore, `${group}.jwe.recipients`))) {
      createJweGroup(keystore, group, this.did);
    }
    // Refresh the in-memory keystore so a same-process readAsync opens the
    // group (the LoadedKeystore was snapshotted at init, before this mint).
    const gk = this.keystore.groups.get(group) ?? { kits: [] };
    const jweKeys = loadJweKeys(keystore, group);
    if (jweKeys.length > 0) gk.jweKeys = jweKeys;
    this.keystore.groups.set(group, gk);
    this._registerGroupInConfig(group, "jwe");
    this._persistGroupYaml(group, "jwe", fields, true);
  }

  /**
   * Flip `ceremony.mode` (local <-> linked) in the AUTHORITATIVE yaml.
   *
   * Byte-faithful port of the persistent half of Python's
   * `tn.admin.set_link_state` (`python/tn/admin/__init__.py::set_link_state`
   * + its inner `_mutate`, which writes via
   * `_update_authoritative_yaml(..., key="vault")`). Two reasons the write
   * must touch more than `ceremony.mode`:
   *
   *   1. Python's config loader REJECTS a `mode: linked` yaml that has no
   *      `linked_vault` (`config.py::_resolve_ceremony_settings`:
   *      "ceremony.mode=linked requires ceremony.linked_vault"). A bare
   *      mode flip would produce a yaml Python can't even load. So linking
   *      requires a vault URL and writes the `vault:` block Python writes.
   *   2. Link state is project-scoped: the mutation lands at the head of
   *      the `extends:` chain (key="vault"), so unlinking a named stream
   *      flips the project rather than writing a discarded stream-local
   *      override. For a single-file ceremony the authoritative yaml
   *      resolves back to `this.config.yamlPath`, leaving the legacy
   *      single-file layout unchanged.
   *
   * Idempotent on re-link to the same vault; re-linking an already-linked
   * ceremony to a DIFFERENT vault throws (mirrors Python's RuntimeError).
   *
   * The in-memory `this.config.mode` is `readonly`, so callers needing the
   * updated mode in-process should `loadConfig(yamlPath)` again; the next
   * wasm attach picks the change up off disk regardless.
   *
   * @param mode - target `ceremony.mode` (`"local"` == unlinked).
   * @param opts - vault binding; `linkedVault` is REQUIRED when
   *   `mode === "linked"` (Python's `set_link_state` raises without it).
   */
  setCeremonyMode(
    mode: "local" | "linked",
    opts: { linkedVault?: string; linkedProjectId?: string } = {},
  ): void {
    if (mode !== "local" && mode !== "linked") {
      throw new Error(
        `setCeremonyMode: mode must be 'local' or 'linked', got ${JSON.stringify(mode)}`,
      );
    }
    const linkedVault = opts.linkedVault;
    const linkedProjectId = opts.linkedProjectId;
    if (mode === "linked" && (linkedVault === undefined || linkedVault === "")) {
      throw new Error("setCeremonyMode: linked mode requires a linkedVault URL");
    }

    // Python's set_link_state resolves the authoritative yaml with
    // key="vault"; match that so the write lands on the same node Python
    // would pick (the chain entry that owns `vault`, else the root).
    const target = authoritativeYamlFor(this.config.yamlPath, "vault");
    const doc = (parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {};
    const ceremony = (doc.ceremony ?? {}) as Record<string, unknown>;
    const vault = (doc.vault ?? {}) as Record<string, unknown>;

    // Re-link guard (Python: raises when already linked to a different
    // vault). Resolve the current linked vault the same way the loader
    // does: vault.url when the vault block is present, else
    // ceremony.linked_vault.
    if (mode === "linked") {
      const currentVault =
        vault.url !== undefined && vault.url !== ""
          ? String(vault.url)
          : ceremony.linked_vault !== undefined
            ? String(ceremony.linked_vault)
            : "";
      if (
        String(ceremony.mode ?? "local") === "linked" &&
        currentVault &&
        currentVault !== linkedVault
      ) {
        throw new Error(
          `setCeremonyMode: ceremony is already linked to ${currentVault}; ` +
            `unlink first before re-linking to ${String(linkedVault)}`,
        );
      }
    }

    // Mirror Python's `_mutate` field-for-field.
    ceremony.mode = mode;
    if (mode === "linked") {
      ceremony.linked_vault = linkedVault;
      if (linkedProjectId !== undefined && linkedProjectId !== "") {
        ceremony.linked_project_id = linkedProjectId;
      }
      vault.enabled = true;
      vault.url = linkedVault;
      if (linkedProjectId !== undefined && linkedProjectId !== "" && !vault.linked_project_id) {
        vault.linked_project_id = linkedProjectId;
      }
      vault.autosync = Boolean(vault.autosync ?? true);
      if (vault.sync_interval_seconds === undefined) vault.sync_interval_seconds = 600;
    } else {
      delete ceremony.linked_vault;
      delete ceremony.linked_project_id;
      vault.enabled = false;
      vault.url = "";
      vault.linked_project_id = "";
      vault.autosync = false;
      if (vault.sync_interval_seconds === undefined) vault.sync_interval_seconds = 600;
    }
    doc.ceremony = ceremony;
    doc.vault = vault;
    writeFileSync(target, stringifyYaml(doc), "utf8");

    // Force the next emit/read to re-attach wasm off the updated yaml so
    // the runtime's view of the mode stays consistent with disk.
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
      ceremonyId?: string;
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
    } else if (kind === "identity_seed") {
      const built = this._buildIdentitySeedBody(
        opts.nickname !== undefined ? { nickname: opts.nickname } : {},
      );
      body = built.body;
      extras.state = built.state;
      extras.scope = "identity";
      // identity_seed is self-issued: no enclosing ceremony, so stamp the
      // placeholder ceremony id (mirrors Python's _resolve_export_signer).
      extras.ceremonyId = IDENTITY_SEED_CEREMONY_PLACEHOLDER;
    } else if (kind === "contact_update") {
      // Producer-side mirror of the vault-emitted contact_update tnpkg.
      // Python has no `export(kind="contact_update")` (the vault server
      // emits these), so there's no Python producer to byte-match; we
      // build the body Python's `_absorb_contact_update` consumes and
      // validate it up front the same way the reducer does.
      if (opts.contactUpdate === undefined) {
        throw new Error(`export(kind="contact_update") requires opts.contactUpdate=<body>.`);
      }
      const errors = _validateContactUpdateBody(opts.contactUpdate);
      if (errors.length > 0) {
        throw new Error(`export(kind="contact_update"): invalid body — ${errors.join("; ")}`);
      }
      // Canonical, sorted JSON so the on-the-wire body is deterministic.
      body["body/contact_update.json"] = new TextEncoder().encode(
        _canonicalContactUpdateJson(opts.contactUpdate),
      );
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
      ceremonyId: extras.ceremonyId ?? this.config.ceremonyId,
      scope: opts.scope ?? extras.scope ?? _defaultScope(kind),
    };
    if (kind === "project_seed" || kind === "identity_seed" || kind === "full_keystore") {
      // Self-addressed: from_did == to_did. The absorb side rejects a
      // bundle whose from/to disagree (tamper guard).
      manifestArgs.toDid = this.config.device.device_identity;
    } else if (opts.toDid !== undefined) {
      manifestArgs.toDid = opts.toDid;
    }
    const manifest = newManifest(manifestArgs);
    if (extras.clock) manifest.clock = extras.clock;
    if (extras.eventCount !== undefined) manifest.eventCount = extras.eventCount;
    if (extras.headRowHash !== undefined) manifest.headRowHash = extras.headRowHash;
    if (extras.state !== undefined) manifest.state = extras.state;

    signManifestWithBody(manifest, body, this.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  /**
   * Export an AES-256-GCM-encrypted `full_keystore` tnpkg (BYOK / BEK).
   *
   * Mirrors Python's `export(kind="full_keystore", encrypt_body_with=bek)`
   * (the init-upload / pending-claim path). The body files are
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
    const ciphertextSha =
      "sha256:" + createHash("sha256").update(Buffer.from(encrypted)).digest("hex");

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
    signManifestWithBody(manifest, body, this.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  /** Apply a `.tnpkg` to local state. Idempotent. Mirrors Python `tn.absorb`. */
  absorbPkg(
    source: string | Uint8Array,
    opts: { unsafeLegacySigner?: boolean } = {},
  ): AbsorbReceipt {
    let manifest: Manifest;
    let body: Map<string, Uint8Array>;
    let unsafeLegacyImport = false;
    try {
      const parsed = readTnpkgVerified(source);
      manifest = parsed.manifest;
      body = parsed.body;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // The named unsafe legacy-import path: a signed package with NO body
      // digest index may enter only with the explicit flag, never for
      // security-sensitive kinds, and never marked verified.
      const missingIndexOnly =
        e instanceof TrustError &&
        e.reason === "body_digest_mismatch" &&
        e.detail.includes("index is missing");
      if (opts.unsafeLegacySigner === true && missingIndexOnly) {
        const legacy = this._absorbLegacyUnverified(source);
        if (legacy !== null) {
          manifest = legacy.manifest;
          body = legacy.body;
          unsafeLegacyImport = true;
        } else {
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
      } else {
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
    } else if (kind === "group_keys" || manifest.scope === "group_keys") {
      // group_keys rides the `full_keystore` wire kind (server-known) marked
      // with scope=group_keys; route by the marker, not just the kind.
      receipt = this._absorbGroupKeys(manifest, body);
    } else if (kind === "kit_bundle" || kind === "full_keystore") {
      receipt =
        kind === "kit_bundle" && manifest.toDid !== undefined && manifest.toDid !== this.did
          ? {
              kind,
              acceptedCount: 0,
              dedupedCount: 0,
              noop: false,
              derivedState: null,
              conflicts: [],
              rejectedReason: "kit_bundle recipient_identity does not match this device",
            }
          : this._absorbKitBundle(manifest, body);
    } else if (kind === "identity_seed") {
      receipt = this._absorbIdentitySeed(manifest, body);
    } else if (kind === "project_seed") {
      receipt = this._absorbProjectSeed(manifest, body);
    } else if (kind === "contact_update") {
      receipt = this._absorbContactUpdate(manifest, body);
    } else if (kind === "offer" || kind === "enrolment") {
      // Security-sensitive version-1 kinds always fail closed: they never
      // enter through the unsafe legacy-import path.
      if (unsafeLegacyImport) {
        return {
          kind,
          acceptedCount: 0,
          dedupedCount: 0,
          noop: false,
          derivedState: null,
          conflicts: [],
          rejectedReason:
            `absorb: ${kind} packages require a signed body digest index and cannot ` +
            `enter through unsafeLegacySigner`,
        };
      }
      receipt =
        kind === "offer"
          ? this._absorbTrustedOffer(source, body)
          : this._absorbEnrolment(manifest, body);
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

    if (
      kind === "kit_bundle" &&
      !unsafeLegacyImport &&
      manifest.toDid === this.did &&
      receipt.rejectedReason === undefined &&
      receipt.acceptedCount + receipt.dedupedCount > 0
    ) {
      recordVerifiedKitBundlePublisher({
        keystoreDir: this.config.keystorePath,
        manifest,
        artifactDigest: packageArtifactDigest(source),
      });
      receipt.verifiedPublisherDid = manifest.fromDid;
    }
    if (unsafeLegacyImport) {
      receipt.unsafeLegacyImport = true;
      const artifactBytes =
        typeof source === "string" ? new Uint8Array(readFileSync(source)) : source;
      // Best-effort from this sync path; async callers can await the audit
      // via recordUnsafeOperation directly.
      void this.recordUnsafeOperation({
        operation: "legacy_package_import",
        relaxations: ["legacy_signer_mismatch"],
        group: null,
        subject_did: manifest.fromDid,
        artifact_digest: sha256Digest(artifactBytes),
      });
    }
    if (this._adminCache !== null) this._adminCache.refresh();
    return receipt;
  }

  /** Explicitly unverified legacy read: bounded structure checks + manifest
   * signature only. Returns null when even that fails. */
  private _absorbLegacyUnverified(
    source: string | Uint8Array,
  ): { manifest: Manifest; body: Map<string, Uint8Array> } | null {
    try {
      const parsed = readTnpkg(source);
      if (!isManifestSignatureValid(parsed.manifest)) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  /** Stage a trusted key-binding offer into pending enrollment state. A
   * legacy offer without a signed proof keeps the historical stub receipt. */
  private _absorbTrustedOffer(
    source: string | Uint8Array,
    body: Map<string, Uint8Array>,
  ): AbsorbReceipt {
    let pkg: TnPackage | null = null;
    const raw = body.get("body/package.json");
    if (raw !== undefined) {
      try {
        pkg = parseTnPackage(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)));
      } catch {
        pkg = null;
      }
    }
    const hasProof =
      pkg !== null &&
      pkg.payload["key_binding_proof"] !== undefined &&
      pkg.payload["key_binding_proof"] !== null;
    if (!hasProof) {
      // Historical offer stub (no strict signed binding declared).
      return {
        kind: "offer",
        acceptedCount: body.has("body/package.json") ? 1 : 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
      };
    }
    try {
      const artifact = typeof source === "string" ? new Uint8Array(readFileSync(source)) : source;
      const pending = this.enrollmentStore().stageOffer(artifact, this.did);
      return {
        kind: "offer",
        acceptedCount: 1,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        offerDigest: pending.offerDigest,
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        kind: "offer",
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: msg,
      };
    }
  }

  /** Reader-side enrolment absorb: verify and install an accepted-enrollment
   * response as a verified publisher. Legacy enrolment bodies keep the
   * historical stub receipt. */
  private _absorbEnrolment(manifest: Manifest, body: Map<string, Uint8Array>): AbsorbReceipt {
    const raw = body.get("body/package.json");
    let pkg: TnPackage | null = null;
    if (raw !== undefined) {
      try {
        pkg = parseTnPackage(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)));
      } catch {
        pkg = null;
      }
    }
    const responseValue = pkg?.payload["enrollment_response"];
    if (pkg === null || responseValue === undefined || responseValue === null) {
      return {
        kind: "enrolment",
        acceptedCount: body.has("body/package.json") ? 1 : 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
      };
    }
    try {
      if (manifest.fromDid !== pkg.device_identity) {
        throw new TrustError(
          "outer_inner_signer_mismatch",
          "outer manifest and inner enrolment name different signers",
        );
      }
      verifyTnPackageSignature(pkg);
      if (manifest.toDid !== this.did || pkg.recipient_identity !== this.did) {
        throw new TrustError("wrong_recipient", "enrolment response names a different reader");
      }
      const installed = installEnrollmentResponse({
        keystoreDir: this.config.keystorePath,
        readerDid: this.did,
        response: responseValue,
      });
      if (installed.publisherDid !== pkg.device_identity) {
        throw new TrustError(
          "outer_inner_signer_mismatch",
          "enrolment response publisher and package signer differ",
        );
      }
      return {
        kind: "enrolment",
        acceptedCount: 1,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        verifiedPublisherDid: installed.publisherDid,
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        kind: "enrolment",
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: msg,
      };
    }
  }

  /**
   * Absorb a `.tnpkg` that MAY be recipient-sealed. When the manifest carries
   * a `state.body_encryption.recipient_wraps[]` (a kit sealed to a DID via
   * {@link sealKitForRecipient} / the Python `seal_for_recipient` path), this
   * unwraps the BEK with this device's key, decrypts the body, and installs
   * the kit files — the async peer of the synchronous {@link absorbPkg}
   * (WebCrypto unseal cannot run on the sync path). An unsealed package falls
   * straight through to {@link absorbPkg}, so this is always safe to call.
   */
  async absorbPkgAsync(
    source: string | Uint8Array,
    opts: { unsafeLegacySigner?: boolean } = {},
  ): Promise<AbsorbReceipt> {
    let manifest: Manifest;
    try {
      manifest = readTnpkgVerified(source).manifest;
    } catch {
      return this.absorbPkg(source, opts); // let the sync path report the parse error
    }
    const state = manifest.state as Record<string, unknown> | undefined;
    const be = state?.["body_encryption"] as Record<string, unknown> | undefined;
    const sealed =
      be !== undefined &&
      (be["recipient_wraps"] !== undefined || be["recipient_wrap"] !== undefined);
    if (sealed && (manifest.kind === "kit_bundle" || manifest.kind === "full_keystore")) {
      if (
        manifest.kind === "kit_bundle" &&
        manifest.toDid !== undefined &&
        manifest.toDid !== this.did
      ) {
        return {
          kind: manifest.kind,
          acceptedCount: 0,
          dedupedCount: 0,
          noop: false,
          derivedState: null,
          conflicts: [],
          rejectedReason: "kit_bundle recipient_identity does not match this device",
        };
      }
      const r = await absorbSealedKitBundle(source, {
        seed: this.keystore.device.seed,
        keystoreDir: this.config.keystorePath,
        yamlPath: this.config.yamlPath,
      });
      const receipt: AbsorbReceipt = {
        kind: r.kind,
        acceptedCount: r.acceptedCount,
        dedupedCount: r.dedupedCount,
        noop: r.acceptedCount === 0 && r.rejectedReason === undefined,
        derivedState: null,
        conflicts: [],
      };
      if (r.rejectedReason !== undefined) receipt.rejectedReason = r.rejectedReason;
      if (
        manifest.kind === "kit_bundle" &&
        manifest.toDid === this.did &&
        r.rejectedReason === undefined &&
        r.acceptedCount + r.dedupedCount > 0
      ) {
        recordVerifiedKitBundlePublisher({
          keystoreDir: this.config.keystorePath,
          manifest,
          artifactDigest: packageArtifactDigest(source),
        });
        receipt.verifiedPublisherDid = manifest.fromDid;
      }
      if (this._adminCache !== null) this._adminCache.refresh();
      return receipt;
    }
    return this.absorbPkg(source, opts);
  }

  /**
   * Re-seal an unsealed kit_bundle `.tnpkg` in place so ONLY `recipientDid`'s
   * device key can open it (closes the plaintext-bearer-token gap: an
   * intercepted kit is useless to anyone else). No-op — returns false — when
   * the DID is absent or has no embedded key (a did-less hand-off stays
   * plaintext by necessity). Mirrors the Python `seal_for_recipient` opt-in.
   */
  async sealKitForRecipient(kitPath: string, recipientDid?: string): Promise<boolean> {
    if (!recipientDid || !recipientKeyIsResolvable(recipientDid)) return false;
    await sealBundleForRecipient({
      unsealedBundle: kitPath,
      recipientDid,
      publisherKey: this.keystore.device,
      outPath: kitPath,
    });
    return true;
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
    const jweGroups = requested.filter((group) => cfg.groups.get(group)?.cipher === "jwe");
    if (jweGroups.length > 0) {
      throw new Error(
        `bundleForRecipient: JWE groups ${JSON.stringify(jweGroups)} have no reader kit; ` +
          "use tn.pkg.prepareRecipient with an accepted public-key offer. " +
          "A reader's .jwe.mykey is private, reader-local material and is never exported.",
      );
    }

    const td = mkdtempSync(join(tmpdir(), "tn-bundle-"));
    try {
      for (const gname of requested) {
        if (cfg.groups.get(gname)?.cipher === "hibe") {
          // hibe grant: stage the reader-kit files (mpk + idpath + a fresh
          // delegated key) — same file set grantReader packages.
          const mat = this._requireHibeGroup("addRecipient", gname);
          const sk = hibeMintReaderKey(mat, mat.idPath);
          writeFileSync(join(td, `${gname}.hibe.mpk`), Buffer.from(mat.mpk));
          writeFileSync(join(td, `${gname}.hibe.idpath`), mat.idPath, "utf8");
          writeFileSync(join(td, `${gname}.hibe.sk`), Buffer.from(sk));
          const grants = this._hibeGrantsLoad(gname).filter((g) => g.reader_did !== recipientDid);
          grants.push({ reader_did: recipientDid, id_path: mat.idPath });
          this._hibeGrantsWrite(gname, grants);
          continue;
        }
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
      const names = [
        `${gname}.btn.mykit`,
        `${gname}.hibe.idpath`,
        `${gname}.hibe.mpk`,
        `${gname}.hibe.sk`,
      ];
      for (const name of names) {
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
    signManifestWithBody(manifest, body, this.keystore.device);
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
    // A hibe reader kit: the authority mpk, the group's identity path, and
    // the delegated identity key. NEVER `.hibe.msk` — the master secret can
    // mint a key for ANY path under that authority and only rides
    // full_keystore (self-addressed backup), mirroring the local.private
    // posture. Mirrors Python export.py `_HIBE_KIT_RE`.
    const hibeKitRe = /^(.+?)\.hibe\.(mpk|idpath|sk)$/;
    const jweFullRe = /^(.+?)\.jwe\.(mykey|sender|recipients)(?:\.revoked\..+)?$/;
    const body: Record<string, Uint8Array> = {};
    const kitsMeta: Array<{ name: string; sha256: string; bytes: number }> = [];

    for (const entry of readdirSync(keystore).sort()) {
      const m = kitRe.exec(entry) ?? hibeKitRe.exec(entry);
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
        } else {
          const jwe = jweFullRe.exec(entry);
          if (jwe !== null) {
            const group = jwe[1]!;
            if (!groupFilter || groupFilter.has(group)) {
              const data = new Uint8Array(readFileSync(join(keystore, entry)));
              body[`body/${entry}`] = data;
              kitsMeta.push({
                name: entry,
                sha256: "sha256:" + createHash("sha256").update(Buffer.from(data)).digest("hex"),
                bytes: data.length,
              });
            }
            continue;
          }
          // Private/per-group material packed only for full_keystore:
          // btn publisher state, HIBE authority state, and JWE current/history.
          for (const suffix of [".btn.state", ".hibe.msk", ".hibe.idpath.history"]) {
            if (entry.endsWith(suffix)) {
              const group = entry.slice(0, -suffix.length);
              if (!groupFilter || groupFilter.has(group)) {
                body[`body/${entry}`] = new Uint8Array(readFileSync(join(keystore, entry)));
              }
              break;
            }
          }
        }
      }
    }

    if (kitsMeta.length === 0) {
      const suffix = groupFilter ? ` matching groups [${[...groupFilter].sort().join(", ")}]` : "";
      throw new Error(
        `kit_bundle: no BTN/HIBE reader kits or full-backup JWE material in ${keystore}${suffix}`,
      );
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

  /**
   * Build the body + manifest extras for an `identity_seed` export.
   *
   * Byte-faithful port of Python's `_build_identity_seed_body`
   * (`python/tn/export.py` ~398-473). The bundle is self-issued: the
   * Ed25519 device key it carries IS the manifest signer (from_did ==
   * to_did), so there's no enclosing ceremony — the caller stamps the
   * `IDENTITY_SEED_CEREMONY_PLACEHOLDER` ceremony id.
   *
   * Body:
   *   body/local.private  — 32-byte Ed25519 seed (this runtime's device).
   *   body/local.public   — utf-8 `did:key:z...` (same convention as
   *                         config._create_fresh, so a fresh-installed
   *                         keystore is indistinguishable from `tn init`).
   *   body/tn.yaml        — minimal stub naming the DID (+ optional
   *                         nickname). Matches Python's stub text exactly.
   *
   * Extras carried into the manifest:
   *   scope = "identity"
   *   state.identity = {schema: "tn-identity-seed-v1", nickname, minted_at}
   */
  private _buildIdentitySeedBody(opts: { nickname?: string }): {
    body: Record<string, Uint8Array>;
    state: Record<string, unknown>;
  } {
    const device = this.keystore.device;
    const privateBytes = device.seed;
    if (privateBytes.length !== 32) {
      throw new Error(
        `identity_seed: device private seed must be 32 bytes (Ed25519); got ${privateBytes.length}`,
      );
    }
    const did = String(device.did);
    if (!did.startsWith("did:key:z")) {
      throw new Error(`identity_seed: device.did must be a did:key:z... identifier; got ${did}`);
    }
    const nickname = opts.nickname;

    // Stub yaml — byte-identical to Python's `_build_identity_seed_body`
    // (note the trailing newline on each line, and JSON-encoded nickname).
    let stubYaml =
      "# Identity seed stub written by tn.export(kind='identity_seed').\n" +
      "# Replace this file with a real ceremony tn.yaml when joining one.\n" +
      "identity:\n" +
      `  did: ${did}\n`;
    if (nickname) {
      stubYaml += `  nickname: ${JSON.stringify(nickname)}\n`;
    }

    const body: Record<string, Uint8Array> = {
      "body/local.private": new Uint8Array(privateBytes),
      "body/local.public": new TextEncoder().encode(did),
      "body/tn.yaml": new TextEncoder().encode(stubYaml),
    };

    return {
      body,
      state: {
        identity: {
          schema: "tn-identity-seed-v1",
          // Match Python: nickname is always present, null when unset.
          nickname: nickname ?? null,
          minted_at: nowIsoMillis(),
        },
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
    const seenRowHashes = existingRowHashes(adminLog);
    const localClock = _localClockFromAdminLog(adminLog);

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

    const revokedLeaves = _revokedLeavesFromAdminLog(adminLog);
    const { acceptedEnvs, conflicts, deduped } = _ingestSnapshotEnvelopes(
      raw,
      seenRowHashes,
      revokedLeaves,
      manifest.clock,
    );

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
      existingDoc =
        (parseYaml(Buffer.from(existingYaml).toString("utf8")) as Record<string, unknown>) ?? {};
      incomingDoc =
        (parseYaml(Buffer.from(incomingYaml).toString("utf8")) as Record<string, unknown>) ?? {};
    } catch {
      return { vaultOnly: false };
    }
    if (typeof existingDoc !== "object" || typeof incomingDoc !== "object") {
      return { vaultOnly: false };
    }
    const existingVault = existingDoc["vault"] as Record<string, unknown> | undefined;
    const incomingVault = incomingDoc["vault"] as Record<string, unknown> | undefined;
    if (
      !existingVault ||
      !incomingVault ||
      typeof existingVault !== "object" ||
      typeof incomingVault !== "object"
    ) {
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
      if (
        ceremony &&
        incomingCeremony &&
        typeof ceremony === "object" &&
        typeof incomingCeremony === "object"
      ) {
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
   * Reduce a `contact_update` body into `contacts.yaml`. Mirrors Python's
   * `_absorb_contact_update` (`python/tn/absorb.py` ~1131) +
   * `_apply_contact_update` (`python/tn/contacts.py` ~146).
   *
   * Body shape (spec §4.6):
   *   body/contact_update.json: {
   *     account_id, label, package_did, x25519_pub_b64,
   *     claimed_at, source_link_id
   *   }
   *
   * contacts.yaml lives at `<yamlDir>/.tn/<stem>/contacts.yaml` (Python's
   * per-stem `tn_dir`). The doc is `{contacts: [row, ...]}`; each row is
   * projected to the canonical six-field shape. Idempotency key is
   * `(account_id, package_did)`: a matching row is replaced in
   * place, otherwise the row is appended.
   *
   * Malformed bodies surface as a rejected receipt (rejectedReason set),
   * matching Python's `legacy_status="rejected"` path; a successful merge
   * returns acceptedCount=1.
   */
  private _absorbContactUpdate(manifest: Manifest, body: Map<string, Uint8Array>): AbsorbReceipt {
    const reject = (reason: string): AbsorbReceipt => ({
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: reason,
    });

    const pkgBytes = body.get("body/contact_update.json");
    if (pkgBytes === undefined) {
      return reject("contact_update body missing `body/contact_update.json`");
    }
    let doc: unknown;
    try {
      doc = JSON.parse(new TextDecoder("utf-8").decode(pkgBytes));
    } catch (e) {
      return reject(`contact_update body is not valid JSON: ${(e as Error).message}`);
    }
    const errors = _validateContactUpdateBody(doc);
    if (errors.length > 0) {
      return reject("contact_update body invalid: " + errors.join("; "));
    }

    _applyContactUpdate(this._contactsYamlPath(), doc as Record<string, unknown>);

    return {
      kind: manifest.kind,
      acceptedCount: 1,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
    };
  }

  /** Canonical contacts.yaml path for this ceremony. Mirrors Python's
   *  `tn.contacts._contacts_yaml_path` -> `tn_dir(yaml_path)/contacts.yaml`,
   *  i.e. `<yamlDir>/.tn/<stem>/contacts.yaml` where `<stem>` is the yaml
   *  filename without its `.yaml`/`.yml` suffix. */
  private _contactsYamlPath(): string {
    const yamlPath = this.config.yamlPath;
    const base = yamlPath.split(/[\\/]/).pop() ?? "tn.yaml";
    const stem = base.replace(/\.ya?ml$/i, "");
    return join(this.config.yamlDir, ".tn", stem, "contacts.yaml");
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
    const rejectedReason = kitBundleInstallRejection({
      kind: manifest.kind,
      fromDid: manifest.fromDid,
      ...(manifest.toDid === undefined ? {} : { toDid: manifest.toDid }),
      localDid: this.did,
      names: body.keys(),
    });
    if (rejectedReason !== null) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason,
      };
    }
    const ts = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";
    let accepted = 0;
    let skipped = 0;
    const replaced: string[] = [];
    for (const [name, data] of body) {
      if (!name.startsWith("body/")) continue;
      const rel = name.slice("body/".length);
      const dest =
        manifest.kind === "full_keystore" && rel === "tn.yaml"
          ? this.config.yamlPath
          : pathResolve(keystore, rel);
      if (existsSync(dest)) {
        const existing = readFileSync(dest);
        if (existing.length === data.length && Buffer.from(existing).equals(Buffer.from(data))) {
          skipped += 1;
          continue;
        }
        const backup = `${dest}.previous.${ts}`;
        renameSync(dest, backup);
        replaced.push(dest);
      }
      atomicWriteKitMember(dest, data, kitMemberIsSecret(rel));
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
  // group_keys — two-device group sync (DAY-1).
  // ---------------------------------------------------------------------------

  /**
   * Pack a `group_keys` `.tnpkg` carrying this ceremony's group KEY material
   * so a second device on the SAME account can INSTALL + ROUTE the groups
   * after `pull -> absorb`.
   *
   * Body  : `body/keys/<group>.btn.state` + `body/keys/<group>.btn.mykit`
   *         for every btn group (minus `tn.agents`, which every ceremony
   *         mints locally).
   * State : `{ groups: { <name>: <yaml-block> } }` — the EXACT authoritative
   *         `groups.<name>` block (policy/cipher/recipients/fields), so absorb
   *         re-registers the group without re-deriving it.
   *
   * Self-addressed (fromDid === toDid === the author DID) — it rides the
   * OWN-account inbox. Returns the path.
   *
   * NO device secret (`local.private`) is carried — the two devices keep
   * their distinct identities; only the shared group publisher keys travel.
   *
   * Wire kind: `full_keystore` with `scope: "group_keys"`. The vault's inbox
   * route accepts `full_keystore` (a known kind) and does NOT enforce its body
   * contents; the `scope` marker + `state.groups` block tell the TS absorb to
   * route this to the group-key installer (`_absorbGroupKeys`) rather than the
   * blanket keystore overwrite — so no new server-side kind is required.
   *
   * `opts.signWith` / `opts.authorDid` let the caller author the snapshot AS
   * the account-bound IDENTITY device key (the vault's inbox POST requires
   * `manifest.publisher_identity == auth_did`). When omitted, the ceremony's
   * own device key signs (self-contained / test path).
   */
  exportGroupKeys(
    outPath: string,
    opts: { groups?: string[]; signWith?: DeviceKey; authorDid?: string } = {},
  ): string {
    const keystore = this.config.keystorePath;
    if (!existsSync(keystore) || !statSync(keystore).isDirectory()) {
      throw new Error(`group_keys: keystore directory not found: ${keystore}`);
    }

    // Resolve the authoritative groups.<name> blocks once.
    const authYaml = authoritativeYamlFor(this.config.yamlPath, "groups");
    const authDoc = existsSync(authYaml)
      ? ((parseYaml(readFileSync(authYaml, "utf8")) as Record<string, unknown>) ?? {})
      : {};
    const authGroups = (authDoc.groups ?? {}) as Record<string, Record<string, unknown>>;

    const requested = opts.groups && opts.groups.length > 0 ? new Set(opts.groups) : null;

    const body: Record<string, Uint8Array> = {};
    const blocks: Record<string, Record<string, unknown>> = {};
    const carried: string[] = [];

    for (const [group] of this.config.groups) {
      if (group === "tn.agents") continue; // minted locally on every ceremony
      const gcfg = this.config.groups.get(group);
      if (gcfg && gcfg.cipher !== "btn") continue;
      if (requested && !requested.has(group)) continue;
      const statePath = join(keystore, `${group}.btn.state`);
      const mykitPath = join(keystore, `${group}.btn.mykit`);
      if (!existsSync(statePath) || !existsSync(mykitPath)) continue;
      body[`body/keys/${group}.btn.state`] = new Uint8Array(readFileSync(statePath));
      body[`body/keys/${group}.btn.mykit`] = new Uint8Array(readFileSync(mykitPath));
      // Carry the authoritative yaml block if present, else a minimal one.
      blocks[group] = ownEntry(authGroups, group) ?? {
        policy: gcfg?.policy ?? "private",
        cipher: "btn",
        recipients: this.did ? [{ recipient_identity: this.did }] : [],
      };
      carried.push(group);
    }

    if (carried.length === 0) {
      throw new Error(
        `group_keys: no btn groups with key material in ${keystore}` +
          (requested ? ` matching [${[...requested].sort().join(", ")}]` : ""),
      );
    }

    const signKey = opts.signWith ?? this.keystore.device;
    const authorDid = opts.authorDid ?? signKey.did;
    const manifest = newManifest({
      // full_keystore is a server-known kind; the scope marker below routes
      // the absorb to the group-key installer (no new wire kind needed).
      kind: "full_keystore",
      fromDid: authorDid,
      ceremonyId: this.config.ceremonyId,
      scope: "group_keys",
      toDid: authorDid,
    });
    manifest.state = { groups: blocks, kind: "group-keys-v1" };
    signManifestWithBody(manifest, body, signKey);
    return writeTnpkg(outPath, manifest, body);
  }

  /**
   * Absorb a `group_keys` snapshot: INSTALL the group key files into the
   * keystore (content-addressed — identical bytes skip, different bytes back
   * up + replace) AND register each carried group in the receiver's
   * authoritative yaml `groups:` block (union — a group already present is
   * left untouched; a new group is added). After this, a fresh
   * `NodeRuntime.init` over the same yaml routes `tn.info`/read through the
   * group (USABLE, not merely known).
   *
   * Idempotent: re-absorbing the same snapshot is a no-op. Two devices that
   * add DIFFERENT groups and cross-sync end with the UNION of both — no
   * clobber, because each `.btn.state` is keyed by its own group name and the
   * yaml merge skips groups already present.
   *
   * Must be self-addressed (fromDid === toDid) — group_keys only flows within
   * one account, never between counterparties.
   */
  private _absorbGroupKeys(manifest: Manifest, body: Map<string, Uint8Array>): AbsorbReceipt {
    if (manifest.toDid !== undefined && manifest.fromDid !== manifest.toDid) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason: `group_keys must be self-addressed (fromDid === toDid).`,
      };
    }

    const keystore = this.config.keystorePath;
    if (!existsSync(keystore)) mkdirSync(keystore, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";

    // Step A: install key material crash-safely, per group. The carried
    // state+kit for a group are committed as a matched PAIR through the same
    // pending->archive->promote dance rotateGroup uses (commitGroupKeys), so a
    // crash mid-absorb is repaired on the next loadKeystore rather than
    // stranding the member. The superseded files are archived as LOADABLE
    // `.revoked.<ts>` (NOT `.previous.<ts>` which the cipher ignores) so a
    // PRIOR member catching up to a rotation through this sync keeps read
    // access to everything from before it. Mirrors Python _absorb_group_keys.
    let accepted = 0;
    let deduped = 0;
    const replaced: string[] = [];
    const byGroup = new Map<string, { stateBytes?: Uint8Array; selfKit?: Uint8Array }>();
    for (const [name, data] of body) {
      if (!name.startsWith("body/keys/")) continue;
      const rel = name.slice("body/keys/".length);
      if (!rel) continue;
      if (rel.includes("/") || rel.includes("\\")) continue; // flat only
      // Only group key material — never a device secret.
      let group: string | undefined;
      let slot: "stateBytes" | "selfKit" | undefined;
      if (rel.endsWith(".btn.state")) {
        group = rel.slice(0, -".btn.state".length);
        slot = "stateBytes";
      } else if (rel.endsWith(".btn.mykit")) {
        group = rel.slice(0, -".btn.mykit".length);
        slot = "selfKit";
      } else {
        continue;
      }
      const dest = pathResolve(keystore, rel);
      if (existsSync(dest) && Buffer.from(readFileSync(dest)).equals(Buffer.from(data))) {
        deduped += 1;
        continue; // byte-identical: nothing to install
      }
      if (existsSync(dest)) replaced.push(dest);
      const entry = byGroup.get(group) ?? {};
      entry[slot] = new Uint8Array(data);
      byGroup.set(group, entry);
      accepted += 1;
    }
    for (const [group, keys] of byGroup) {
      commitGroupKeys(keystore, group, { ...keys, archiveTs: ts });
    }

    // Step B: register each carried group in the authoritative yaml (union).
    const blocks =
      manifest.state && typeof manifest.state === "object"
        ? ((manifest.state as Record<string, unknown>).groups as
            | Record<string, Record<string, unknown>>
            | undefined)
        : undefined;
    if (blocks && Object.keys(blocks).length > 0) {
      const target = authoritativeYamlFor(this.config.yamlPath, "groups");
      const doc = existsSync(target)
        ? ((parseYaml(readFileSync(target, "utf8")) as Record<string, unknown>) ?? {})
        : {};
      const groups = (doc.groups ?? {}) as Record<string, Record<string, unknown>>;
      let changed = false;
      for (const [group, block] of Object.entries(blocks)) {
        if (group === "tn.agents") continue;
        if (ownEntry(groups, group)) continue; // union: keep the local block, don't clobber
        groups[group] = block;
        changed = true;
        accepted += 1;
      }
      if (changed) {
        doc.groups = groups;
        writeFileSync(target, stringifyYaml(doc), "utf8");
        // Drop the cached wasm runtime so a same-process re-read re-attaches
        // off the freshly-written yaml + keystore and routes the new groups.
        this._resetWasmAfterAdminWrite();
      }
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
    // Trusted enrollment: reverify retained offers and auto-promote only
    // challenged, preauthorized bindings (mirrors the Python init-time
    // reconcile tail). Best-effort: no retained state means a fast no-op,
    // and a conflict never aborts recipient reconciliation.
    try {
      reconcileTrustedOffers(this.config, this.keystore.device);
    } catch {
      // Enrollment-state failures surface on the explicit verbs instead.
    }

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
  *read(logPath?: string, expectGenesis = false): Generator<ReadEntry, void, void> {
    const sources = this._collectReadSources(logPath);
    const prevHashByType = new Map<string, string>();
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
      // Chain continuity check (per event_type, matches Python). The
      // off-by-default genesis anchor lives in verifyChainLink.
      const chainOk = verifyChainLink(
        prevHashByType,
        eventType,
        envPrevHash,
        String(env["row_hash"] ?? ""),
        expectGenesis,
      );
      const entry = this._decodeReadEnvelope(env, chainOk);
      yield entry;
    }
  }

  // Collect the ndjson source lines to read (with origin path + extracted
  // timestamp for stable cross-file ordering). A templated `log` glob-expands
  // to every rendered file; an explicit path reads that one file; the default
  // merges the main log with the admin log. Lines are sorted by sequence (the
  // chain's emission counter), with timestamp as the tiebreak; unparseable
  // lines keep seq=-1 so they sort to the front and surface their JSON error
  // in read()'s main loop with the correct path:lineno.
  private _collectReadSources(
    logPath?: string,
  ): { path: string; lineno: number; line: string; ts: string }[] {
    type SourceLine = { path: string; lineno: number; line: string; ts: string; seq: number };
    const sources: SourceLine[] = [];
    const collect = (path: string): void => {
      if (!existsSync(path)) return;
      const text = readFileSync(path, "utf8");
      let lineno = 0;
      for (const rawLine of text.split(/\r?\n/)) {
        lineno += 1;
        if (!rawLine) continue;
        let ts = "";
        let seq = -1;
        try {
          const env = JSON.parse(rawLine) as Record<string, unknown>;
          const t = env["timestamp"];
          if (typeof t === "string") ts = t;
          const s = env["sequence"];
          if (typeof s === "number") seq = s;
          else if (typeof s === "string" && s.trim() !== "" && !Number.isNaN(Number(s)))
            seq = Number(s);
        } catch {
          // Leave ts = "" / seq = -1 (unparseable sorts to the front).
        }
        sources.push({ path, lineno, line: rawLine, ts, seq });
      }
    };

    if (logPath !== undefined) {
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

    // Order by the chain's authoritative emission counter (sequence), not the
    // wall clock. Wall-clock timestamps aren't guaranteed monotonic under load,
    // which intermittently reordered near-simultaneous entries and broke
    // per-event-type prev_hash chain verification. Timestamp is the tiebreak
    // for any legacy rows without a sequence; unparseable lines (seq=-1) still
    // sort to the front to surface their JSON error first.
    sources.sort((a, b) => a.seq - b.seq || a.ts.localeCompare(b.ts));
    return sources;
  }

  // Decode one parsed envelope into a ReadEntry: identify group ciphertexts,
  // gather public fields, recompute the row_hash, verify the signature, and
  // decrypt each group we hold kits for. `chainOk` is supplied by the caller
  // (read tracks per-event-type chain continuity; a single line cannot).
  private _decodeReadEnvelope(env: Record<string, unknown>, chainOk: boolean): ReadEntry {
    const eventType = String(env["event_type"] ?? "");
    const envPrevHash = String(env["prev_hash"] ?? ZERO_HASH());
    const envRowHash = String(env["row_hash"] ?? "");
    const envSig = String(env["signature"] ?? "");
    const envDid = String(env["device_identity"] ?? "");
    const envTs = String(env["timestamp"] ?? "");
    const envEventId = String(env["event_id"] ?? "");
    const envLevel = String(env["level"] ?? "");

    const groupRaw = _identifyGroupPayloads(env);

    const publicFields: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(env)) {
      if (!_ENVELOPE_RESERVED.has(k) && !groupRaw.has(k) && this.config.publicFields.has(k)) {
        publicFields[k] = v;
      }
    }
    // The ``tn_aad`` echo is an authenticated public field the writer folded
    // into row_hash even though it is not a user-declared public field. Fold
    // it back so recompute matches — and so a tampered echo flips row_hash to
    // invalid alongside the AEAD failure.
    if ("tn_aad" in env) {
      publicFields["tn_aad"] = env["tn_aad"];
    }

    const groupsForHash: Record<
      string,
      { ciphertext_b64: string; field_hashes: Record<string, string> }
    > = {};
    for (const [gname, g] of groupRaw) {
      groupsForHash[gname] = {
        ciphertext_b64: Buffer.from(g.ct).toString("base64"),
        field_hashes: g.fieldHashes,
      };
    }
    let rowHashOk: boolean;
    try {
      const recomputed = computeRowHash({
        device_identity: envDid,
        timestamp: envTs,
        event_id: envEventId,
        event_type: eventType,
        level: envLevel,
        prev_hash: envPrevHash,
        public_fields: publicFields,
        groups: groupsForHash,
      });
      rowHashOk = recomputed === envRowHash;
    } catch {
      rowHashOk = false;
    }

    let sigOk: boolean;
    try {
      const sig = signatureFromB64(asSignatureB64(envSig));
      sigOk = verify(asDid(envDid), new Uint8Array(Buffer.from(envRowHash, "utf8")), sig);
    } catch {
      sigOk = false;
    }

    const plaintext: Record<string, Record<string, unknown>> = {};
    for (const [gname, g] of groupRaw) {
      plaintext[gname] = decryptGroup(
        { ct: g.ct, aad: aadBytesFor(env, gname) },
        this._kitsForGroup(gname),
      ) as Record<string, unknown>;
    }

    return {
      envelope: env,
      plaintext,
      valid: { signature: sigOk, rowHash: rowHashOk, chain: chainOk },
    };
  }

  /** Assemble the decrypt kits for one group from the loaded keystore,
   *  keyed by the group's declared cipher. hibe groups carry the mpk plus
   *  the precomputed candidate keys (held sk, derived-down, superseded
   *  `.previous` keys, and — authority-side — msk-minted keys for the
   *  current and prior identity paths). */
  private _kitsForGroup(gname: string): GroupKits {
    const gk = this.keystore.groups.get(gname);
    const cipherKind = (this.config.groups.get(gname)?.cipher ?? "btn") as CipherKind;
    if (cipherKind === "hibe") {
      const kits: GroupKits = { cipher: "hibe", kits: gk?.hibeKits ?? [] };
      if (gk?.hibe) kits.mpk = gk.hibe.mpk;
      return kits;
    }
    if (cipherKind === "jwe") {
      // Current reader key first, then rotation-archived `.revoked.<ts>` keys.
      return { cipher: "jwe", kits: gk?.jweKeys ?? [] };
    }
    return { cipher: cipherKind, kits: gk?.kits ?? [] };
  }

  /** Async-compatible sibling of {@link read}. Signature/row_hash/chain and
   * cipher opening use the same Rust-backed primitives as synchronous read. */
  async *readAsync(logPath?: string, expectGenesis = false): AsyncGenerator<ReadEntry, void, void> {
    const sources = this._collectReadSources(logPath);
    const prevHashByType = new Map<string, string>();
    for (const src of sources) {
      const { path, lineno, line: rawLine } = src;
      let env: Record<string, unknown>;
      try {
        env = JSON.parse(rawLine) as Record<string, unknown>;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`${path}:${lineno}: invalid JSON: ${msg}`, { cause: e });
      }
      const eventType = String(env["event_type"] ?? "");
      const envPrevHash = String(env["prev_hash"] ?? ZERO_HASH());
      const chainOk = verifyChainLink(
        prevHashByType,
        eventType,
        envPrevHash,
        String(env["row_hash"] ?? ""),
        expectGenesis,
      );
      yield await this._decodeReadEnvelopeAsync(env, chainOk);
    }
  }

  /** Decode one envelope for the async iterator. Reuses the synchronous decode,
   * then overlays jwe plaintext through the compatibility async delegate. */
  private async _decodeReadEnvelopeAsync(
    env: Record<string, unknown>,
    chainOk: boolean,
  ): Promise<ReadEntry> {
    const entry = this._decodeReadEnvelope(env, chainOk);
    for (const [gname, g] of _identifyGroupPayloads(env)) {
      if (this.config.groups.get(gname)?.cipher !== "jwe") continue;
      entry.plaintext[gname] = (await decryptGroupAsync(
        { ct: g.ct, aad: aadBytesFor(env, gname) },
        this._kitsForGroup(gname),
      )) as Record<string, unknown>;
    }
    return entry;
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
    const envPrevHash = String(env["prev_hash"] ?? ZERO_HASH());
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
    // Fold the authenticated ``tn_aad`` echo back for the recompute (see the
    // matching note in `_decodeReadEnvelope`).
    if ("tn_aad" in env) {
      publicFields["tn_aad"] = env["tn_aad"];
    }

    // Recompute row_hash.
    const groupsForHash: Record<
      string,
      { ciphertext_b64: string; field_hashes: Record<string, string> }
    > = {};
    for (const [gname, g] of groupRaw) {
      groupsForHash[gname] = {
        ciphertext_b64: Buffer.from(g.ct).toString("base64"),
        field_hashes: g.fieldHashes,
      };
    }
    let rowHashOk: boolean;
    try {
      const recomputed = computeRowHash({
        device_identity: envDid,
        timestamp: envTs,
        event_id: envEventId,
        event_type: eventType,
        level: envLevel,
        prev_hash: envPrevHash,
        public_fields: publicFields,
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
      plaintext[gname] = decryptGroup(
        { ct: g.ct, aad: aadBytesFor(env, gname) },
        this._kitsForGroup(gname),
      ) as Record<string, unknown>;
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

// Identify the group ciphertext payloads on an envelope, decoding each
// ciphertext from base64 and reading its field hashes (Rust may write
// `field_hashes` (snake) or `fieldHashes` (camel)).
function _identifyGroupPayloads(
  env: Record<string, unknown>,
): Map<string, { ct: Uint8Array; fieldHashes: Record<string, string> }> {
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
  return groupRaw;
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
  /** Optional human label baked into an `identity_seed` bundle's
   *  `state.identity.nickname`. Mirrors Python's `export(nickname=...)`.
   *  Ignored for other kinds. */
  nickname?: string;
  /** Required for `kind: "contact_update"`: the contact-record body that
   *  becomes `body/contact_update.json`. Shape (spec §4.6):
   *  `{account_id, label, package_did, x25519_pub_b64, claimed_at,
   *  source_link_id}` — the three latter fields may be null. */
  contactUpdate?: ContactUpdateBody;
}

/** Body of a `contact_update` tnpkg (mirrors Python's contacts.py shape).
 *  `package_did` / `x25519_pub_b64` / `source_link_id` are nullable. */
export interface ContactUpdateBody {
  account_id: string;
  label: string;
  package_did: string | null;
  x25519_pub_b64: string | null;
  claimed_at: string;
  source_link_id: string | null;
}

/** Placeholder ceremony id stamped into a self-issued `identity_seed`
 *  manifest (it has no enclosing ceremony). Mirrors Python's
 *  `export.IDENTITY_SEED_CEREMONY_PLACEHOLDER`. */
const IDENTITY_SEED_CEREMONY_PLACEHOLDER = "_identity_seed";

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
    case "identity_seed":
      return "identity";
    default:
      return "admin";
  }
}

// ---------------------------------------------------------------------------
// contact_update reducer — port of python/tn/contacts.py.
// ---------------------------------------------------------------------------

/** Every contact_update body must carry these keys. The three nullable
 *  ones are required-present-but-may-be-null per the plan. */
const _CONTACT_REQUIRED_KEYS = [
  "account_id",
  "label",
  "package_did",
  "x25519_pub_b64",
  "claimed_at",
  "source_link_id",
] as const;

/** Subset that must be non-null, non-empty strings. */
const _CONTACT_NON_NULL_STRING_KEYS = ["account_id", "label", "claimed_at"] as const;

/** Validate a contact_update body. Returns a list of error strings; `[]`
 *  means valid. Mirrors Python's `_validate_contact_update_body`. */
function _validateContactUpdateBody(doc: unknown): string[] {
  const errors: string[] = [];
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return [
      `contact_update body must be a JSON object; got ${Array.isArray(doc) ? "array" : typeof doc}`,
    ];
  }
  const d = doc as Record<string, unknown>;
  for (const key of _CONTACT_REQUIRED_KEYS) {
    if (!(key in d)) errors.push(`missing required key '${key}'`);
  }
  for (const key of _CONTACT_NON_NULL_STRING_KEYS) {
    const v = d[key];
    if (v === null || v === undefined) {
      errors.push(`required key '${key}' must not be null`);
    } else if (typeof v !== "string" || v === "") {
      errors.push(`required key '${key}' must be a non-empty string`);
    }
  }
  for (const key of ["package_did", "x25519_pub_b64", "source_link_id"] as const) {
    if (!(key in d)) continue; // missing handled above
    const v = d[key];
    if (v === null || v === undefined) continue;
    if (typeof v !== "string") errors.push(`key '${key}' must be a string or null`);
  }
  return errors;
}

/** Serialize a validated contact_update body to canonical JSON: the six
 *  fields in a fixed order, nullable fields explicit-null. Deterministic
 *  so the on-the-wire `body/contact_update.json` is stable across runs.
 *  Python consumes it with `json.loads`, so only the parsed values
 *  matter to the reducer; the fixed order keeps OUR output reproducible. */
function _canonicalContactUpdateJson(body: ContactUpdateBody): string {
  const b = body as unknown as Record<string, unknown>;
  const ordered: Record<string, unknown> = {
    account_id: b["account_id"],
    label: b["label"],
    package_did: b["package_did"] ?? null,
    x25519_pub_b64: b["x25519_pub_b64"] ?? null,
    claimed_at: b["claimed_at"],
    source_link_id: b["source_link_id"] ?? null,
  };
  return JSON.stringify(ordered);
}

/** Idempotency key `(account_id, package_did)`,
 *  treating null as a valid value. */
function _contactRowMatches(
  existing: Record<string, unknown>,
  incoming: Record<string, unknown>,
): boolean {
  return (
    (existing["account_id"] ?? null) === (incoming["account_id"] ?? null) &&
    (existing["package_did"] ?? null) === (incoming["package_did"] ?? null)
  );
}

/** Merge a validated contact_update body into contacts.yaml at
 *  `targetPath`. Mirrors Python's `_apply_contact_update`: project to the
 *  canonical row shape, match on (account_id, package_did) -> replace in
 *  place, else append. Writes `{contacts: [...]}`. */
function _applyContactUpdate(targetPath: string, body: Record<string, unknown>): void {
  // Canonical row shape (null for absent nullable fields), matching
  // Python's projection so downstream readers get a stable schema.
  const row: Record<string, unknown> = {
    account_id: body["account_id"],
    label: body["label"],
    package_did: body["package_did"] ?? null,
    x25519_pub_b64: body["x25519_pub_b64"] ?? null,
    claimed_at: body["claimed_at"],
    source_link_id: body["source_link_id"] ?? null,
  };

  // Load existing contacts.yaml (or an empty doc).
  let doc: Record<string, unknown> = { contacts: [] };
  if (existsSync(targetPath)) {
    const raw = readFileSync(targetPath, "utf8");
    if (raw.trim()) {
      const parsed = parseYaml(raw) as unknown;
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        doc = parsed as Record<string, unknown>;
      }
    }
  }
  let contacts = doc["contacts"];
  if (!Array.isArray(contacts)) {
    contacts = [];
    doc["contacts"] = contacts;
  }
  const list = contacts as Record<string, unknown>[];

  let replaced = false;
  for (let i = 0; i < list.length; i += 1) {
    const existing = list[i];
    if (existing === null || typeof existing !== "object") continue;
    if (_contactRowMatches(existing, row)) {
      list[i] = row;
      replaced = true;
      break;
    }
  }
  if (!replaced) list.push(row);
  doc["contacts"] = list;

  mkdirSync(dirname(targetPath), { recursive: true });
  writeFileSync(targetPath, stringifyYaml(doc), "utf8");
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

// ---- admin-log-snapshot absorb helpers -----------------------------------
// Each revoked leaf carries the revoke's (did, sequence) so a reuse attempt
// can be classified informed-vs-concurrent against the snapshot clock
// (mirrors Python `_build_revoked_leaves`).
type RevokedLeaf = { rowHash: string | null; did: string | null; seq: number | null };

function _revokedLeafFrom(env: Record<string, unknown>, rh: unknown): RevokedLeaf {
  const did = env["device_identity"];
  const seq = env["sequence"];
  return {
    rowHash: typeof rh === "string" ? rh : null,
    did: typeof did === "string" ? did : null,
    seq: typeof seq === "number" ? seq : null,
  };
}

// Parse each non-empty ndjson line of an admin log on disk, invoking `fn` with
// the decoded envelope. Bad JSON / a missing file are silently skipped.
function _forEachAdminLogEnvelope(
  adminLog: string,
  fn: (env: Record<string, unknown>) => void,
): void {
  if (!existsSync(adminLog)) return;
  for (const rawLine of readFileSync(adminLog, "utf8").split(/\r?\n/)) {
    const s = rawLine.trim();
    if (!s) continue;
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(s) as Record<string, unknown>;
    } catch {
      continue;
    }
    fn(env);
  }
}

// Build the local vector clock {did -> {event_type -> max_seq}} from the
// admin log already on disk.
function _localClockFromAdminLog(adminLog: string): VectorClock {
  const localClock: VectorClock = {};
  _forEachAdminLogEnvelope(adminLog, (env) => {
    const did = env["device_identity"];
    const et = env["event_type"];
    const seq = env["sequence"];
    if (typeof did === "string" && typeof et === "string" && typeof seq === "number") {
      const slot = localClock[did] ?? {};
      const cur = slot[et] ?? 0;
      if (seq > cur) slot[et] = seq;
      localClock[did] = slot;
    }
  });
  return localClock;
}

// Build the revoked-leaf map {`group leaf` -> RevokedLeaf} from the admin log
// already on disk (used to classify later reuse attempts).
function _revokedLeavesFromAdminLog(adminLog: string): Map<string, RevokedLeaf> {
  const revokedLeaves = new Map<string, RevokedLeaf>();
  _forEachAdminLogEnvelope(adminLog, (env) => {
    if (env["event_type"] !== "tn.recipient.revoked") return;
    const g = env["group"];
    const li = env["leaf_index"];
    const rh = env["row_hash"];
    if (typeof g === "string" && typeof li === "number") {
      revokedLeaves.set(`${g} ${li}`, _revokedLeafFrom(env, rh));
    }
  });
  return revokedLeaves;
}

interface SnapshotIngest {
  acceptedEnvs: Record<string, unknown>[];
  conflicts: ChainConflict[];
  deduped: number;
}

// Ingest the snapshot's `body/admin.ndjson`: drop malformed/unsigned/duplicate
// envelopes, flag leaf-reuse against `revokedLeaves` (mutated as revokes are
// seen), and accumulate accepted envelopes. `seenRowHashes` is mutated to
// track dedupe across the producer log + snapshot.
function _ingestSnapshotEnvelopes(
  raw: Uint8Array,
  seenRowHashes: Set<string>,
  revokedLeaves: Map<string, RevokedLeaf>,
  manifestClock: VectorClock,
): SnapshotIngest {
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
            originallyRevokedAtRowHash: revokedLeaves.get(k)?.rowHash ?? null,
            informed: reuseIsInformed(
              revokedLeaves.get(k)?.did ?? null,
              revokedLeaves.get(k)?.seq ?? null,
              manifestClock,
            ),
          };
          conflicts.push(reuse);
        }
      }
    }
    if (env["event_type"] === "tn.recipient.revoked") {
      const g = env["group"];
      const li = env["leaf_index"];
      if (typeof g === "string" && typeof li === "number") {
        revokedLeaves.set(`${g} ${li}`, _revokedLeafFrom(env, rh));
      }
    }
    acceptedEnvs.push(env);
    seenRowHashes.add(rh);
  }
  return { acceptedEnvs, conflicts, deduped };
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
  /** Group-sealing cipher for the fresh ceremony's `default` group.
   *  `"btn"` (default) or `"hibe"` (the keystore becomes its own HIBE
   *  authority — Setup + msk + a self-delegated reader key on `"self"`),
   *  or `jwe` (a per-recipient ECDH-ES group; the creator becomes publisher
   *  and sole reader). The reserved `tn.agents` group always stays btn
   *  (kit-bundle onboarding), matching Python's `create_fresh`. */
  cipher?: "btn" | "hibe" | "jwe";
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

  const cipher = opts.cipher ?? "btn";
  if (cipher !== "btn" && cipher !== "hibe" && cipher !== "jwe") {
    throw new Error(
      `createFreshCeremony: unknown cipher ${JSON.stringify(cipher)}; expected 'btn', 'hibe', or 'jwe'.`,
    );
  }

  // Fresh default-group key material: btn publisher + self-kit, or a hibe
  // authority (Setup + msk + self-delegated reader key on "self").
  let stateBytes: Uint8Array | null = null;
  let selfKit: Uint8Array | null = null;
  if (cipher === "btn") {
    const btnSeed = new Uint8Array(randomBytes(32));
    const pub = new BtnPublisher(btnSeed);
    selfKit = pub.mint();
    stateBytes = pub.toBytes();
    pub.free();
  }

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
  if (cipher === "btn") {
    writeFileSync(join(keysDir, "default.btn.state"), Buffer.from(stateBytes!));
    writeFileSync(join(keysDir, "default.btn.mykit"), Buffer.from(selfKit!));
  } else if (cipher === "hibe") {
    createHibeGroup(keysDir, "default");
  } else {
    createJweGroup(keysDir, "default", dk.did);
  }
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
    ? rel(opts.adminLogPath, `./.tn/${yamlStem}/admin/default.ndjson`)
    : `./.tn/${yamlStem}/admin/default.ndjson`;
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
  cipher: ${cipher}
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
    cipher: ${cipher}
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
