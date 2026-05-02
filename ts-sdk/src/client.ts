// TNClient: the public SDK surface for TypeScript.
//
// Thin wrapper over NodeRuntime that exposes the cipher-agnostic verb set
// described in tn-protocol/docs/sdk-parity.md. The goal is that a developer
// moving from Python or Rust to TypeScript finds the same names and semantics.
//
// Foundational writes (`emit`, `emitWith`, …) live on NodeRuntime. This class
// adds log-level wrappers (log/debug/info/warning/error) and the admin +
// lifecycle surface, so `TNClient` is the recommended entry point for apps;
// `NodeRuntime` remains accessible for the lower-level calls.

import { Buffer } from "node:buffer";
import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve } from "node:path";

import * as admin from "./admin.js";
import { normalizeLogFields } from "./_log_fields.js";
import {
  AdminStateCache,
  type ChainConflict,
  type LeafReuseAttempt,
} from "./admin_cache.js";
import {
  appendAdminEnvelopes,
  existingRowHashes,
  isAdminEventType,
  resolveAdminLogPath,
} from "./admin_log.js";
import type { TNHandler } from "./handlers/index.js";
import { StdoutHandler } from "./handlers/stdout.js";
import { readAsRecipient } from "./read_as_recipient.js";
import {
  NodeRuntime,
  setSigning as _runtimeSetSigning,
  type EmitReceipt,
  type ReadEntry,
} from "./runtime/node_runtime.js";
import { signatureFromB64, verify as verifySig } from "./core/signing.js";
import {
  KNOWN_KINDS,
  type Manifest,
  type ManifestKind,
  type VectorClock,
  clockDominates,
  isManifestSignatureValid,
  newManifest,
  signManifest,
  verifyManifest,
} from "./core/tnpkg.js";
import { readTnpkg, writeTnpkg } from "./tnpkg_io.js";
import { asDid, asSignatureB64 } from "./core/types.js";

export type { EmitReceipt, ReadEntry } from "./runtime/node_runtime.js";
import {
  flattenRawEntry,
  invalidReasonsFromValid,
  attachInstructions,
  type SecureEntry,
} from "./core/read_shape.js";
export type { Instructions, SecureEntry } from "./core/read_shape.js";

// ---------------------------------------------------------------------
// Read-shape helpers (per 2026-04-25 read-ergonomics spec §1).
// Projection logic now lives in core/read_shape.ts (Task 1.7).
// ---------------------------------------------------------------------

/** Peek at the first JSON line of `logPath`; return true iff its
 * envelope's publisher `did` differs from `ownDid`. Used by
 * `client.read({logPath})` to auto-route cross-publisher reads through
 * `readAsRecipient` (FINDINGS S6.2 cross-binding port). Conservative
 * on failure — if the file is unreadable or has no parseable line,
 * return false so the regular path runs and surfaces the underlying
 * error itself. */
function _isForeignLog(logPath: string, ownDid: string): boolean {
  try {
    const text = readFileSync(logPath, "utf8");
    for (const rawLine of text.split(/\r?\n/)) {
      const s = rawLine.trim();
      if (!s) continue;
      let env: Record<string, unknown>;
      try {
        env = JSON.parse(s) as Record<string, unknown>;
      } catch {
        continue;
      }
      const envDid = env["did"];
      if (typeof envDid === "string" && envDid.length > 0) {
        return envDid !== ownDid;
      }
      // First non-empty line had no did — give up; let the regular path
      // do its thing.
      return false;
    }
  } catch {
    return false;
  }
  return false;
}

export interface SecureReadOptions {
  onInvalid?: "skip" | "raise" | "forensic";
  logPath?: string;
}

/** Thrown by `secureRead({onInvalid: "raise"})` on the first verification
 * failure. Mirrors Python `tn.VerificationError`. */
export class VerificationError extends Error {
  readonly envelope: Record<string, unknown>;
  readonly invalidReasons: string[];
  constructor(envelope: Record<string, unknown>, invalidReasons: string[]) {
    const et = envelope["event_type"];
    const eid = envelope["event_id"];
    super(
      `secureRead: envelope event_type=${JSON.stringify(et)} ` +
        `event_id=${JSON.stringify(eid)} failed verification: ` +
        JSON.stringify(invalidReasons),
    );
    this.name = "VerificationError";
    this.envelope = envelope;
    this.invalidReasons = [...invalidReasons];
  }
}

/** Roster entry yielded by `TNClient.recipients`. Matches Python `tn.recipients`. */
export interface RecipientEntry {
  leafIndex: number;
  recipientDid: string | null;
  mintedAt: string | null;
  kitSha256: string | null;
  revoked: boolean;
  revokedAt: string | null;
}

export interface AdminCeremonyState {
  ceremonyId: string;
  cipher: string;
  deviceDid: string;
  createdAt: string | null;
}

export interface AdminGroupState {
  group: string;
  cipher: string;
  publisherDid: string;
  addedAt: string;
}

export interface AdminRecipientState {
  group: string;
  leafIndex: number;
  recipientDid: string | null;
  kitSha256: string;
  mintedAt: string | null;
  activeStatus: "active" | "revoked" | "retired";
  revokedAt: string | null;
  retiredAt: string | null;
}

export interface AdminRotationState {
  group: string;
  cipher: string;
  generation: number;
  previousKitSha256: string;
  rotatedAt: string;
}

export interface AdminCouponState {
  group: string;
  slot: number;
  toDid: string;
  issuedTo: string;
  issuedAt: string | null;
}

export interface AdminEnrolmentState {
  group: string;
  peerDid: string;
  packageSha256: string;
  status: "offered" | "absorbed";
  compiledAt: string | null;
  absorbedAt: string | null;
}

export interface AdminVaultLinkState {
  vaultDid: string;
  projectId: string;
  linkedAt: string;
  unlinkedAt: string | null;
}

export interface AdminState {
  ceremony: AdminCeremonyState | null;
  groups: AdminGroupState[];
  recipients: AdminRecipientState[];
  rotations: AdminRotationState[];
  coupons: AdminCouponState[];
  enrolments: AdminEnrolmentState[];
  vaultLinks: AdminVaultLinkState[];
}

// --- AdminState wire-format conversion --------------------------------
//
// On the wire (manifest.state), AdminState uses snake_case keys to match
// the Python and Rust serializations byte-for-byte. The TS public API
// (AdminState etc.) uses camelCase per TS conventions. These helpers
// convert between the two when crossing the manifest boundary.

const ADMIN_STATE_FIELD_MAP: Record<string, string> = {
  ceremonyId: "ceremony_id",
  deviceDid: "device_did",
  createdAt: "created_at",
  publisherDid: "publisher_did",
  addedAt: "added_at",
  leafIndex: "leaf_index",
  recipientDid: "recipient_did",
  kitSha256: "kit_sha256",
  mintedAt: "minted_at",
  activeStatus: "active_status",
  revokedAt: "revoked_at",
  retiredAt: "retired_at",
  previousKitSha256: "previous_kit_sha256",
  rotatedAt: "rotated_at",
  toDid: "to_did",
  issuedTo: "issued_to",
  issuedAt: "issued_at",
  peerDid: "peer_did",
  packageSha256: "package_sha256",
  compiledAt: "compiled_at",
  absorbedAt: "absorbed_at",
  vaultDid: "vault_did",
  projectId: "project_id",
  linkedAt: "linked_at",
  unlinkedAt: "unlinked_at",
  vaultLinks: "vault_links",
};

const ADMIN_STATE_FIELD_MAP_REVERSE: Record<string, string> = Object.fromEntries(
  Object.entries(ADMIN_STATE_FIELD_MAP).map(([k, v]) => [v, k]),
);

function _convertKeysDeep(
  value: unknown,
  map: Record<string, string>,
): unknown {
  if (Array.isArray(value)) {
    return value.map((v) => _convertKeysDeep(v, map));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const newKey = map[k] ?? k;
      out[newKey] = _convertKeysDeep(v, map);
    }
    return out;
  }
  return value;
}

function adminStateToWire(state: AdminState): Record<string, unknown> {
  return _convertKeysDeep(state, ADMIN_STATE_FIELD_MAP) as Record<string, unknown>;
}

function adminStateFromWire(wire: unknown): AdminState | null {
  if (wire === null || typeof wire !== "object") return null;
  return _convertKeysDeep(wire, ADMIN_STATE_FIELD_MAP_REVERSE) as unknown as AdminState;
}

function _mergeEnvelope(entry: ReadEntry): Record<string, unknown> {
  // Python's recipients() / admin_state() flatten plaintext groups into the
  // envelope so the reducer sees a single dict. Match that exactly.
  const merged: Record<string, unknown> = { ...entry.envelope };
  for (const groupFields of Object.values(entry.plaintext)) {
    if (groupFields && typeof groupFields === "object" && !Array.isArray(groupFields)) {
      Object.assign(merged, groupFields);
    }
  }
  return merged;
}

function _applySchemaDefaults(eventType: string, merged: Record<string, unknown>): void {
  // The Rust emitter stores cipher/recipient_did as implicit defaults but the
  // catalog schema requires them present at reduce time. Mirror the Python
  // workaround so the reducer's schema check passes without altering semantics.
  if (eventType === "tn.recipient.added" && !("cipher" in merged)) {
    merged["cipher"] = "btn";
  }
  if (eventType === "tn.recipient.revoked" && !("recipient_did" in merged)) {
    merged["recipient_did"] = null;
  }
}

/**
 * Resolve whether to attach the default stdout handler at TNClient init.
 *
 * Precedence (mirrors Python `tn.init(stdout=)` + Python's S0.4 fix):
 *   1. Explicit `stdout` kwarg wins outright.
 *   2. `TN_NO_STDOUT=1` env disables.
 *   3. Yaml `handlers:` block is authoritative when non-empty: stdout
 *      fires only if the list explicitly contains a `{kind: "stdout"}`
 *      entry. Removing the entry silences stdout for both admin and
 *      user emits (FINDINGS S0.4).
 *   4. Otherwise (no yaml handlers list at all, no env opt-out, no
 *      kwarg): default-on, matching pre-S0.4 behavior.
 */
function _shouldEnableStdoutFor(
  cfg: { handlers?: Array<Record<string, unknown>> } | undefined,
  kwarg: boolean | undefined,
): boolean {
  if (kwarg !== undefined) return kwarg;
  if (process.env["TN_NO_STDOUT"] === "1") return false;
  const list = cfg?.handlers ?? [];
  if (list.length > 0) {
    return list.some((h) => h && typeof h === "object" && (h as Record<string, unknown>).kind === "stdout");
  }
  return true;
}

/**
 * Standard log-level numeric values. Mirror stdlib Python `logging`.
 * Public so external callers can pass either ``"info"`` strings or
 * the int directly through `setLevel`.
 */
export const LOG_LEVELS = {
  debug: 10,
  info: 20,
  warning: 30,
  error: 40,
} as const;

export type LogLevel = keyof typeof LOG_LEVELS | number;

function _levelValue(level: LogLevel | string): number {
  if (typeof level === "number") return level;
  if (level === "") return -1;
  const lower = level.toLowerCase();
  if (lower in LOG_LEVELS) return LOG_LEVELS[lower as keyof typeof LOG_LEVELS];
  throw new Error(
    `unknown log level ${JSON.stringify(level)}; expected one of ` +
      `${JSON.stringify(Object.keys(LOG_LEVELS))} or a number`,
  );
}

export class TNClient {
  /**
   * Process-wide level threshold (AVL J3.2: stdlib `logging`-style
   * filtering). Verbs whose level is below this value short-circuit
   * before any work happens. Default 10 (`"debug"`) so existing
   * callers see no behavior change. Raise via `TNClient.setLevel(...)`.
   *
   * Static so the early-exit gate is a single-load check, not an
   * instance-attribute hop. Multi-client processes share the same
   * threshold (intentional — stdlib `logging.Logger.setLevel` is also
   * effectively process-wide for the root logger).
   */
  private static _logLevelThreshold: number = LOG_LEVELS.debug;

  private readonly rt: NodeRuntime;
  /**
   * For clients built via `TNClient.ephemeral()`: the absolute path to
   * the tempdir we own. `close()` does best-effort recursive removal.
   * `undefined` for clients built via `init(yamlPath)` — those point at
   * caller-managed paths and must not be deleted on close.
   */
  private ownedTempdir: string | undefined;

  /**
   * Per-client UUID auto-injected as a public field on every emit.
   * Lets `client.read()` default-filter to "this run only" so naive
   * filters don't pick up entries from prior runs (FINDINGS.md #12).
   * Mirrors Python's `_run_id` and Rust's `Runtime.run_id`.
   */
  private readonly _runId: string;

  /**
   * Stack of per-scope context overlays pushed by `client.scope()`.
   * Bottom of the stack is the long-lived context (set via
   * `setContext`/`updateContext`); each `scope()` push layers fresh
   * fields and pops on disposal.
   */
  private _contextStack: Record<string, unknown>[] = [{}];

  private constructor(rt: NodeRuntime, ownedTempdir?: string) {
    this.rt = rt;
    this.ownedTempdir = ownedTempdir;
    // randomUUID() is already imported above for event_id minting.
    this._runId = randomUUID().replace(/-/g, "");
    // Best-effort: emit `tn.agents.policy_published` if the active policy's
    // content_hash differs from the last published one in the log (or none
    // was ever published). Mirrors Python's `_maybe_emit_policy_published`.
    try {
      this._maybeEmitPolicyPublished();
    } catch {
      // Init must not block on best-effort policy bookkeeping.
    }
  }

  /**
   * Load or create a ceremony from a yaml manifest and return a client
   * bound to it. Matches Python `tn.init` and Rust `Runtime::init`.
   *
   * Stdout fan-out is on by default (every emit also writes the canonical
   * NDJSON line to `process.stdout`). Opt out via the `TN_NO_STDOUT=1`
   * env var or `TNClient.init(path, { stdout: false })`.
   */
  static init(yamlPath: string, opts?: { stdout?: boolean }): TNClient {
    const rt = NodeRuntime.init(yamlPath);
    if (_shouldEnableStdoutFor(rt.config, opts?.stdout)) {
      rt.addHandler(new StdoutHandler());
    }
    // Honor yaml `ceremony.log_level` only when a programmatic
    // setLevel() hasn't already locked the threshold (AVL J3.2). The
    // floor default is `LOG_LEVELS.debug`; if the static threshold has
    // moved above that, treat it as caller intent and don't override.
    if (rt.config.logLevel && TNClient._logLevelThreshold === LOG_LEVELS.debug) {
      try {
        TNClient.setLevel(rt.config.logLevel as LogLevel);
      } catch {
        // Bad yaml level — ignore; floor default stays.
      }
    }
    return new TNClient(rt);
  }

  /**
   * Build a client backed by a fresh ceremony in a private tempdir.
   * The tempdir is removed on `close()` (best-effort — failures are
   * swallowed because tempdir cleanup races with file handles on
   * Windows and the tempdir cleanup is informational, not load-bearing).
   *
   * Mirrors Rust `Runtime::ephemeral()` and the test-mode ergonomics of
   * Python's `tn.session()`. Use this in tests and one-shot scripts
   * where the ceremony is throwaway.
   */
  static ephemeral(opts?: { stdout?: boolean }): TNClient {
    const td = mkdtempSync(join(tmpdir(), "tn-ephemeral-"));
    const yamlPath = join(td, "tn.yaml");
    // NodeRuntime.init auto-creates a fresh btn ceremony when the yaml
    // is missing — we just point it at a path inside the tempdir.
    const rt = NodeRuntime.init(yamlPath);
    if (_shouldEnableStdoutFor(rt.config, opts?.stdout)) {
      rt.addHandler(new StdoutHandler());
    }
    return new TNClient(rt, td);
  }

  // ------------------------------------------------------------------
  // Identity / lifecycle
  // ------------------------------------------------------------------

  get did(): string {
    return this.rt.did;
  }

  get logPath(): string {
    return this.rt.config.logPath;
  }

  get config() {
    return this.rt.config;
  }

  close(): void {
    this.rt.close();
    if (this.ownedTempdir !== undefined) {
      const td = this.ownedTempdir;
      // Clear first so a double-close doesn't try to rm a missing dir.
      this.ownedTempdir = undefined;
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        // Best-effort: Windows file-handle races, locked log writers
        // mid-rotation, etc. The OS will clean the temp directory
        // eventually; logging here would be noise.
      }
    }
  }

  addHandler(h: TNHandler): void {
    this.rt.addHandler(h);
  }

  /**
   * Expose the underlying NodeRuntime for low-level primitives
   * (`emit`, custom handlers, etc.). Application code should prefer the
   * verb methods on this class.
   */
  get runtime(): NodeRuntime {
    return this.rt;
  }

  // ------------------------------------------------------------------
  // Write verbs (log-level wrappers over emit)
  //
  // Shapes match Python: `log` is severity-less (emits level=""), the others
  // pass their namesake level to emit. All return `void` for cross-language
  // parity (Python returns None, Rust returns ()) and to keep the REPL
  // free of receipt-dict echoes.
  //
  // Positional `message` ergonomic (matches Python):
  //   client.info("startup", "name = hi")          → fields = {message: "name = hi"}
  //   client.info("startup", "hi", {port: 8080})   → fields = {message: "hi", port: 8080}
  //   client.info("startup", {port: 8080})         → fields = {port: 8080}
  // ------------------------------------------------------------------

  /** Build the merged-fields dict: scope-stack overlays + caller fields
   * + auto-injected run_id. Caller-supplied `run_id` wins. */
  private _mergeForEmit(rawFields: Record<string, unknown>): Record<string, unknown> {
    const merged: Record<string, unknown> = {};
    for (const layer of this._contextStack) {
      for (const [k, v] of Object.entries(layer)) merged[k] = v;
    }
    for (const [k, v] of Object.entries(rawFields)) merged[k] = v;
    if (!("run_id" in merged)) merged["run_id"] = this._runId;
    return merged;
  }

  /**
   * Set the process-wide log-level threshold. Verbs at a lower level
   * short-circuit before any work happens — no encryption, no chain
   * advance, no I/O. Mirrors Python `tn.set_level()` and stdlib
   * `logging.Logger.setLevel`. (AVL J3.2.)
   *
   * The severity-less `client.log()` always emits regardless of the
   * threshold — it's an explicit "this is a fact" primitive.
   */
  static setLevel(level: LogLevel): void {
    TNClient._logLevelThreshold = _levelValue(level);
  }

  /** Return the current threshold as a level name when it matches one
   * of the standard four (debug/info/warning/error), or the numeric
   * value as a string for custom levels. */
  static getLevel(): string {
    const t = TNClient._logLevelThreshold;
    for (const [name, value] of Object.entries(LOG_LEVELS)) {
      if (value === t) return name;
    }
    return String(t);
  }

  /** True iff `level` would currently emit. Use as a guard around
   * expensive log-arg construction. Mirrors stdlib
   * `logging.Logger.isEnabledFor`. */
  static isEnabledFor(level: LogLevel): boolean {
    return _levelValue(level) >= TNClient._logLevelThreshold;
  }

  /** Severity-less attested event. Matches Python `tn.log(event_type, **fields)`.
   * Always emits regardless of `setLevel(...)` — severity-less by design. */
  log(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    this.rt.emit("", eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  debug(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (10 < TNClient._logLevelThreshold) return;
    this.rt.emit("debug", eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  info(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (20 < TNClient._logLevelThreshold) return;
    this.rt.emit("info", eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  warning(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (30 < TNClient._logLevelThreshold) return;
    this.rt.emit("warning", eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  error(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): void {
    if (40 < TNClient._logLevelThreshold) return;
    this.rt.emit("error", eventType, this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)));
  }

  /** Block-scoped context: layers `fields` on top of the current
   * context, runs `body`, restores prior context on return (even if
   * `body` throws). Mirrors Python `with tn.scope(**fields):` and
   * Rust's closure-based equivalent. (FINDINGS.md #8.)
   *
   *     client.scope({sale_id: "abc", register: 2}, () => {
   *       client.info("sale.start");
   *       for (const line of cart) client.info("sale.line", line);
   *       client.info("sale.end", { total });
   *     });
   *     // outside the block, sale_id and register are gone
   */
  scope<T>(fields: Record<string, unknown>, body: () => T): T {
    this._contextStack.push({ ...fields });
    try {
      return body();
    } finally {
      this._contextStack.pop();
    }
  }

  /**
   * Replace the long-lived context with `fields`. Every subsequent
   * emit on this client carries those fields until `setContext` is
   * called again or `clearContext` resets it. Use for per-request
   * middleware (FastAPI dependency, Express middleware, etc.) where
   * the context lives across many emits and a `scope()` closure
   * would be awkward.
   *
   * The bottom of the per-scope stack stores this long-lived
   * context; nested `scope()` blocks layer on top and are restored
   * when their callback returns. Mirrors Python's
   * `tn.set_context(**kwargs)`.
   *
   * Example::
   *
   *     client.setContext({ request_id: "req_abc", user_id: "u_42" });
   *     client.info("page.view", { path: "/checkout" });
   *     // … many emits later …
   *     client.clearContext();
   */
  setContext(fields: Record<string, unknown>): void {
    this._contextStack[0] = { ...fields };
  }

  /**
   * Merge `fields` into the long-lived context (additive; existing
   * keys are overwritten only when the kwarg supplies them). Mirrors
   * Python's `tn.update_context(**kwargs)`. Useful for "I have a
   * request_id from middleware, now layer in a trace_id" flows.
   */
  updateContext(fields: Record<string, unknown>): void {
    this._contextStack[0] = { ...this._contextStack[0], ...fields };
  }

  /**
   * Drop the long-lived context (and any nested `scope()` overlays
   * — emits after this only carry the per-client `run_id`). Mirrors
   * Python's `tn.clear_context()`.
   */
  clearContext(): void {
    this._contextStack = [{}];
  }

  /**
   * Return a shallow copy of the merged context (long-lived + every
   * active `scope()` overlay) the way every emit sees it. Use for
   * diagnostics — e.g. logging the fields a future emit *would*
   * carry. Mirrors Python's `tn.get_context()`.
   */
  getContext(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const layer of this._contextStack) {
      for (const [k, v] of Object.entries(layer)) out[k] = v;
    }
    return out;
  }

  /** Foundational emit. Prefer the level wrappers for readability.
   *
   * Routes through `_mergeForEmit` so context fields and the per-client
   * `run_id` are auto-injected — same behavior as `info`/`log`/`debug`/
   * `warning`/`error`. Without this routing, entries written via
   * `client.emit(...)` are missing `run_id` and silently filtered out by
   * the strict-match `client.read({allRuns: false})` default. */
  emit(level: string, eventType: string, fields: Record<string, unknown>): EmitReceipt {
    return this.rt.emit(level, eventType, this._mergeForEmit(fields));
  }

  /**
   * `emit` with explicit `timestamp` / `eventId` overrides — useful for
   * deterministic tests and replay tooling. Mirrors Python's `_timestamp`
   * / `_event_id` kwargs and Rust's `Runtime::emit_with`.
   */
  emitWith(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    opts?: { timestamp?: string; eventId?: string },
  ): EmitReceipt {
    return this.rt.emitWith(level, eventType, this._mergeForEmit(fields), opts);
  }

  /**
   * Per-call signing override. `true` forces signing, `false` skips it,
   * `null` falls back to the session/yaml default.
   * Mirrors Python's `_sign=` kwarg + Rust `Runtime::emit_override_sign`.
   */
  emitOverrideSign(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    sign: boolean | null,
  ): EmitReceipt {
    return this.rt.emitOverrideSign(level, eventType, this._mergeForEmit(fields), sign);
  }

  /** Full-control emit — timestamp + event_id + sign override. */
  emitWithOverrideSign(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    opts?: { timestamp?: string; eventId?: string; sign?: boolean | null },
  ): EmitReceipt {
    return this.rt.emitWithOverrideSign(level, eventType, this._mergeForEmit(fields), opts);
  }

  /**
   * Session-level signing override. `null` resets to the ceremony's
   * yaml `ceremony.sign` default. Mirrors Python `tn.set_signing(...)`.
   *
   * Per-call overrides on `emitOverrideSign` / `emitWithOverrideSign`
   * win over this.
   */
  static setSigning(enabled: boolean | null): void {
    _runtimeSetSigning(enabled);
  }

  // ------------------------------------------------------------------
  // Read verbs
  // ------------------------------------------------------------------

  /**
   * Iterate decoded log entries.
   *
   * Default (no opts) — flat decrypted dict per entry, matching the
   * 2026-04-25 read-ergonomics spec §1.1:
   *
   *     {
   *       timestamp: "...",
   *       event_type: "order.created",
   *       level: "info",
   *       did: "did:key:z…",
   *       sequence: 4827,
   *       event_id: "01HX…",
   *       // decrypted fields, flat from every group the caller can read:
   *       order_id: "...", amount: 4999,
   *       // markers, only present when there's something to report:
   *       _hidden_groups: ["pii"],
   *       _decrypt_errors: ["finance"],
   *     }
   *
   * Crypto plumbing (`prev_hash`, `row_hash`, `signature`, raw ciphertext,
   * `field_hashes`) is excluded — surface those via `{raw: true}`.
   *
   * `{verify: true}` adds a `_valid` block: `{signature, row_hash, chain}`.
   * `{raw: true}` returns today's `{envelope, plaintext, valid}` shape.
   * The two flags compose: `raw: true` overrides `verify: true` (no error;
   * `raw: true` already includes a `valid` block).
   *
   * Field-name collisions across groups: object last-write-wins. Group
   * fields are merged in alphabetical group order so the result is
   * deterministic across runs (per spec §4.1). Callers needing field
   * provenance use `raw: true`.
   *
   * Field naming: snake_case throughout the flat dict (envelope basics
   * AND metadata keys like `_hidden_groups`/`_decrypt_errors`). Matches
   * Python and the on-disk wire format byte-for-byte.
   */
  read(opts?: {
    verify?: boolean;
    raw?: boolean;
    logPath?: string;
    /** When false (default), only entries with `run_id == this client's
     * run_id` (or no `run_id` at all — legacy entries) are yielded. When
     * true, every entry is yielded. (FINDINGS.md #12.) */
    allRuns?: boolean;
    /** Optional predicate. Composes with `allRuns`. */
    where?: (entry: Record<string, unknown>) => boolean;
  }): Iterable<Record<string, unknown> | ReadEntry> {
    const verify = opts?.verify ?? false;
    const raw = opts?.raw ?? false;
    const logPath = opts?.logPath;
    const allRuns = opts?.allRuns ?? false;
    const where = opts?.where;
    const rt = this.rt;
    const runId = this._runId;
    const inCurrentRun = (entry: Record<string, unknown>): boolean => {
      const rid = entry["run_id"];
      // Strict match: an entry without run_id is from a prior writer or
      // pre-run_id era — exclude by default. Use {allRuns: true} to opt
      // in. Matches Python's _entry_in_current_run_flat semantics; closes
      // the TS-only drift flagged in the cash-register audit's parity log.
      return typeof rid === "string" && rid === runId;
    };

    // FINDINGS S6.2 cross-binding port — auto-route foreign logs.
    //
    // When `logPath` points at another publisher's ndjson, the runtime
    // here is bound to OUR ceremony's btn state and the underlying
    // decrypt would fail because every envelope was produced under a
    // different state. Detect the case by peeking at the first
    // envelope's `did` and route through `readAsRecipient` using our
    // own keystore — `client.absorb()` placed the foreign kit there.
    // Mirrors Python's `tn.read()` cross-publisher auto-routing.
    if (logPath !== undefined && _isForeignLog(logPath, this.did)) {
      const keystorePath = this.rt.config.keystorePath;
      // Wrap each ForeignReadEntry into the same shape callers get from
      // the in-runtime path (raw → {envelope, plaintext, valid}; flat →
      // flatten via the existing helper).
      const foreign = readAsRecipient(logPath, keystorePath, {
        group: "default",
        verifySignatures: verify,
      });
      if (raw) {
        return (function* () {
          for (const entry of foreign) {
            const r = entry as unknown as ReadEntry;
            if (where && !where(r as unknown as Record<string, unknown>)) continue;
            yield r;
          }
        })();
      }
      return (function* () {
        for (const entry of foreign) {
          // ForeignReadEntry's `valid` is {signature, chain} (no rowHash);
          // synthesize a rowHash:true so the flat shape's _valid block
          // is present-and-passing for non-row-hash callers. Anything
          // doing strict row-hash audits should use `secureRead`.
          const rEntry = {
            envelope: entry.envelope,
            plaintext: entry.plaintext,
            valid: {
              signature: entry.valid.signature,
              rowHash: true,
              chain: entry.valid.chain,
            },
          } as unknown as ReadEntry;
          const flat = flattenRawEntry(rEntry, { includeValid: verify });
          if (where && !where(flat)) continue;
          yield flat;
        }
      })();
    }

    if (raw) {
      return (function* () {
        for (const r of rt.read(logPath)) {
          if (!allRuns) {
            // run_id lives in the per-group plaintext for the raw shape.
            const pt = (r as { plaintext?: Record<string, Record<string, unknown>> }).plaintext ?? {};
            let matchedRun = false;
            for (const grp of Object.values(pt)) {
              if (grp && typeof grp === "object" && "run_id" in grp) {
                matchedRun = grp["run_id"] === runId;
                break;
              }
            }
            if (!matchedRun) continue;
          }
          if (where && !where(r as unknown as Record<string, unknown>)) continue;
          yield r;
        }
      })();
    }
    return (function* () {
      for (const r of rt.read(logPath)) {
        const flat = flattenRawEntry(r, { includeValid: verify });
        if (!allRuns && !inCurrentRun(flat)) continue;
        if (where && !where(flat)) continue;
        yield flat;
      }
    })();
  }

  /**
   * Audit-grade alias: returns the `{envelope, plaintext, valid}` shape
   * that Python's `read_raw()` produces. Equivalent to `read({raw: true})`.
   */
  *readRaw(logPath?: string): Generator<ReadEntry, void, void> {
    yield* this.rt.read(logPath);
  }

  /**
   * Iterate verified log entries — fail-closed on any (sig, row_hash,
   * chain) failure. Spec §3.
   *
   * Returns flat dicts in the same default shape as `read()`, plus an
   * `instructions` block when the caller holds the `tn.agents` kit and
   * the entry carries a populated `tn.agents` group.
   *
   * `onInvalid` modes:
   *
   * * `"skip"` (default) — silently drop non-verifying entries. A
   *   `tn.read.tampered_row_skipped` event is appended to the local
   *   admin log so monitoring can surface tampering without exposing
   *   the bad row's payload.
   * * `"raise"` — throw `VerificationError` on the first failure.
   * * `"forensic"` — yield the entry with `_valid` and `_invalid_reasons`
   *   keys exposed.
   */
  *secureRead(opts?: SecureReadOptions): Generator<SecureEntry, void, void> {
    const onInvalid = opts?.onInvalid ?? "skip";
    if (onInvalid !== "skip" && onInvalid !== "raise" && onInvalid !== "forensic") {
      throw new Error(
        `secureRead: unknown onInvalid=${JSON.stringify(onInvalid)}; ` +
          `expected 'skip' | 'raise' | 'forensic'`,
      );
    }
    const logPath = opts?.logPath;
    for (const r of this.rt.read(logPath)) {
      const v = r.valid;
      const allValid = Boolean(v.signature) && Boolean(v.rowHash) && Boolean(v.chain);
      if (!allValid) {
        const reasons = invalidReasonsFromValid(v);
        const env = r.envelope;
        if (onInvalid === "raise") {
          throw new VerificationError(env, reasons);
        }
        if (onInvalid === "skip") {
          // Don't loop our own tampered-row event back through secureRead —
          // emitting an event for the very event we're verifying.
          if (String(env["event_type"] ?? "") === "tn.read.tampered_row_skipped") {
            continue;
          }
          try {
            this._emitTamperedRowSkipped(env, reasons);
          } catch {
            // Best-effort.
          }
          continue;
        }
        // forensic — fall through and yield the entry, augmented.
        const flat = flattenRawEntry(r, { includeValid: true }) as SecureEntry;
        flat["_invalid_reasons"] = [...new Set(reasons)].sort();
        attachInstructions(flat, r);
        yield flat;
        continue;
      }

      const flat = flattenRawEntry(r, { includeValid: false }) as SecureEntry;
      attachInstructions(flat, r);
      yield flat;
    }
  }

  // ------------------------------------------------------------------
  // Admin verbs — cipher-agnostic names, btn backend today.
  // ------------------------------------------------------------------

  /**
   * Mint a new reader kit for `group`, write it to `outKitPath`, and return
   * the leaf index. When `recipientDid` is given, a `tn.recipient.added`
   * attested event is emitted so the log is the source of truth for who
   * holds an active kit.
   *
   * Matches Python `tn.admin_add_recipient` and Rust `Runtime::admin_add_recipient`.
   *
   * FINDINGS #5 parity: rejects suffix-mismatched filenames up front. The
   * kit_bundle exporter regex requires `.btn.mykit`; non-matching files
   * are silently skipped and the publisher's own self-kit ships in their
   * place — a critical identity-leak path.
   */
  adminAddRecipient(group: string, outKitPath: string, recipientDid?: string): number {
    const basename = outKitPath.split(/[\\/]/).pop() ?? "";
    if (!basename.endsWith(".btn.mykit") || basename === ".btn.mykit") {
      throw new Error(
        `adminAddRecipient: out_path basename must end with '.btn.mykit' ` +
          `(e.g. ${JSON.stringify(group + ".btn.mykit")}, or ` +
          `${JSON.stringify(group + "_alt.btn.mykit")} for a second kit in ` +
          `the same group), got ${JSON.stringify(basename)}. The kit_bundle ` +
          `exporter regex requires the .btn.mykit suffix; non-matching ` +
          `files get silently skipped and the publisher's own self-kit ships ` +
          `in their place (FINDINGS #5). For ergonomic per-recipient bundling, ` +
          `use bundleForRecipient() — it handles minting + canonical filename ` +
          `+ export in one call.`,
      );
    }
    return this.rt.addRecipient(group, outKitPath, recipientDid);
  }

  /** Revoke a reader and emit `tn.recipient.revoked`. */
  adminRevokeRecipient(group: string, leafIndex: number, recipientDid?: string): void {
    this.rt.revokeRecipient(group, leafIndex, recipientDid);
  }

  /** Number of revoked recipients in `group`. */
  adminRevokedCount(group: string): number {
    return this.rt.revokedCount(group);
  }

  /**
   * Mint a fresh kit for `recipientDid` across one or more groups and bundle
   * them into a single `.tnpkg` at `outPath`. Closes FINDINGS #5 (Python
   * parity): doing this by hand requires the canonical `<group>.btn.mykit`
   * filename and a clean keystore — using anything else silently ships the
   * publisher's own self-kit, which would let the recipient impersonate the
   * publisher. This verb does both internally so the caller can't get either
   * step wrong.
   *
   * `groups` defaults to every NON-internal group declared in the active
   * ceremony (i.e. excludes `tn.agents` — that group is for LLM runtime
   * bundles via `adminAddAgentRuntime`). Pass an explicit list to scope.
   *
   * Returns the absolute path to the written `.tnpkg`.
   */
  bundleForRecipient(
    recipientDid: string,
    outPath: string,
    opts: { groups?: string[] } = {},
  ): string {
    const cfg = this.rt.config;
    let requested: string[];
    if (opts.groups === undefined) {
      requested = [...cfg.groups.keys()].filter((g) => g !== "tn.agents");
    } else {
      // De-dupe while preserving order.
      const seen = new Set<string>();
      requested = [];
      for (const g of opts.groups) {
        if (seen.has(g)) continue;
        seen.add(g);
        requested.push(g);
      }
    }
    if (requested.length === 0) {
      throw new Error(
        "bundleForRecipient: no groups to bundle. The ceremony has only " +
          "the internal tn.agents group; declare a regular group via the " +
          "yaml first, or pass {groups: [...]}.",
      );
    }
    const unknown = requested.filter((g) => !cfg.groups.has(g));
    if (unknown.length > 0) {
      throw new Error(
        `bundleForRecipient: unknown groups ${JSON.stringify(unknown)}; ` +
          `this ceremony declares ${JSON.stringify([...cfg.groups.keys()].sort())}.`,
      );
    }

    // Mint each kit into a tempdir using the canonical filename. The
    // publisher's own keystore is never the export source, which avoids the
    // FINDINGS #5 trap (shipping the publisher's self-kit by accident).
    const td = mkdtempSync(join(tmpdir(), "tn-bundle-"));
    try {
      for (const gname of requested) {
        const kitPath = join(td, `${gname}.btn.mykit`);
        this.rt.addRecipient(gname, kitPath, recipientDid);
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

  /**
   * Mint kits for an LLM-runtime DID across all named groups + `tn.agents`.
   *
   * Per the 2026-04-25 read-ergonomics spec §2.8. Equivalent to:
   *
   *     for (const group of [...groups, "tn.agents"]) {
   *       client.adminAddRecipient(group, kitPath, runtimeDid);
   *     }
   *     client.export({kind: "kit_bundle", ...}, outPath);
   *
   * The `tn.agents` group is always implicitly included (and de-duplicated
   * if the caller passed it). Returns the absolute `.tnpkg` path.
   *
   * The runtime imports the bundle once via `client.absorb()`; from then on
   * every `secureRead()` call surfaces decrypted data + instructions.
   */
  adminAddAgentRuntime(opts: AdminAddAgentRuntimeOptions): string {
    // Dedup: tn.agents is always added; if the caller passes it, don't
    // double-mint (spec §2.8: "always implicit-adds tn.agents").
    const seen = new Set<string>();
    const requested: string[] = [];
    for (const g of opts.groups) {
      if (g === "tn.agents") continue;
      if (seen.has(g)) continue;
      seen.add(g);
      requested.push(g);
    }
    requested.push("tn.agents");

    const cfg = this.rt.config;
    for (const gname of requested) {
      if (!cfg.groups.has(gname)) {
        throw new Error(
          `adminAddAgentRuntime: group ${JSON.stringify(gname)} is not ` +
            `declared in this ceremony's yaml ` +
            `(known: ${JSON.stringify([...cfg.groups.keys()].sort())})`,
        );
      }
    }

    // Mint kits into a private tempdir using the canonical filename so
    // `export(kind="kit_bundle")` picks them up. Then call export pointing
    // at the temp keystore so only our N+1 kits land in the bundle.
    const td = mkdtempSync(join(tmpdir(), "tn-agent-bundle-"));
    try {
      // The kits get minted into the *publisher's* keystore (where
      // BtnPublisher state lives) — that's where addRecipient writes.
      // For the bundle, we need just those kit files in a clean dir,
      // so we copy them after minting. addRecipient writes the kit
      // file at the path we pass in, NOT into the publisher's keystore,
      // so that's the natural drop site.
      for (const gname of requested) {
        const kitPath = join(td, `${gname}.btn.mykit`);
        this.rt.addRecipient(gname, kitPath, opts.runtimeDid);
      }

      const exportArgs: ExportOptions = {
        kind: "kit_bundle",
        groups: requested,
      };
      if (opts.runtimeDid !== undefined) exportArgs.toDid = opts.runtimeDid;

      // export()'s `kit_bundle` builder reads kits from
      // `cfg.keystorePath`, not from our temp dir — but addRecipient
      // already wrote each freshly-minted kit to BOTH the requested
      // outKitPath AND updated the publisher's `<group>.btn.state`.
      // The kit files at the publisher's keystore (e.g.
      // `<keystore>/<group>.btn.mykit`) hold the publisher's self-kit
      // and are not what we want to export — those are the publisher's
      // own reader material. So copy our minted kits into the keystore
      // under unique names? That would clobber the self-kit.
      //
      // Cleaner: copy the temp-dir kits to a clean staging dir and tell
      // export() to read from there. But _buildKitBundleBody hardcodes
      // `cfg.keystorePath`. To stay surgical, write a small custom
      // bundler here using the existing tnpkg primitives.
      const out = this._buildAgentRuntimeBundle(
        opts.outPath,
        td,
        requested,
        opts.runtimeDid,
      );

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
        // Best-effort tempdir cleanup; the OS will reap eventually.
      }
    }
  }

  /** Pack a `.tnpkg` of `kind: kit_bundle` from a directory of `*.btn.mykit`
   * files. Used by `adminAddAgentRuntime` because the canonical export
   * builder reads from the publisher's keystore (where it would pick up
   * the publisher's own self-kit, not the freshly-minted runtime kits). */
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
      throw new Error(`adminAddAgentRuntime: no kits minted for groups ${JSON.stringify(groups)}`);
    }
    const manifest = newManifest({
      kind: "kit_bundle",
      fromDid: this.rt.config.me.did,
      ceremonyId: this.rt.config.ceremonyId,
      scope: "kit_bundle",
      toDid: runtimeDid,
    });
    manifest.state = { kits: kitsMeta, kind: "readers-only" };
    signManifest(manifest, this.rt.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  /** Append a `tn.read.tampered_row_skipped` admin event with public
   * fields only — the bad row's payload is NOT exposed. */
  private _emitTamperedRowSkipped(
    envelope: Record<string, unknown>,
    reasons: string[],
  ): void {
    this.rt.emit("warning", "tn.read.tampered_row_skipped", this._mergeForEmit({
      envelope_event_id: envelope["event_id"] ?? null,
      envelope_did: envelope["did"] ?? null,
      envelope_event_type: envelope["event_type"] ?? null,
      envelope_sequence: envelope["sequence"] ?? null,
      invalid_reasons: [...new Set(reasons)].sort(),
    }));
  }

  /** Look up the most-recent `tn.agents.policy_published` content_hash in
   * the local logs. Walks the main log + the admin log. Returns `null` if
   * no such event exists. */
  private _lastPolicyPublishedHash(): string | null {
    const sources = [this.rt.config.logPath];
    const adminLog = resolveAdminLogPath(this.rt.config);
    if (adminLog !== this.rt.config.logPath) sources.push(adminLog);
    let lastTs = "";
    let lastHash: string | null = null;
    for (const path of sources) {
      if (!existsSync(path)) continue;
      const text = readFileSync(path, "utf8");
      for (const rawLine of text.split(/\r?\n/)) {
        const s = rawLine.trim();
        if (!s) continue;
        let env: Record<string, unknown>;
        try {
          env = JSON.parse(s) as Record<string, unknown>;
        } catch {
          continue;
        }
        if (env["event_type"] !== "tn.agents.policy_published") continue;
        const ts = String(env["timestamp"] ?? "");
        const h = env["content_hash"];
        if (typeof h !== "string") continue;
        if (ts >= lastTs) {
          lastTs = ts;
          lastHash = h;
        }
      }
    }
    return lastHash;
  }

  /** Emit `tn.agents.policy_published` iff the active policy file's
   * content_hash differs from the last published one in the log (or no
   * such event exists). No-op when the file is absent. */
  private _maybeEmitPolicyPublished(): void {
    const doc = this.rt.agentPolicy;
    if (doc === null) return;
    const last = this._lastPolicyPublishedHash();
    if (last === doc.contentHash) return;
    this.rt.emit("info", "tn.agents.policy_published", this._mergeForEmit({
      policy_uri: doc.path,
      version: doc.version,
      content_hash: doc.contentHash,
      event_types_covered: [...doc.templates.keys()].sort(),
      policy_text: doc.body,
    }));
  }

  /** Emit a signed `tn.vault.linked` event. */
  vaultLink(vaultDid: string, projectId: string): EmitReceipt {
    return this.rt.emit("info", "tn.vault.linked", this._mergeForEmit({
      vault_did: vaultDid,
      project_id: projectId,
      linked_at: new Date().toISOString(),
    }));
  }

  /** Emit a signed `tn.vault.unlinked` event. */
  vaultUnlink(vaultDid: string, projectId: string, reason?: string): EmitReceipt {
    const fields: Record<string, unknown> = {
      vault_did: vaultDid,
      project_id: projectId,
      unlinked_at: new Date().toISOString(),
    };
    if (reason !== undefined) fields["reason"] = reason;
    return this.rt.emit("info", "tn.vault.unlinked", this._mergeForEmit(fields));
  }

  /**
   * Return the current recipient roster for `group` by replaying the log.
   *
   * Mirrors Python `tn.recipients(group, include_revoked=...)`. Tampered
   * admin events (failed signature / row_hash / chain) are warned and
   * skipped rather than aborting the whole replay.
   */
  recipients(group: string, opts?: { includeRevoked?: boolean }): RecipientEntry[] {
    const includeRevoked = opts?.includeRevoked ?? false;

    const active = new Map<number, RecipientEntry>();
    const revokedMap = new Map<number, RecipientEntry>();

    for (const entry of this.rt.read()) {
      const eventType = (entry.envelope["event_type"] as string) ?? "";
      if (!eventType.startsWith("tn.recipient.")) continue;

      const v = entry.valid;
      if (!(v.signature && v.rowHash && v.chain)) {
        console.warn(
          `tn.recipients: skipping tampered admin event event=${JSON.stringify(eventType)}`,
        );
        continue;
      }

      const merged = _mergeEnvelope(entry);
      _applySchemaDefaults(eventType, merged);
      const ts = (entry.envelope["timestamp"] as string | undefined) ?? null;

      let delta: admin.StateDelta;
      try {
        delta = admin.reduce(merged);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(
          `tn.recipients: admin event failed reduce: ${JSON.stringify(eventType)}: ${msg}`,
        );
        continue;
      }

      if (delta.kind === "recipient_added" && delta["group"] === group) {
        const leaf = delta["leaf_index"];
        if (typeof leaf !== "number") continue;
        active.set(leaf, {
          leafIndex: leaf,
          recipientDid: (delta["recipient_did"] as string | null) ?? null,
          mintedAt: ts,
          kitSha256: (delta["kit_sha256"] as string | null) ?? null,
          revoked: false,
          revokedAt: null,
        });
      } else if (delta.kind === "recipient_revoked" && delta["group"] === group) {
        const leaf = delta["leaf_index"];
        if (typeof leaf !== "number") continue;
        const existing = active.get(leaf);
        active.delete(leaf);
        const rec: RecipientEntry = existing ?? {
          leafIndex: leaf,
          recipientDid: null,
          mintedAt: null,
          kitSha256: null,
          revoked: false,
          revokedAt: null,
        };
        rec.revoked = true;
        rec.revokedAt = ts;
        revokedMap.set(leaf, rec);
      }
    }

    const out = [...active.values()].sort((a, b) => a.leafIndex - b.leafIndex);
    if (includeRevoked) {
      out.push(...[...revokedMap.values()].sort((a, b) => a.leafIndex - b.leafIndex));
    }
    return out;
  }

  /**
   * Return the full local admin state, derived by replaying the log
   * through the Rust reducer. Shape mirrors Python `tn.admin_state` and
   * the vault `GET /api/v1/projects/{id}/state` endpoint, but with
   * camelCased field names (TypeScript convention).
   *
   * If `group` is given, lists are filtered to that group. The ceremony
   * record is not filtered.
   */
  adminState(group?: string): AdminState {
    const state: AdminState = {
      ceremony: null,
      groups: [],
      recipients: [],
      rotations: [],
      coupons: [],
      enrolments: [],
      vaultLinks: [],
    };

    const byLeaf = new Map<string, AdminRecipientState>();
    const enrolmentsByPeer = new Map<string, AdminEnrolmentState>();
    const vaultLinksByDid = new Map<string, AdminVaultLinkState>();

    for (const entry of this.rt.read()) {
      const eventType = (entry.envelope["event_type"] as string) ?? "";
      if (
        !(
          eventType.startsWith("tn.ceremony.") ||
          eventType.startsWith("tn.group.") ||
          eventType.startsWith("tn.recipient.") ||
          eventType.startsWith("tn.rotation.") ||
          eventType.startsWith("tn.coupon.") ||
          eventType.startsWith("tn.enrolment.") ||
          eventType.startsWith("tn.vault.")
        )
      ) {
        continue;
      }

      const merged = _mergeEnvelope(entry);
      _applySchemaDefaults(eventType, merged);
      const ts = (merged["timestamp"] as string | undefined) ?? null;

      let d: admin.StateDelta;
      try {
        d = admin.reduce(merged);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(
          `tn.adminState: admin event failed reduce: ${JSON.stringify(eventType)}: ${msg}`,
        );
        continue;
      }

      switch (d.kind) {
        case "ceremony_init":
          state.ceremony = {
            ceremonyId: d["ceremony_id"] as string,
            cipher: d["cipher"] as string,
            deviceDid: d["device_did"] as string,
            createdAt: (d["created_at"] as string | null) ?? null,
          };
          break;
        case "group_added":
          state.groups.push({
            group: d["group"] as string,
            cipher: d["cipher"] as string,
            publisherDid: d["publisher_did"] as string,
            addedAt: d["added_at"] as string,
          });
          break;
        case "recipient_added": {
          const leaf = d["leaf_index"];
          if (typeof leaf !== "number") break;
          const key = `${d["group"] as string}\u0000${leaf}`;
          byLeaf.set(key, {
            group: d["group"] as string,
            leafIndex: leaf,
            recipientDid: (d["recipient_did"] as string | null) ?? null,
            kitSha256: d["kit_sha256"] as string,
            mintedAt: ts,
            activeStatus: "active",
            revokedAt: null,
            retiredAt: null,
          });
          break;
        }
        case "recipient_revoked": {
          const leaf = d["leaf_index"];
          if (typeof leaf !== "number") break;
          const key = `${d["group"] as string}\u0000${leaf}`;
          const rec = byLeaf.get(key);
          if (rec) {
            rec.activeStatus = "revoked";
            rec.revokedAt = ts;
          }
          break;
        }
        case "rotation_completed": {
          state.rotations.push({
            group: d["group"] as string,
            cipher: d["cipher"] as string,
            generation: d["generation"] as number,
            previousKitSha256: d["previous_kit_sha256"] as string,
            rotatedAt: d["rotated_at"] as string,
          });
          // Retire any currently-active recipients in this group.
          for (const rec of byLeaf.values()) {
            if (rec.group === d["group"] && rec.activeStatus === "active") {
              rec.activeStatus = "retired";
              rec.retiredAt = ts;
            }
          }
          break;
        }
        case "coupon_issued":
          state.coupons.push({
            group: d["group"] as string,
            slot: d["slot"] as number,
            toDid: d["to_did"] as string,
            issuedTo: d["issued_to"] as string,
            issuedAt: ts,
          });
          break;
        case "enrolment_compiled": {
          const peerKey = `${d["group"] as string}\u0000${d["peer_did"] as string}`;
          enrolmentsByPeer.set(peerKey, {
            group: d["group"] as string,
            peerDid: d["peer_did"] as string,
            packageSha256: d["package_sha256"] as string,
            status: "offered",
            compiledAt: d["compiled_at"] as string,
            absorbedAt: null,
          });
          break;
        }
        case "enrolment_absorbed": {
          const peerKey = `${d["group"] as string}\u0000${d["from_did"] as string}`;
          const existing = enrolmentsByPeer.get(peerKey);
          if (existing) {
            existing.status = "absorbed";
            existing.absorbedAt = d["absorbed_at"] as string;
          } else {
            enrolmentsByPeer.set(peerKey, {
              group: d["group"] as string,
              peerDid: d["from_did"] as string,
              packageSha256: d["package_sha256"] as string,
              status: "absorbed",
              compiledAt: null,
              absorbedAt: d["absorbed_at"] as string,
            });
          }
          break;
        }
        case "vault_linked":
          vaultLinksByDid.set(d["vault_did"] as string, {
            vaultDid: d["vault_did"] as string,
            projectId: d["project_id"] as string,
            linkedAt: d["linked_at"] as string,
            unlinkedAt: null,
          });
          break;
        case "vault_unlinked": {
          const link = vaultLinksByDid.get(d["vault_did"] as string);
          if (link) link.unlinkedAt = d["unlinked_at"] as string;
          break;
        }
        default:
          break;
      }
    }

    state.recipients = [...byLeaf.values()];
    state.enrolments = [...enrolmentsByPeer.values()];
    state.vaultLinks = [...vaultLinksByDid.values()];

    // Fallback: if no ceremony_init landed in the log (common for btn
    // ceremonies, where the Rust runtime writes ceremony info to the yaml
    // rather than the log), derive the ceremony record from current config.
    if (state.ceremony === null) {
      const cfg = this.rt.config;
      state.ceremony = {
        ceremonyId: cfg.ceremonyId,
        cipher: cfg.cipher,
        deviceDid: cfg.me.did,
        createdAt: null,
      };
    }

    if (group !== undefined) {
      state.groups = state.groups.filter((x) => x.group === group);
      state.recipients = state.recipients.filter((x) => x.group === group);
      state.rotations = state.rotations.filter((x) => x.group === group);
      state.coupons = state.coupons.filter((x) => x.group === group);
      state.enrolments = state.enrolments.filter((x) => x.group === group);
    }

    return state;
  }

  // ------------------------------------------------------------------
  // .tnpkg export / absorb (Section 2-3 of the 2026-04-24 admin log
  // architecture plan).
  // ------------------------------------------------------------------

  private _adminCache: AdminStateCache | null = null;

  /** Lazy-initialized AdminState cache. One per TNClient instance. */
  adminCache(): AdminStateCache {
    if (this._adminCache === null) this._adminCache = new AdminStateCache(this);
    return this._adminCache;
  }

  /** Pack a `.tnpkg` from local ceremony state. Mirrors Python `tn.export`. */
  export(opts: ExportOptions, outPath: string): string {
    const { kind } = opts;
    if (!KNOWN_KINDS.has(kind as ManifestKind)) {
      throw new Error(
        `export: unknown kind ${JSON.stringify(kind)}; expected one of ` +
          JSON.stringify([...KNOWN_KINDS].sort()),
      );
    }
    if (kind === "full_keystore" && !opts.confirmIncludesSecrets) {
      throw new Error(
        "export(kind='full_keystore') writes the publisher's raw private keys " +
          "(local.private + index_master.key) into the zip. Pass " +
          "confirmIncludesSecrets=true to acknowledge.",
      );
    }
    if (kind === "recipient_invite") {
      throw new Error(
        `export(kind=${JSON.stringify(kind)}) is reserved in the manifest schema ` +
          "but not implemented in the TS SDK yet. Track parity in docs/sdk-parity.md.",
      );
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
      extras.state = adminStateToWire(this.adminCache().state());
    } else if (kind === "offer" || kind === "enrolment") {
      if (!opts.packageBody) {
        throw new Error(
          `export(kind=${JSON.stringify(kind)}) requires packageBody=<bytes> ` +
            "(serialized Package JSON, matching the Python `Package` dataclass shape).",
        );
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
    }

    const manifestArgs: {
      kind: ManifestKind | string;
      fromDid: string;
      ceremonyId: string;
      scope: string;
      toDid?: string;
    } = {
      kind,
      fromDid: this.rt.config.me.did,
      ceremonyId: this.rt.config.ceremonyId,
      scope: opts.scope ?? extras.scope ?? defaultScope(kind),
    };
    if (opts.toDid !== undefined) manifestArgs.toDid = opts.toDid;
    const manifest = newManifest(manifestArgs);
    if (extras.clock) manifest.clock = extras.clock;
    if (extras.eventCount !== undefined) manifest.eventCount = extras.eventCount;
    if (extras.headRowHash !== undefined) manifest.headRowHash = extras.headRowHash;
    if (extras.state !== undefined) manifest.state = extras.state;

    signManifest(manifest, this.rt.keystore.device);
    return writeTnpkg(outPath, manifest, body);
  }

  /** Apply a `.tnpkg` to local state. Idempotent. Mirrors Python `tn.absorb`. */
  absorb(source: string | Uint8Array): AbsorbReceipt {
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
          `${JSON.stringify(manifest.fromDid)}. The package is corrupt, truncated, ` +
          `or tampered with.`,
      };
    }

    const kind = manifest.kind;
    let receipt: AbsorbReceipt;
    if (kind === "admin_log_snapshot") {
      receipt = this._absorbAdminLogSnapshot(manifest, body);
    } else if (kind === "kit_bundle" || kind === "full_keystore") {
      receipt = this._absorbKitBundle(manifest, body);
    } else if (kind === "offer" || kind === "enrolment") {
      // Body bytes carried through to the caller; the TS SDK doesn't
      // ship offer/enrolment producer state-merging logic yet (it's a
      // Python-side legacy path). Surface as accepted=1 with no state.
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

  // ---- Internal: body builders ------------------------------------

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
    const main = this.rt.config.logPath;
    const adminLog = resolveAdminLogPath(this.rt.config);
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
        const did = env["did"];
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

  private _buildKitBundleBody(opts: {
    full: boolean;
    groups: string[] | undefined;
  }): { body: Record<string, Uint8Array>; state: Record<string, unknown> } {
    const keystore = this.rt.config.keystorePath;
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
        if (
          entry === "local.private" ||
          entry === "local.public" ||
          entry === "index_master.key"
        ) {
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
      const suffix = groupFilter
        ? ` matching groups [${[...groupFilter].sort().join(", ")}]`
        : "";
      throw new Error(`kit_bundle: no *.btn.mykit files in ${keystore}${suffix}`);
    }

    if (opts.full) {
      const yamlPath = this.rt.config.yamlPath;
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

  // ---- Internal: absorb handlers ----------------------------------

  private _absorbAdminLogSnapshot(
    manifest: Manifest,
    body: Map<string, Uint8Array>,
  ): AbsorbReceipt {
    const adminLog = resolveAdminLogPath(this.rt.config);
    // Build local clock from the admin log.
    const localClock: VectorClock = {};
    const seenRowHashes = existingRowHashes(adminLog);
    if (existsSync(adminLog)) {
      for (const rawLine of readFileSync(adminLog, "utf8").split(/\r?\n/)) {
        const s = rawLine.trim();
        if (!s) continue;
        try {
          const env = JSON.parse(s) as Record<string, unknown>;
          const did = env["did"];
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
        derivedState: adminStateFromWire(manifest.state),
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

    // Build local revoked-leaf set.
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
              revokedLeaves.set(`${g}\u0000${li}`, typeof rh === "string" ? rh : null);
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
      if (!envelopeWellFormed(env)) continue;
      if (!verifyEnvelopeSignature(env)) continue;

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
          const k = `${g}\u0000${li}`;
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
          revokedLeaves.set(`${g}\u0000${li}`, rh);
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

  private _absorbKitBundle(
    manifest: Manifest,
    body: Map<string, Uint8Array>,
  ): AbsorbReceipt {
    const keystore = this.rt.config.keystorePath;
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
        // Surface the swap on the receipt (FINDINGS #6 cross-binding
        // parity). Original bytes are preserved at `backup`; record
        // the destination path so callers can map to the .previous
        // sidecar by appending the same UTC timestamp suffix.
        replaced.push(dest);
      }
      writeFileSync(dest, Buffer.from(data));
      accepted += 1;
    }
    void copyFileSync; // referenced for future reorg; keep import alive
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
}

// ---------------------------------------------------------------------
// Export / absorb public types
// ---------------------------------------------------------------------

export interface AdminAddAgentRuntimeOptions {
  runtimeDid: string;
  groups: string[];
  outPath: string;
  label?: string;
}

export interface ExportOptions {
  kind: ManifestKind;
  toDid?: string;
  scope?: string;
  confirmIncludesSecrets?: boolean;
  /** For `kind="kit_bundle"` / `"full_keystore"`: filter to these groups only. */
  groups?: string[];
  /** For `kind="offer"` / `"enrolment"`: pre-built body bytes (the
   * serialized Python `Package` dataclass JSON). The TS SDK does not
   * yet ship a producer for offer/enrolment packages — these bytes are
   * carried verbatim through the wrapper. */
  packageBody?: Uint8Array;
}

export interface AbsorbReceipt {
  kind: string;
  acceptedCount: number;
  dedupedCount: number;
  noop: boolean;
  derivedState: AdminState | null;
  conflicts: ChainConflict[];
  /**
   * Paths in the local keystore whose existing contents were renamed
   * to a `.previous.<UTC_TS>` sidecar to make room for kits from the
   * absorbed package. Empty when nothing was overwritten.
   *
   * Mirrors Python `AbsorbReceipt.replaced_kit_paths` (FINDINGS #6
   * cross-binding parity). Iterate this field after absorb to decide
   * whether to alert / restore / accept the swap rather than relying
   * on a printed warning. Optional: omitted (or empty) when nothing
   * was overwritten.
   */
  replacedKitPaths?: string[];
  /** Set when the package was rejected (signature failure, missing body,
   * unsupported kind). Otherwise undefined. */
  rejectedReason?: string;
}

export type { ChainConflict, LeafReuseAttempt } from "./admin_cache.js";

// ---------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------

function defaultScope(kind: ManifestKind | string): string {
  switch (kind) {
    case "admin_log_snapshot":
      return "admin";
    case "kit_bundle":
      return "kit_bundle";
    case "full_keystore":
      return "full";
    default:
      return "admin";
  }
}

function envelopeWellFormed(env: Record<string, unknown>): boolean {
  for (const k of ["did", "timestamp", "event_id", "event_type", "row_hash", "signature"]) {
    if (typeof env[k] !== "string") return false;
  }
  return true;
}

function verifyEnvelopeSignature(env: Record<string, unknown>): boolean {
  try {
    const did = String(env["did"]);
    const rh = String(env["row_hash"]);
    const sigB64 = String(env["signature"]);
    const sig = signatureFromB64(asSignatureB64(sigB64));
    return verifySig(asDid(did), new Uint8Array(Buffer.from(rh, "utf8")), sig);
  } catch {
    return false;
  }
}

// `verifyManifest` re-exported through tnpkg for callers who need the
// strict-throws variant.
void verifyManifest;
