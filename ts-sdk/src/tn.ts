// @tnproto/sdk — main Layer 2 class, the 0.3.0 replacement for TNClient.
//
// Splits into namespaced sub-objects (tn.admin, tn.pkg, tn.vault,
// tn.agents, tn.handlers). I/O verbs are async; emit/read stay sync.
// See docs/superpowers/specs/2026-05-01-ts-sdk-refresh-design.md.
//
// Method bodies populated in Task 2.4 (statics, log/read/context),
// Task 2.6–2.10 (namespaces), Phase 3 Task 3.2 (watch).

import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve, isAbsolute as pathIsAbsolute } from "node:path";
import { randomUUID } from "node:crypto";

import {
  NodeRuntime,
  setSigning as _runtimeSetSigning,
} from "./runtime/node_runtime.js";
import type { EmitReceipt } from "./core/results.js";
import { watch, type WatchOptions } from "./watch.js";
import { asRowHash, type Entry, type LogLevel } from "./core/types.js";
import type { ReadEntry } from "./core/read_shape.js";
import {
  flattenRawEntry,
  invalidReasonsFromValid,
  attachInstructions,
} from "./core/read_shape.js";
import type { SecureEntry } from "./core/read_shape.js";
import { VerificationError } from "./core/errors.js";
import { AdminNamespace } from "./admin/index.js";
import { PkgNamespace } from "./pkg/index.js";
import { VaultNamespace } from "./vault/index.js";
import { AgentsNamespace } from "./agents/index.js";
import { HandlersNamespace } from "./handlers/namespace.js";
import { normalizeLogFields } from "./_log_fields.js";
import { StdoutHandler } from "./handlers/stdout.js";
import { buildHandlers } from "./handlers/registry.js";
import { readAsRecipient } from "./read_as_recipient.js";

// ---------------------------------------------------------------------------
// Re-export types for callers that import from tn.ts directly.
// ---------------------------------------------------------------------------
export type { LogLevel } from "./core/types.js";
export type { EmitReceipt } from "./core/results.js";
export type { SecureEntry } from "./core/read_shape.js";
export type { WatchOptions, WatchSince } from "./watch.js";

// ---------------------------------------------------------------------------
// Module-level log-level state — own copy for Tn (does not share with
// TNClient._logLevelThreshold; both classes share the same numeric values).
// ---------------------------------------------------------------------------

const _LOG_LEVELS = {
  debug: 10,
  info: 20,
  warning: 30,
  error: 40,
} as const;

/**
 * Standard log-level numeric values. Mirror stdlib Python `logging`.
 * Public so external callers can pass either `"info"` strings or the int
 * directly through `setLevel`. Matches the values that were on TNClient.
 */
export const LOG_LEVELS: typeof _LOG_LEVELS = _LOG_LEVELS;

/** Process-wide level threshold for the Tn class. Default: debug (10). */
let _tnLogLevelThreshold: number = _LOG_LEVELS.debug;

function _levelValue(level: LogLevel): number {
  return _LOG_LEVELS[level];
}

// ---------------------------------------------------------------------------
// Module-level strict mode. When true, Tn.init() with no yaml path throws
// rather than silently minting a fresh ceremony.
// ---------------------------------------------------------------------------
let _strictMode = false;

// ---------------------------------------------------------------------------
// _shouldEnableStdout — same logic as TNClient's internal helper.
// ---------------------------------------------------------------------------
function _shouldEnableStdoutFor(
  cfg: { handlers?: Array<Record<string, unknown>> } | undefined,
  kwarg: boolean | undefined,
): boolean {
  if (kwarg !== undefined) return kwarg;
  if (process.env["TN_NO_STDOUT"] === "1") return false;
  const list = cfg?.handlers ?? [];
  if (list.length > 0) {
    return list.some(
      (h) =>
        h != null && typeof h === "object" && (h as Record<string, unknown>).kind === "stdout",
    );
  }
  return true;
}

// ---------------------------------------------------------------------------
// _isForeignLog — peek at first envelope line to detect cross-publisher log.
// Duplicated from client.ts (not exported there) to keep client.ts surgical.
// ---------------------------------------------------------------------------
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
      return false;
    }
  } catch {
    return false;
  }
  return false;
}

// Multi-ceremony name validation: ascii alphanumeric + underscore + dash,
// must not start with a dash, must not be the reserved legacy directory
// name "tn". Mirrors the Python ``tn._layout.is_valid_ceremony_name``.
const _CEREMONY_NAME_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_\-]*$/;
function _isValidCeremonyName(name: string): boolean {
  if (!name) return false;
  if (name === "tn") return false;
  return _CEREMONY_NAME_RE.test(name);
}

// Process-local handle registry — Bug 8 fix. Keyed by
// (resolved projectDir + "::" + name). Mirrors Python's tn._registry
// so two ``Tn.use("payments")`` calls return the same instance.
// Closed instances evict themselves on close() so the next ``use``
// call mints a fresh one.
const _registry: Map<string, Tn> = new Map();

// Emit a one-time loud notice when ``Tn.use(name)`` auto-mints a
// fresh default ceremony as a side effect of opening a stream. Bug 2
// fix: silently creating a new device DID is the wrong default;
// surfacing it gives the operator a chance to recover before they
// emit anything.
let _autoMintNoticePrinted = false;
function _emitAutoMintNotice(defaultYaml: string, projectDir: string): void {
  if (_autoMintNoticePrinted) return;
  if (process.env["TN_AUTOINIT_QUIET"] === "1") {
    _autoMintNoticePrinted = true;
    return;
  }
  const banner =
    "\n" +
    "================================================================\n" +
    "  TN: A NEW DEFAULT CEREMONY HAS BEEN CREATED\n" +
    "================================================================\n" +
    `  Location:  ${defaultYaml}\n` +
    `  Project:   ${projectDir}\n` +
    "  This was auto-created as a side effect of opening a stream\n" +
    "  in a project that had no existing default ceremony. The\n" +
    "  device DID is fresh and unique to this project directory.\n" +
    "\n" +
    "  If you intended to attach to an EXISTING ceremony, stop now\n" +
    "  and either restore the prior ceremony to .tn/default/ or\n" +
    "  point your project elsewhere.\n" +
    "\n" +
    "  Silence this notice with TN_AUTOINIT_QUIET=1.\n" +
    "================================================================\n";
  try {
    process.stderr.write(banner);
  } catch {
    /* ignore broken stderr */
  }
  _autoMintNoticePrinted = true;
}

/** Sentinel receipt returned when a level-filtered emit short-circuits. */
function _nullReceipt(): EmitReceipt {
  return {
    eventId: "",
    rowHash: asRowHash("sha256:" + "0".repeat(64)),
    sequence: 0,
  };
}

// ---------------------------------------------------------------------------
// Public interface types
// ---------------------------------------------------------------------------

export interface TnInitOptions {
  stdout?: boolean;
}

export interface ReadOptions {
  verify?: boolean;
  raw?: boolean;
  logPath?: string;
  allRuns?: boolean;
  where?: (entry: Record<string, unknown>) => boolean;
}

export interface ReadAsRecipientOptions {
  logPath: string;
  group?: string;
  verifySignatures?: boolean;
}

export interface SecureReadOptions {
  onInvalid?: "skip" | "raise" | "forensic";
  logPath?: string;
}

// ---------------------------------------------------------------------------
// Tn — main public class
// ---------------------------------------------------------------------------

export class Tn {
  readonly admin: AdminNamespace;
  readonly pkg: PkgNamespace;
  readonly vault: VaultNamespace;
  readonly agents: AgentsNamespace;
  readonly handlers: HandlersNamespace;

  /** Per-instance run ID; auto-injected into every emit as `run_id`. */
  private readonly _runId: string;

  /**
   * Stack of per-scope context overlays pushed by `tn.scope()`.
   * Bottom of the stack is the long-lived context; each `scope()` push
   * layers fresh fields and pops on disposal.
   */
  private _contextStack: Record<string, unknown>[] = [{}];

  /** For ephemeral instances: the tempdir to remove on close(). */
  private _ownedTempdir: string | undefined;

  private constructor(rt: NodeRuntime, ownedTempdir?: string) {
    this._rt = rt;
    this._ownedTempdir = ownedTempdir;
    this._runId = randomUUID().replace(/-/g, "");
    this.admin = new AdminNamespace(rt);
    this.pkg = new PkgNamespace(rt);
    this.vault = new VaultNamespace(rt, (f) => this._mergeForEmit(f));
    this.agents = new AgentsNamespace(rt);
    this.handlers = new HandlersNamespace(rt);
    // Best-effort policy bookkeeping — mirrors TNClient constructor.
    try {
      this._maybeEmitPolicyPublished();
    } catch {
      // Init must not block on best-effort policy bookkeeping.
    }
  }

  /** The underlying NodeRuntime (kept private; use the verb methods). */
  private readonly _rt: NodeRuntime;

  // -------------------------------------------------------------------------
  // Static factory methods
  // -------------------------------------------------------------------------

  /**
   * Load or create a ceremony from a yaml manifest and return a client
   * bound to it. Mirrors Python `tn.init` and `TNClient.init`.
   *
   * When `yamlPath` is omitted the discovery chain is consulted:
   *   1. `TN_YAML` env var
   *   2. `./tn.yaml`
   *   3. `./.tn/default/tn.yaml`  (multi-ceremony layout, see
   *      docs/directory-layout.md)
   *   4. `$TN_HOME/tn.yaml`
   * If strict mode is active (`Tn.setStrict(true)`) and no file is found,
   * an error is thrown. Otherwise a fresh ephemeral ceremony is minted.
   *
   * For named multi-ceremony projects, prefer `Tn.openCeremony(name)`
   * which resolves directly against `.tn/<name>/tn.yaml`.
   */
  static async init(yamlPath?: string, opts?: TnInitOptions): Promise<Tn> {
    let resolvedPath = yamlPath;

    if (resolvedPath === undefined) {
      // 1. TN_YAML env var.
      const fromEnv = process.env["TN_YAML"];
      if (fromEnv) {
        resolvedPath = fromEnv;
      }

      // 2. ./tn.yaml
      if (resolvedPath === undefined) {
        const candidate = join(process.cwd(), "tn.yaml");
        if (existsSync(candidate)) resolvedPath = candidate;
      }

      // 3. ./.tn/default/tn.yaml — the multi-ceremony default.
      // Picked up automatically for projects that have migrated off
      // the legacy single-ceremony layout. See docs/directory-layout.md.
      if (resolvedPath === undefined) {
        const candidate = join(process.cwd(), ".tn", "default", "tn.yaml");
        if (existsSync(candidate)) resolvedPath = candidate;
      }

      // 4. $TN_HOME/tn.yaml
      if (resolvedPath === undefined && process.env["TN_HOME"]) {
        const candidate = join(process.env["TN_HOME"], "tn.yaml");
        if (existsSync(candidate)) resolvedPath = candidate;
      }

      if (resolvedPath === undefined) {
        if (_strictMode) {
          throw new Error(
            "Tn.init: no yaml path provided and strict mode is on. " +
              "Set TN_YAML env var, create ./tn.yaml, set TN_HOME, " +
              "or pass a path explicitly to Tn.init().",
          );
        }
        // Fall back to ephemeral.
        return Tn.ephemeral(opts);
      }
    }

    const rt = NodeRuntime.init(resolvedPath);
    // Wire yaml-declared handlers (e.g. file.rotating, otel) into the
    // runtime. Two kinds are excluded from buildHandlers here because the
    // runtime handles them separately:
    //   - stdout  → managed by _shouldEnableStdoutFor below (avoids dup)
    //   - file.rotating pointing at config.logPath → the runtime already
    //     appends every event to the main log via appendFileSync; a
    //     FileHandler for the same path would double-write every line.
    // Kinds that need host-injected adapters (vault.push/pull, fs.drop/scan)
    // will throw at buildHandlers time if the adapter is absent — callers
    // that need those must use rt.addHandler() directly.
    if (rt.config.handlers.length > 0) {
      const mainLog = rt.config.logPath;
      const filteredSpecs = rt.config.handlers.filter((h) => {
        const kind = String(h["kind"] ?? "").toLowerCase();
        if (kind === "stdout") return false;
        if (kind === "file.rotating" || kind === "file") {
          const rawPath = String(h["path"] ?? "");
          if (rawPath) {
            const resolved = pathIsAbsolute(rawPath)
              ? rawPath
              : pathResolve(rt.config.yamlDir, rawPath);
            if (resolved === mainLog) return false;
          }
        }
        return true;
      });
      if (filteredSpecs.length > 0) {
        const yamlHandlers = buildHandlers(filteredSpecs, {}, rt.config.yamlDir);
        for (const h of yamlHandlers) {
          rt.addHandler(h);
        }
      }
    }
    if (_shouldEnableStdoutFor(rt.config, opts?.stdout)) {
      rt.addHandler(new StdoutHandler());
    }
    // Honor yaml ceremony.log_level when no programmatic setLevel has moved
    // the threshold above the default (mirrors TNClient.init logic).
    if (rt.config.logLevel && _tnLogLevelThreshold === _LOG_LEVELS.debug) {
      const lvl = rt.config.logLevel as string;
      if (lvl in _LOG_LEVELS) {
        _tnLogLevelThreshold = _LOG_LEVELS[lvl as LogLevel];
      }
    }
    return new Tn(rt);
  }

  /**
   * Build a client backed by a fresh ceremony in a private tempdir.
   * The tempdir is removed on `close()`.
   *
   * Mirrors `TNClient.ephemeral()` and Python's `tn.session()`.
   */
  static async ephemeral(opts?: TnInitOptions): Promise<Tn> {
    const td = mkdtempSync(join(tmpdir(), "tn-ephemeral-"));
    const yamlPath = join(td, "tn.yaml");
    const rt = NodeRuntime.init(yamlPath);
    if (_shouldEnableStdoutFor(rt.config, opts?.stdout)) {
      rt.addHandler(new StdoutHandler());
    }
    return new Tn(rt, td);
  }

  /**
   * Get-or-create a named TN ceremony at ``.tn/<name>/tn.yaml``.
   *
   * Mirrors Python's ``tn.use(name)``. Same semantics, same
   * verb. ``Tn.openCeremony`` is kept as a deprecated alias.
   *
   * The reserved name ``"default"`` resolves the default ceremony.
   * Any other valid name resolves under ``.tn/<name>/``. If the
   * directory does not exist on disk, it is auto-created — for the
   * default ceremony, a fresh identity + keystore + full yaml are
   * minted; for named streams, a lightweight extends-based yaml is
   * written and identity is inherited from default (which is created
   * first if absent).
   *
   * **Handle interning.** Per-(projectDir, name), this call returns
   * the same ``Tn`` instance across repeated invocations within the
   * same process. Two calls with the same arguments give you the
   * same handle — matching Python's ``tn.use`` registry contract.
   * Calling ``close()`` on the cached instance evicts it; subsequent
   * calls mint a fresh one.
   */
  static async use(
    name: string,
    opts?: TnInitOptions & { projectDir?: string; profile?: string },
  ): Promise<Tn> {
    const { ensureCeremonyOnDisk, ceremonyYamlPath, checkProfileConflict, migrateLegacyLayout } =
      await import("./multi.js");
    if (!_isValidCeremonyName(name)) {
      throw new Error(
        `Tn.use: invalid ceremony name ${JSON.stringify(name)}; ` +
          "must match [a-zA-Z0-9_][a-zA-Z0-9_-]* and not be 'tn' (reserved).",
      );
    }
    const projectDir = opts?.projectDir ?? process.cwd();

    // Handle interning — Bug 8 fix. Cache by (resolved projectDir,
    // name). If we've already minted a Tn for this pair in this
    // process, return it. Matches Python's ``tn.use`` interning.
    const { resolve: pathResolve } = await import("node:path");
    const cacheKey = `${pathResolve(projectDir)}::${name}`;
    const cached = _registry.get(cacheKey);
    if (cached !== undefined) return cached;

    // Opportunistic legacy migration of ``.tn/tn/`` -> ``.tn/default/``.
    try {
      migrateLegacyLayout(projectDir);
    } catch (e) {
      throw new Error(
        `Tn.use: legacy layout migration failed: ${(e as Error).message}`,
      );
    }

    const yamlPath = ceremonyYamlPath(name, projectDir);
    checkProfileConflict(yamlPath, opts?.profile);
    const ensureOpts: { projectDir?: string; profile?: string } = { projectDir };
    if (opts?.profile !== undefined) ensureOpts.profile = opts.profile;

    // Will the default ceremony get auto-minted as a side effect?
    // Bug 2 fix: surface a loud, one-time notice so the operator
    // sees that a fresh project DID was just created.
    const defaultYamlBefore = ceremonyYamlPath("default", projectDir);
    const willMintDefault = !existsSync(defaultYamlBefore);

    ensureCeremonyOnDisk(name, ensureOpts);

    if (willMintDefault) {
      _emitAutoMintNotice(ceremonyYamlPath("default", projectDir), projectDir);
    }

    const tn = await Tn.init(yamlPath, opts);
    _registry.set(cacheKey, tn);
    return tn;
  }

  /**
   * @deprecated Use ``Tn.use(name, opts)`` instead. Same semantics,
   * matches Python's ``tn.use`` verb. This alias will be removed in
   * a future release.
   */
  static async openCeremony(
    name: string,
    opts?: TnInitOptions & { projectDir?: string; profile?: string },
  ): Promise<Tn> {
    return Tn.use(name, opts);
  }

  /**
   * List ceremony names found on disk under `.tn/` for `projectDir`
   * (default: cwd). Returns the immediate subdirectories of `.tn/`
   * that contain a `tn.yaml`. Sorted for deterministic output.
   */
  static listCeremonies(projectDir?: string): string[] {
    const root = join(projectDir ?? process.cwd(), ".tn");
    if (!existsSync(root)) return [];
    const out: string[] = [];
    for (const child of readdirSync(root)) {
      if (!_isValidCeremonyName(child) && child !== "tn") continue;
      const yp = join(root, child, "tn.yaml");
      if (existsSync(yp)) out.push(child);
    }
    out.sort();
    return out;
  }

  // -------------------------------------------------------------------------
  // Static configuration methods
  // -------------------------------------------------------------------------

  /**
   * Set the process-wide log-level threshold for Tn. Verbs at a lower level
   * short-circuit before any work happens. Mirrors Python `tn.set_level()`.
   *
   * Uses the simple 4-value union from `core/types.ts`. Numbers as level
   * values are an internal-runtime concern, not the public Tn API surface.
   */
  static setLevel(level: LogLevel): void {
    _tnLogLevelThreshold = _levelValue(level);
  }

  /** Return the current threshold as a level name or numeric string. */
  static getLevel(): string {
    const t = _tnLogLevelThreshold;
    for (const [name, value] of Object.entries(_LOG_LEVELS)) {
      if (value === t) return name;
    }
    return String(t);
  }

  /** True iff `level` would currently emit. Mirrors `logging.Logger.isEnabledFor`. */
  static isEnabledFor(level: LogLevel): boolean {
    return _levelValue(level) >= _tnLogLevelThreshold;
  }

  /**
   * Session-level signing override. `null` resets to the ceremony's yaml
   * `ceremony.sign` default. Mirrors Python `tn.set_signing(...)`.
   */
  static setSigning(enabled: boolean | null): void {
    _runtimeSetSigning(enabled);
  }

  /**
   * Enable or disable strict mode. When `true`, `Tn.init()` with no yaml
   * path throws if the discovery chain finds no file rather than silently
   * minting a fresh ceremony. Mirrors Python `tn.set_strict(enabled)`.
   */
  static setStrict(enabled: boolean): void {
    _strictMode = enabled;
  }

  // -------------------------------------------------------------------------
  // Identity / lifecycle
  // -------------------------------------------------------------------------

  get did(): string {
    return this._rt.did;
  }

  get logPath(): string {
    return this._rt.config.logPath;
  }

  /** Returns the underlying NodeRuntime config. */
  config(): unknown {
    return this._rt.config;
  }

  /** Always false — Tn wraps NodeRuntime (pure-TS), not a Rust WASM runtime. */
  usingRust(): boolean {
    return false;
  }

  /** Flush handlers and (for ephemeral instances) remove the tempdir.
   *
   * Also evicts this instance from the process-level handle registry
   * so a subsequent ``Tn.use(name, opts)`` call mints a fresh
   * runtime rather than returning a stale closed handle.
   */
  async close(): Promise<void> {
    this._rt.close();
    if (this._ownedTempdir !== undefined) {
      const td = this._ownedTempdir;
      this._ownedTempdir = undefined;
      try {
        rmSync(td, { recursive: true, force: true });
      } catch {
        // Best-effort: Windows file-handle races, etc.
      }
    }
    // Evict from registry. Linear scan is fine — registry size is
    // O(ceremonies in this project), not O(emits).
    for (const [k, v] of _registry) {
      if (v === this) {
        _registry.delete(k);
        break;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Context management
  // -------------------------------------------------------------------------

  /** Build the merged fields dict: scope-stack overlays + caller fields + run_id. */
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
   * Block-scoped context: layers `fields` on top of the current context,
   * runs `body`, restores prior context on return (even if `body` throws).
   * Mirrors Python `with tn.scope(**fields):`.
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
   * Replace the long-lived context with `fields`. Mirrors
   * Python `tn.set_context(**kwargs)`.
   */
  setContext(fields: Record<string, unknown>): void {
    this._contextStack[0] = { ...fields };
  }

  /**
   * Merge `fields` into the long-lived context (additive; existing keys
   * overwritten only when supplied). Mirrors Python `tn.update_context(**kwargs)`.
   */
  updateContext(fields: Record<string, unknown>): void {
    this._contextStack[0] = { ...this._contextStack[0], ...fields };
  }

  /**
   * Drop the long-lived context (and any nested `scope()` overlays).
   * Mirrors Python `tn.clear_context()`.
   */
  clearContext(): void {
    this._contextStack = [{}];
  }

  /**
   * Return a shallow copy of the merged context (long-lived + every active
   * `scope()` overlay). Mirrors Python `tn.get_context()`.
   */
  getContext(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const layer of this._contextStack) {
      for (const [k, v] of Object.entries(layer)) out[k] = v;
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Write verbs
  // -------------------------------------------------------------------------

  /**
   * Severity-less attested event. Always emits regardless of `setLevel()`.
   * Mirrors Python `tn.log(event_type, **fields)`.
   */
  log(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): EmitReceipt {
    return this._rt.emit(
      "",
      eventType,
      this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)),
    );
  }

  debug(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): EmitReceipt {
    if (10 < _tnLogLevelThreshold) return _nullReceipt();
    return this._rt.emit(
      "debug",
      eventType,
      this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)),
    );
  }

  info(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): EmitReceipt {
    if (20 < _tnLogLevelThreshold) return _nullReceipt();
    return this._rt.emit(
      "info",
      eventType,
      this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)),
    );
  }

  warning(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): EmitReceipt {
    if (30 < _tnLogLevelThreshold) return _nullReceipt();
    return this._rt.emit(
      "warning",
      eventType,
      this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)),
    );
  }

  error(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
  ): EmitReceipt {
    if (40 < _tnLogLevelThreshold) return _nullReceipt();
    return this._rt.emit(
      "error",
      eventType,
      this._mergeForEmit(normalizeLogFields(msgOrFields, fieldsIfMessage)),
    );
  }

  /**
   * Foundational emit. Routes through `_mergeForEmit` so context fields and
   * the per-client `run_id` are auto-injected — same behavior as the level
   * wrappers above.
   */
  emit(level: string, eventType: string, fields: Record<string, unknown>): EmitReceipt {
    return this._rt.emit(level, eventType, this._mergeForEmit(fields));
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
    return this._rt.emitWith(level, eventType, this._mergeForEmit(fields), opts);
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
    return this._rt.emitOverrideSign(level, eventType, this._mergeForEmit(fields), sign);
  }

  /** Full-control emit — timestamp + event_id + sign override. */
  emitWithOverrideSign(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    opts?: { timestamp?: string; eventId?: string; sign?: boolean | null },
  ): EmitReceipt {
    return this._rt.emitWithOverrideSign(level, eventType, this._mergeForEmit(fields), opts);
  }

  // -------------------------------------------------------------------------
  // Read verbs
  // -------------------------------------------------------------------------

  /**
   * Iterate decoded log entries. Default shape: flat decrypted dict per entry
   * (matching the 2026-04-25 read-ergonomics spec §1.1).
   *
   * Mirrors `TNClient.read()` behavior including:
   * - `allRuns` filter (default: current run only)
   * - `where` predicate
   * - foreign-log auto-routing via `readAsRecipient` (FINDINGS S6.2)
   * - `raw: true` for the `{envelope, plaintext, valid}` shape
   * - `verify: true` adds a `_valid` block to the flat shape
   */
  read(opts?: ReadOptions): Iterable<Record<string, unknown> | ReadEntry> {
    // Bug 3 fix: streams whose profile has no replay surface (e.g.
    // ``telemetry`` writes only to stdout) yield an empty iterator
    // rather than going to the reader. Mirrors Python's
    // ``TN.read``: "this stream has nothing to replay" is a
    // different shape, not an error.
    if (!this._hasReplaySurface()) {
      return (function* () {
        // intentionally empty
      })();
    }
    const verify = opts?.verify ?? false;
    const raw = opts?.raw ?? false;
    const logPath = opts?.logPath;
    const allRuns = opts?.allRuns ?? false;
    const where = opts?.where;
    const rt = this._rt;
    const runId = this._runId;

    const inCurrentRun = (entry: Record<string, unknown>): boolean => {
      const rid = entry["run_id"];
      return typeof rid === "string" && rid === runId;
    };

    // FINDINGS S6.2 — auto-route foreign logs through readAsRecipient.
    if (logPath !== undefined && _isForeignLog(logPath, this.did)) {
      const keystorePath = this._rt.config.keystorePath;
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
   * Audit-grade alias: returns the `{envelope, plaintext, valid}` shape.
   * Equivalent to `read({raw: true})`.
   */
  *readRaw(logPath?: string): Generator<ReadEntry, void, void> {
    yield* this._rt.read(logPath);
  }

  /**
   * Read a foreign publisher's log file using a kit from the local keystore.
   * Useful after absorbing a `kit_bundle` from a foreign publisher.
   */
  *readAsRecipient(opts: ReadAsRecipientOptions): Generator<Record<string, unknown>, void, void> {
    const entries = readAsRecipient(opts.logPath, this._rt.config.keystorePath, {
      group: opts.group ?? "default",
      verifySignatures: opts.verifySignatures ?? true,
    });
    for (const entry of entries) {
      const rEntry = {
        envelope: entry.envelope,
        plaintext: entry.plaintext,
        valid: {
          signature: entry.valid.signature,
          rowHash: true,
          chain: entry.valid.chain,
        },
      } as unknown as ReadEntry;
      yield flattenRawEntry(rEntry, { includeValid: false });
    }
  }

  /**
   * Iterate verified log entries — fail-closed on any (sig, row_hash, chain)
   * failure. Mirrors `TNClient.secureRead()`.
   *
   * `onInvalid` modes:
   * * `"skip"` (default) — silently drop non-verifying entries.
   * * `"raise"` — throw `VerificationError` on the first failure.
   * * `"forensic"` — yield the entry with `_valid` and `_invalid_reasons` exposed.
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
    for (const r of this._rt.read(logPath)) {
      const v = r.valid;
      const allValid = Boolean(v.signature) && Boolean(v.rowHash) && Boolean(v.chain);
      if (!allValid) {
        const reasons = invalidReasonsFromValid(v);
        const env = r.envelope;
        if (onInvalid === "raise") {
          throw new VerificationError(env, reasons);
        }
        if (onInvalid === "skip") {
          // Avoid looping our own tampered-row event back through secureRead.
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
        // forensic — yield with augmentation.
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

  /**
   * Async-iterable over live log appends. Opens the log, yields existing
   * entries from the chosen starting point, then keeps watching for new bytes.
   *
   * Tracks byte offset so we never re-read prior bytes on append. Survives
   * rotation (inode change) and emits a tamper-class admin event on
   * unexpected truncation.
   *
   * `since` controls the starting point:
   * - `"now"` (default) — yields only new appends after `watch()` is called.
   * - `"start"` — replays from the beginning of the current log file.
   * - A sequence number — resumes at the first envelope with sequence >= N.
   * - An ISO-8601 string — resumes at the first envelope with timestamp >= S.
   *
   * Break out of the `for await` loop to stop watching. The underlying
   * chokidar watcher is closed automatically when the generator is done.
   */
  watch(opts?: WatchOptions): AsyncIterable<Entry> {
    // Bug 3 fix: empty async-iterable for no-replay-surface streams.
    if (!this._hasReplaySurface()) {
      return (async function* () {
        // intentionally empty
      })();
    }
    return watch(this._rt, opts ?? {});
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** True iff this ceremony's profile has a readable backlog.
   *  Mirrors python/tn/_handle.py:_has_replay_surface. */
  private _hasReplaySurface(): boolean {
    try {
      const yamlPath = this._rt.config.yamlPath;
      const text = readFileSync(yamlPath, "utf8");
      const m = text.match(/^\s+profile:\s*(\S+)/m);
      const profileName = m?.[1];
      if (!profileName) return true;
      // Avoid sync require of profiles module on hot read paths;
      // hardcode the catalog property mirror. Matches profiles.ts.
      const noReplay: ReadonlySet<string> = new Set(["telemetry"]);
      return !noReplay.has(profileName);
    } catch {
      return true;
    }
  }

  /** Append a `tn.read.tampered_row_skipped` admin event — public fields only. */
  private _emitTamperedRowSkipped(
    envelope: Record<string, unknown>,
    reasons: string[],
  ): void {
    this._rt.emit(
      "warning",
      "tn.read.tampered_row_skipped",
      this._mergeForEmit({
        envelope_event_id: envelope["event_id"] ?? null,
        envelope_did: envelope["did"] ?? null,
        envelope_event_type: envelope["event_type"] ?? null,
        envelope_sequence: envelope["sequence"] ?? null,
        invalid_reasons: [...new Set(reasons)].sort(),
      }),
    );
  }

  /**
   * Look up the most-recent `tn.agents.policy_published` content_hash in
   * the local logs. Walks the main log + the admin log (if separate).
   */
  private _lastPolicyPublishedHash(): string | null {
    const sources = [this._rt.config.logPath];
    // Resolve the admin log path: if there's a sibling *.admin.ndjson use it.
    const adminCandidate = this._rt.config.logPath.replace(/\.ndjson$/, ".admin.ndjson");
    if (adminCandidate !== this._rt.config.logPath && existsSync(adminCandidate)) {
      sources.push(adminCandidate);
    }
    let lastTs = "";
    let lastHash: string | null = null;
    for (const path of sources) {
      if (!existsSync(path)) continue;
      let text: string;
      try {
        text = readFileSync(path, "utf8");
      } catch {
        continue;
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

  /** Emit `tn.agents.policy_published` iff the active policy's content_hash differs. */
  private _maybeEmitPolicyPublished(): void {
    const doc = this._rt.agentPolicy;
    if (doc === null) return;
    const last = this._lastPolicyPublishedHash();
    if (last === doc.contentHash) return;
    this._rt.emit(
      "info",
      "tn.agents.policy_published",
      this._mergeForEmit({
        policy_uri: doc.path,
        version: doc.version,
        content_hash: doc.contentHash,
        event_types_covered: [...doc.templates.keys()].sort(),
        policy_text: doc.body,
      }),
    );
  }
}
