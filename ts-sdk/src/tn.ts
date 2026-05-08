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
import { watch as _watchFlat, type WatchOptions as _WatchFlatOptions } from "./watch.js";
import { asRowHash, type LogLevel } from "./core/types.js";
import type { ReadEntry } from "./core/read_shape.js";
import { Entry, VerifyError } from "./Entry.js";
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
export { Entry, VerifyError } from "./Entry.js";
export type { WatchSince } from "./watch.js";

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
const _CEREMONY_NAME_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/;
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

function _checkVerifyKwarg(v: unknown): asserts v is VerifyMode {
  if (v === false || v === true || v === "skip" || v === "raise") return;
  throw new Error(
    `verify must be false | true | 'skip' | 'raise'; got ${JSON.stringify(v)}`,
  );
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

/** Verify mode for `Tn.read` / `Tn.watch`.
 *
 * - `false` (default): no integrity check.
 * - `true` or `"raise"`: raise `VerifyError` on the first failure.
 * - `"skip"`: drop validation-failed rows AND emit a
 *   `tn.read.tampered_row_skipped` admin event. Parse-level errors
 *   (malformed JSON, structurally broken envelopes) still throw.
 */
export type VerifyMode = false | true | "skip" | "raise";

export interface ReadOptions {
  /** Predicate applied per entry; rejected entries are skipped. */
  where?: (entry: Entry | Record<string, unknown>) => boolean;
  /** Integrity-check policy. Default: `false`. */
  verify?: VerifyMode;
  /** Yield the on-disk envelope dict instead of an `Entry`. */
  raw?: boolean;
  /** Override the log path. Defaults to the bound ceremony's log. */
  log?: string;
  /** Read using a foreign-publisher kit from this keystore directory. */
  asRecipient?: string;
  /** Group whose plaintext to surface (only with `asRecipient`). Default: `"default"`. */
  group?: string;
  /** Scan across all runs in the file. Default: false (current run only). */
  allRuns?: boolean;
}

export interface WatchOptions {
  /** Predicate applied per entry; rejected entries are skipped. */
  where?: (entry: Entry | Record<string, unknown>) => boolean;
  /** Integrity-check policy. Default: `false`. */
  verify?: VerifyMode;
  /** Yield the on-disk envelope dict instead of an `Entry`. */
  raw?: boolean;
  /** Override the log path. Defaults to the bound ceremony's log. */
  log?: string;
  /** Recipient mode is not yet supported on `Tn.watch`. */
  asRecipient?: string;
  /** Group whose plaintext to surface. Default: `"default"`. */
  group?: string;
  /** Starting point. Default: `"now"`. */
  since?: "start" | "now" | number | string;
  /** Polling fallback interval. Default: 300ms. */
  pollIntervalMs?: number;
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
        { cause: e },
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

  /**
   * Static absorb path for self-contained bootstrap bundles
   * (``identity_seed`` / ``project_seed``).
   *
   * In a fresh directory with no prior ``Tn.init()``, call this to
   * install the bundle's tn.yaml + keystore — the follow-up
   * ``Tn.init()`` then picks them up. Mirrors Python
   * ``tn.pkg.absorb(file)``-without-init.
   *
   * For non-bootstrap kinds (kit_bundle, admin_log_snapshot, etc.),
   * use an instance method on ``Tn`` instead.
   */
  static async absorb(
    source: string | Uint8Array,
    opts: { cwd?: string } = {},
  ): Promise<import("./core/results.js").AbsorbReceipt> {
    const { absorbBootstrap } = await import("./runtime/absorb_bootstrap.js");
    return absorbBootstrap(source, opts);
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
  // Read verbs (0.4.0a1 — single thin verb)
  // -------------------------------------------------------------------------

  /**
   * Iterate log entries. Default mode yields `Entry` instances. Pass
   * `raw: true` to yield the on-disk envelope dict (group-keyed
   * ciphertext blocks intact), useful for forensics and chain auditors.
   *
   * Mirrors Python `tn.read`. Kwargs:
   * - `where`        — predicate `(Entry) -> bool`; non-matching skipped.
   * - `verify`       — `false` (default), `true` / `"raise"` (throw
   *                    `VerifyError` on first failure), `"skip"` (drop
   *                    validation failures and emit a
   *                    `tn.read.tampered_row_skipped` admin event).
   * - `raw`          — yield envelope dict instead of `Entry`.
   * - `log`          — alternate log path.
   * - `asRecipient`  — keystore directory to decrypt with (foreign-log mode).
   * - `group`        — group plaintext to surface (with `asRecipient`).
   * - `allRuns`      — scan across all runs.
   */
  *read(opts: ReadOptions = {}): IterableIterator<Entry | Record<string, unknown>> {
    // Bug 3 fix: streams whose profile has no replay surface (e.g.
    // ``telemetry`` writes only to stdout) yield an empty iterator
    // rather than going to the reader.
    if (!this._hasReplaySurface()) return;

    const verify = opts.verify ?? false;
    _checkVerifyKwarg(verify);
    const raw = opts.raw ?? false;
    const logPath = opts.log;
    const asRecipient = opts.asRecipient;
    const group = opts.group ?? "default";
    const allRuns = opts.allRuns ?? false;
    const where = opts.where;
    const rt = this._rt;
    const runId = this._runId;

    // Choose the source of {envelope, plaintext, valid} triples.
    let triples: Iterable<ReadEntry>;
    let usingRecipient = false;
    if (
      asRecipient !== undefined ||
      (logPath !== undefined && _isForeignLog(logPath, this.did))
    ) {
      const keystorePath = asRecipient ?? this._rt.config.keystorePath;
      const path = logPath ?? this._rt.config.logPath;
      usingRecipient = true;
      const foreignIter = readAsRecipient(path, keystorePath, {
        group,
        verifySignatures: verify !== false,
      });
      triples = (function* () {
        for (const entry of foreignIter) {
          const rEntry: ReadEntry = {
            envelope: entry.envelope,
            plaintext: entry.plaintext,
            valid: {
              signature: entry.valid.signature,
              rowHash: true,
              chain: entry.valid.chain,
            },
          };
          yield rEntry;
        }
      })();
    } else {
      triples = rt.read(logPath);
    }

    // Helper: per-row run-id filter (only applies to local reads).
    const matchesRun = (r: ReadEntry): boolean => {
      if (allRuns) return true;
      const pt = r.plaintext ?? {};
      const env = r.envelope;
      // run_id is plaintext-payload; check every group's body.
      for (const body of Object.values(pt)) {
        if (body && typeof body === "object" && "run_id" in body) {
          return body["run_id"] === runId;
        }
      }
      const envRid = env["run_id"];
      return typeof envRid === "string" && envRid === runId;
    };

    // Iterator wrapper that handles parser-level errors per `verify` policy.
    const safeIter = (function* (this: Tn): IterableIterator<ReadEntry> {
      const it = (triples as Iterable<ReadEntry>)[Symbol.iterator]();
      while (true) {
        let next: IteratorResult<ReadEntry>;
        try {
          next = it.next();
        } catch (exc) {
          if (verify === "skip") {
            try {
              this._emitTamperedRowSkipped(
                { event_type: "<parse-error>" },
                [`parse: ${(exc as Error).name}: ${(exc as Error).message}`],
              );
            } catch {
              // best-effort
            }
            continue;
          }
          if (verify === true || verify === "raise") {
            throw new VerifyError(
              0,
              "<parse-error>",
              [`parse: ${(exc as Error).name}: ${(exc as Error).message}`],
            );
          }
          throw exc;
        }
        if (next.done) return;
        yield next.value;
      }
    }).call(this);

    for (const r of safeIter) {
      // run_id filter — only on local reads. Recipient-mode reads cross
      // publishers, so filtering by your local run_id makes no sense.
      if (!usingRecipient && !matchesRun(r)) continue;

      const v = r.valid;
      const allValid = Boolean(v.signature) && Boolean(v.rowHash) && Boolean(v.chain);
      if (!allValid && verify !== false) {
        const reasons: string[] = [];
        if (!v.signature) reasons.push("signature");
        if (!v.rowHash) reasons.push("row_hash");
        if (!v.chain) reasons.push("chain");
        if (verify === true || verify === "raise") {
          throw new VerifyError(
            Number(r.envelope["sequence"] ?? 0),
            String(r.envelope["event_type"] ?? ""),
            reasons,
          );
        }
        if (verify === "skip") {
          // Avoid looping our own tampered-row event back through.
          if (String(r.envelope["event_type"] ?? "") === "tn.read.tampered_row_skipped") {
            continue;
          }
          try {
            this._emitTamperedRowSkipped(r.envelope, reasons);
          } catch {
            // best-effort
          }
          continue;
        }
      }

      if (raw) {
        const env = r.envelope;
        if (where && !where(env)) continue;
        yield env;
        continue;
      }

      let entry: Entry;
      try {
        entry = Entry.fromRaw(r);
      } catch {
        // malformed entry, skip rather than abort
        continue;
      }
      if (where && !where(entry)) continue;
      yield entry;
    }
  }

  /**
   * Tail the log live, yielding entries as they arrive. Async generator.
   *
   * Same options as `Tn.read` plus:
   * - `since`        — `"now"` (default) | `"start"` | sequence number | ISO timestamp
   * - `pollIntervalMs` — fallback poll interval (default 300ms)
   *
   * Recipient-mode watch (`asRecipient`) is not yet supported. Use
   * `Tn.read({asRecipient})` for one-shot foreign-log reads.
   */
  async *watch(opts: WatchOptions = {}): AsyncIterableIterator<Entry | Record<string, unknown>> {
    if (!this._hasReplaySurface()) return;

    if (opts.asRecipient !== undefined) {
      throw new Error(
        "Tn.watch with asRecipient is not yet supported. Use Tn.read for foreign-keystore reads.",
      );
    }

    const verify = opts.verify ?? false;
    _checkVerifyKwarg(verify);
    const raw = opts.raw ?? false;
    const where = opts.where;

    const flatOpts: _WatchFlatOptions = {};
    if (opts.since !== undefined) flatOpts.since = opts.since;
    if (opts.log !== undefined) flatOpts.logPath = opts.log;
    if (opts.pollIntervalMs !== undefined) flatOpts.pollIntervalMs = opts.pollIntervalMs;
    // _watchFlat does its own sig check when `verify` is truthy. We
    // currently best-effort verify on watch (Python parity — there's no
    // raw-triples access post-flatten on this path).
    flatOpts.verify = verify !== false;

    for await (const flat of _watchFlat(this._rt, flatOpts)) {
      if (raw) {
        if (where && !where(flat)) continue;
        yield flat;
        continue;
      }
      let entry: Entry;
      try {
        entry = Entry.fromFlat(flat);
      } catch {
        continue;
      }
      if (where && !where(entry)) continue;
      yield entry;
    }
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
