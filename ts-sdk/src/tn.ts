// tn-proto — main Layer 2 class, the 0.3.0 replacement for TNClient.
//
// Lifecycle (the four-line dirt-easy summary):
//
//   1. const tn = await Tn.absorb('Agentic20.project.tnpkg');
//   2. tn.info("hello.world", { who: "alice" });
//   3. for (const e of tn.read()) console.log(`${e}`);
//   4. await tn.close();
//
// Step 1 is optional once a ceremony is on disk; ``Tn.init()`` will
// discover ``./tn.yaml`` (legacy), ``./.tn/default/tn.yaml`` (legacy
// multi-ceremony), or create/open ``./.tn/<cwd-name>/tn.yaml`` on first
// call. Step 4 is best-practice in long-running processes; ephemeral
// ceremonies need it to clean their tempdir.
//
// Splits into namespaced sub-objects (tn.admin, tn.pkg, tn.vault,
// tn.agents, tn.handlers). I/O verbs are async; emit/read stay sync.

import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as pathResolve, isAbsolute as pathIsAbsolute } from "node:path";

import { NodeRuntime, setSigning as _runtimeSetSigning } from "./runtime/node_runtime.js";
import {
  initUpload as _initUpload,
  type InitUploadOptions,
  type InitUploadResult,
} from "./handlers/init_upload.js";
import { iterLogFiles } from "./runtime/reconcile.js";
import { DEFAULT_CEREMONY_NAME, ensureProjectLayoutOnDisk, defaultProjectName } from "./multi.js";
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
import { readAsRecipient, readAsRecipientAsync } from "./read_as_recipient.js";
import { ScopeBuilder } from "./scope.js";
import {
  sealWithRuntime,
  unsealWithRuntime,
  type SealOptions,
  type SealedObject,
  type SealedTriple,
  type UnsealOptions,
  type UnsealSource,
} from "./seal.js";

// ---------------------------------------------------------------------------
// Re-export types for callers that import from tn.ts directly.
// ---------------------------------------------------------------------------
export type { LogLevel } from "./core/types.js";
export type { EmitReceipt } from "./core/results.js";
export { Entry, VerifyError } from "./Entry.js";
export type { WatchSince } from "./watch.js";
export { SealedObject, SealedObjectError } from "./seal.js";
export type { SealOptions, SealedTriple, UnsealOptions, UnsealSource } from "./seal.js";

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
  const v = _LOG_LEVELS[level];
  if (v === undefined) {
    // Without this guard an unknown name sets the threshold to `undefined`,
    // which makes every `value <= threshold` comparison false and silently
    // drops all emits. Fail loud instead.
    throw new Error(
      `unknown log level ${JSON.stringify(level)}; expected one of ` +
        `${Object.keys(_LOG_LEVELS).join(", ")}`,
    );
  }
  return v;
}

// ---------------------------------------------------------------------------
// Module-level strict mode. When true, Tn.init() with no yaml path throws
// rather than silently minting a fresh ceremony.
//
// Source order matches Python's `_autoinit.is_strict()`:
//   1. `Tn.setStrict(...)` programmatic override (tracked via
//      `_strictOverride !== null`).
//   2. `TN_STRICT` env var — truthy when its lowercased value is in
//      {"1", "true", "yes", "on"} (mirror of python/tn/_autoinit.py:71).
//   3. Default: false.
// ---------------------------------------------------------------------------
const _STRICT_TRUTHY = new Set(["1", "true", "yes", "on"]);

function _envStrict(): boolean {
  const raw = (process.env["TN_STRICT"] ?? "").trim().toLowerCase();
  return _STRICT_TRUTHY.has(raw);
}

/** Programmatic override; `null` falls through to the env-var check. */
let _strictOverride: boolean | null = null;

/** Effective strict-mode flag. Honors the override first, env second. */
function _strictMode(): boolean {
  if (_strictOverride !== null) return _strictOverride;
  return _envStrict();
}

// Process-singleton `run_id`. Implementation lives in `./_run_id.ts`
// so `node_runtime.ts` can stamp the same env var before wasm-init
// without an import cycle through `Tn`.
import { ensureProcessRunId as _ensureProcessRunId } from "./_run_id.js";

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
      (h) => h != null && typeof h === "object" && (h as Record<string, unknown>).kind === "stdout",
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
      const envDid = env["device_identity"];
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

/**
 * Authoritative client-side selector + filter gate. Byte-parity with Python's
 * `read.py::_passes_selector_filter`: re-applies the selector + declarative
 * filter against the envelope's public fields (event_type, level) regardless of
 * whether a source pushed them down. An entry passes when it satisfies the
 * selector (if any) AND every present filter clause.
 */
function _passesSelectorFilter(
  env: Record<string, unknown>,
  selector: string | null | undefined,
  filter: ReadFilter | undefined,
): boolean {
  const et = String(env["event_type"] ?? "");
  if (selector !== null && selector !== undefined && et !== selector) return false;
  if (filter) {
    const lvl = String(env["level"] ?? "");
    if (filter.event_type_in !== undefined && !filter.event_type_in.includes(et)) return false;
    if (filter.event_type_prefix !== undefined && !et.startsWith(filter.event_type_prefix)) {
      return false;
    }
    if (filter.level_in !== undefined && !filter.level_in.includes(lvl)) return false;
  }
  return true;
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

/** True iff `arg` is an explicit yaml path rather than a project name.
 *  Mirrors Python `_looks_like_yaml_path`: conservative - only a `.yaml` /
 *  `.yml` suffix counts, so a malformed name still surfaces as a name error. */
function _looksLikeYamlPath(arg: string): boolean {
  return arg.endsWith(".yaml") || arg.endsWith(".yml");
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
  throw new Error(`verify must be false | true | 'skip' | 'raise'; got ${JSON.stringify(v)}`);
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
  /**
   * Auto-link to a vault and surface a claim URL after init (the module-level
   * `tn.init()` only — the `Tn` class factory never touches the network).
   *
   *   - `true`  — always run the vault upload + claim-URL surfacing.
   *   - `false` — never (the CLI passes this; it runs its own vault flow).
   *   - `undefined` (default) — AUTO: run iff in a serverless context
   *     (Vercel / AWS Lambda / Netlify / Cloud Run / Azure Functions),
   *     mirroring Python's "auto in a notebook kernel" gate. `TN_NO_LINK=1`
   *     is a hard opt-out in every mode.
   */
  link?: boolean;
  /** Override the vault base URL for the auto-link upload. Default resolution:
   *  `TN_VAULT_URL` env, else the hosted vault. */
  vaultUrl?: string;
  /**
   * Group-sealing cipher when the init mints a FRESH ceremony (no effect on
   * an existing yaml — the cipher is read from the yaml). `"btn"` (default),
   * `"hibe"` (BBG hierarchical identity-based encryption; the fresh keystore
   * becomes its own HIBE authority), or `"jwe"` (per-recipient ECDH-ES; the
   * creator becomes publisher and sole reader — seal/open with the async
   * emitAsync/readAsync verbs). Mirrors Python's `tn.init(..., cipher=...)`.
   */
  cipher?: "btn" | "hibe" | "jwe";
}

/**
 * Internal-only option for the auto-init load path. When `mint` is
 * `false` and the discovery chain finds no existing ceremony, `initSync`
 * throws a friendly "no ceremony found" error instead of minting a fresh
 * one. Mirrors Python's split between `maybe_autoinit` (mint) and
 * `maybe_autoinit_load_only` (discover-or-throw). Not part of the public
 * `Tn.init` surface — the read/watch module-level verbs pass it.
 *
 * @internal
 */
interface _InitInternalOptions {
  /** When `false`, discover an existing ceremony but never mint. Default: `true`. */
  mint?: boolean;
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

/**
 * Declarative selector dict applied as the authoritative client-side gate.
 * Byte-parity with Python's `filter` argument (read.py `_passes_selector_filter`):
 * an entry passes when it satisfies EVERY present clause.
 */
export interface ReadFilter {
  /** event_type must be one of these exact strings. */
  event_type_in?: string[];
  /** event_type must start with this prefix. */
  event_type_prefix?: string;
  /** level must be one of these strings. */
  level_in?: string[];
}

export interface ReadOptions {
  /**
   * Primary selector: an exact `event_type` (no wildcards). `undefined`/`null`
   * reads every event_type. Mirrors Python's positional `selector` argument.
   */
  selector?: string | null;
  /**
   * Declarative selector dict (`event_type_in` / `event_type_prefix` /
   * `level_in`) applied as the authoritative gate. Mirrors Python's `filter`.
   */
  filter?: ReadFilter;
  /** Predicate applied per entry; rejected entries are skipped. */
  where?: (entry: Entry | Record<string, unknown>) => boolean;
  /** Integrity-check policy. Default: `true`; pass false to inspect unverified rows. */
  verify?: VerifyMode;
  /** Yield the on-disk envelope dict instead of an `Entry`. */
  raw?: boolean;
  /** Override the log path. Defaults to the bound ceremony's log. */
  log?: string;
  /** Read using a foreign-publisher kit from this keystore directory. */
  asRecipient?: string;
  /** Foreign group override; omit to surface every locally keyed group. */
  group?: string;
  /** Foreign-read writer allowlist; defaults to installed verified publishers. */
  trustedPublisherDids?: string[];
  /** Explicit weakening: permit foreign rows from a writer not in trustedPublisherDids. */
  unsafeAllowUnverifiedPublisher?: boolean;
  /** Scan across all runs in the file. Default: false (current run only). */
  allRuns?: boolean;
  /**
   * Require the first entry of each event_type chain to anchor at the genesis
   * ZERO_HASH, flagging a front-truncated log (`valid.chain=false` on the new
   * first entry). Off by default — ordinary, resumed, rotated, and partial
   * reads legitimately start mid-chain. Opt in only when reading a COMPLETE
   * log from its true start (an audit). See `verifyChainLink`.
   */
  expectGenesis?: boolean;
}

export interface WatchOptions {
  /** Primary selector: an exact `event_type`. Mirrors Python's positional `selector`. */
  selector?: string | null;
  /** Declarative selector dict. Mirrors Python's `filter`. */
  filter?: ReadFilter;
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

/** Per-emit options for the write verbs. Trailing/optional so existing
 * `tn.info(evt, fields)` calls are unaffected. Mirrors Python's `aad=` kwarg. */
export interface EmitOpts {
  /** Additional-authenticated-data: a flat mapping of string -> scalar bound
   * (authenticated, not encrypted) to every group sealed on this row, merged
   * OVER any yaml per-group `aad` default and echoed into the public `tn_aad`
   * block. Not yet wired through the native (btn) runtime — passing it on a
   * btn ceremony throws. Omit (or empty) to bind nothing. */
  aad?: Record<string, unknown>;
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

  /**
   * The claim URL minted by the module-level `tn.init()` auto-link, or `null`
   * when no auto-link ran (link disabled, not serverless, or the upload
   * failed). Paste it into a browser to attach this project to a vault account.
   * Populated only on the instance returned by the `tn.init()` export, never by
   * the `Tn.init`/`Tn.use` class factories (which never touch the network).
   */
  claimUrl: string | null = null;
  /** Full auto-link result behind {@link claimUrl} (vault id + TTL), or null. */
  claim: { vaultId: string; expiresAt: string; claimUrl: string } | null = null;

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
    // Process-singleton, NOT per-instance: every Tn handle in this
    // process stamps the same run_id so reads can filter to "this run
    // only" the way Python does. `_ensureProcessRunId` also writes
    // `process.env["TN_RUN_ID"]` so the wasm runtime — which reads that
    // env at init (crypto/tn-core/src/runtime.rs:860) — picks up the
    // same value and stamps matching `run_id`s on its own writes.
    this._runId = _ensureProcessRunId();
    this.admin = new AdminNamespace(rt);
    this.pkg = new PkgNamespace(rt);
    this.vault = new VaultNamespace(rt, (f) => this._mergeForEmit(f));
    this.agents = new AgentsNamespace(rt);
    this.handlers = new HandlersNamespace(rt);
    // Best-effort policy bookkeeping — mirrors TNClient constructor. Init
    // must not block on it, but a real regression here shouldn't vanish
    // without a trace: surface it on stderr under TN_DEBUG (matching this
    // file's env-gated stderr convention; no console dependency).
    try {
      this._maybeEmitPolicyPublished();
    } catch (e) {
      if (process.env["TN_DEBUG"]) {
        try {
          process.stderr.write(
            `[tn:debug] policy bookkeeping failed in Tn.init: ` +
              `${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}\n`,
          );
        } catch {
          /* ignore broken stderr */
        }
      }
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
   *   3. `./.tn/default/tn.yaml`  (legacy multi-ceremony layout)
   *   4. exactly one `./.tn/<project>/tn.yaml` project-root layout
   * If strict mode is active (`Tn.setStrict(true)`) and no file is found,
   * an error is thrown. Otherwise a fresh project-root ceremony is minted
   * at `./.tn/<cwd-name>/tn.yaml`.
   *
   * Use `Tn.use(stream, { project })` for per-stream handles. Fresh
   * project roots keep stream overlays at `.tn/<project>/streams/<stream>.yaml`.
   */
  static async init(
    yamlPath?: string,
    opts?: TnInitOptions & { projectDir?: string; profile?: string },
  ): Promise<Tn> {
    // `Tn.init` is intentionally a thin async wrapper around the now-sync
    // `initSync`. It stays async so existing callers (`await Tn.init()`,
    // `Tn.init().then(...)`) keep working unchanged — a NON-breaking
    // signature. All discovery/mint logic lives in `initSync`.
    return Tn.initSync(yamlPath, opts);
  }

  /**
   * Synchronous core of {@link Tn.init}. The wasm core self-instantiates
   * at module load (see index.ts) and `multi.js` is statically imported,
   * so nothing in this path is async — making auto-init from the
   * synchronous emit/read verbs possible.
   *
   * @param yamlPath - explicit yaml path, project name, or `undefined`
   *   to walk the discovery chain.
   * @param opts - public init options plus the internal `mint` flag
   *   (`mint: false` discovers an existing ceremony but throws rather
   *   than minting when none is found — the load-only read path).
   */
  static initSync(
    yamlPath?: string,
    opts?: TnInitOptions & { projectDir?: string; profile?: string } & _InitInternalOptions,
  ): Tn {
    let resolvedPath = yamlPath;
    const mint = opts?.mint ?? true;

    // Parity with Python `tn.init`: the first argument is a PROJECT NAME unless
    // it ends in `.yaml` / `.yml` (then it's an explicit yaml path). A name
    // opens/creates the local project at `.tn/<name>/tn.yaml`. Without this, a
    // bare name like "billing" was wrongly used as a literal file path.
    if (resolvedPath !== undefined && !_looksLikeYamlPath(resolvedPath)) {
      const name = resolvedPath;
      if (!_isValidCeremonyName(name)) {
        throw new Error(
          `Tn.init: invalid project name ${JSON.stringify(name)}; must match ` +
            `[a-zA-Z0-9_][a-zA-Z0-9_-]* and not be 'tn'. Pass a path ending in ` +
            `.yaml to use an explicit yaml file instead.`,
        );
      }
      const layoutOpts: {
        projectDir?: string;
        profile?: string;
        cipher?: "btn" | "hibe" | "jwe";
      } = {
        projectDir: opts?.projectDir ?? process.cwd(),
      };
      if (opts?.profile !== undefined) layoutOpts.profile = opts.profile;
      if (opts?.cipher !== undefined) layoutOpts.cipher = opts.cipher;
      resolvedPath = ensureProjectLayoutOnDisk(name, layoutOpts);
    }

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
      // the legacy single-ceremony layout.
      if (resolvedPath === undefined) {
        const candidate = join(process.cwd(), ".tn", "default", "tn.yaml");
        if (existsSync(candidate)) resolvedPath = candidate;
      }

      // 4. Existing project-root layout: exactly one .tn/<project>/tn.yaml,
      // excluding the legacy default name handled above.
      if (resolvedPath === undefined) {
        const root = join(process.cwd(), ".tn");
        if (existsSync(root)) {
          const candidates = readdirSync(root)
            .filter((name) => name !== "default" && _isValidCeremonyName(name))
            .map((name) => join(root, name, "tn.yaml"))
            .filter((path) => existsSync(path));
          if (candidates.length === 1) resolvedPath = candidates[0];
        }
      }

      if (resolvedPath === undefined) {
        if (!mint) {
          // Load-only mode (read/watch auto-init): discover an existing
          // ceremony but never mint one. Mirrors Python
          // `_autoinit.maybe_autoinit_load_only` — a friendly error that
          // points at the same recovery steps.
          throw new Error(
            "tn: no ceremony found. Looked at $TN_YAML, ./tn.yaml, " +
              "./.tn/default/tn.yaml, and ./.tn/<project>/tn.yaml. Run " +
              "`tn.init()` (or an emit verb like `tn.info(...)` to " +
              "auto-create one), set TN_YAML, or create ./tn.yaml, then retry.",
          );
        }
        if (_strictMode()) {
          throw new Error(
            "Tn.init: no yaml path provided and strict mode is on. " +
              "Set TN_YAML env var, create ./tn.yaml, set TN_HOME, " +
              "or pass a path explicitly to Tn.init(). To start from a " +
              "downloaded seed, run `tn-js import <seed.tnpkg>`. " +
              "(Strict mode is on via Tn.setStrict(true) or TN_STRICT=1.)",
          );
        }
        resolvedPath = ensureProjectLayoutOnDisk(defaultProjectName(process.cwd()), {
          projectDir: process.cwd(),
        });
      }
    }

    const rt = NodeRuntime.init(
      resolvedPath,
      opts?.cipher !== undefined ? { cipher: opts.cipher } : {},
    );
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
   * Get-or-create a named stream inside a Project.
   *
   * Mirrors Python's ``tn.use(name)``. Same semantics, same
   * verb. ``Tn.openCeremony`` is kept as a deprecated alias.
   *
   * Fresh project-root streams live at
   * ``.tn/<project>/streams/<stream>.yaml`` and write application
   * entries to ``.tn/<project>/logs/<stream>.ndjson``. The Project root
   * owns identity, groups, recipients, keystore, admin state, and vault
   * control state. When ``project`` is omitted, the current Project is
   * used if one is bound; otherwise the cwd name is inferred unless a
   * legacy ``.tn/default/tn.yaml`` exists.
   *
   * **Handle interning.** Per-(projectDir, name), this call returns
   * the same ``Tn`` instance across repeated invocations within the
   * same process. Two calls with the same arguments give you the
   * same handle — matching Python's ``tn.use`` registry contract.
   * Calling ``close()`` on the cached instance evicts it; subsequent
   * calls mint a fresh one.
   */
  static async use(
    name: string = DEFAULT_CEREMONY_NAME,
    opts?: TnInitOptions & { projectDir?: string; profile?: string; project?: string },
  ): Promise<Tn> {
    // Parity with Python `tn.use(name=None)`: a missing name resolves the
    // `default` ceremony rather than erroring. `name ?? ...` also catches an
    // explicit `undefined` passed by the module-level `tn.use()` wrapper.
    name = name ?? DEFAULT_CEREMONY_NAME;
    const {
      ensureCeremonyOnDisk,
      ensureProjectStreamOnDisk,
      ceremonyYamlPath,
      defaultProjectName,
      streamLayout,
      checkProfileConflict,
      migrateLegacyLayout,
    } = await import("./multi.js");
    if (!_isValidCeremonyName(name)) {
      throw new Error(
        `Tn.use: invalid ceremony name ${JSON.stringify(name)}; ` +
          "must match [a-zA-Z0-9_][a-zA-Z0-9_-]* and not be 'tn' (reserved).",
      );
    }
    const projectDir = opts?.projectDir ?? process.cwd();

    if (opts?.project !== undefined) {
      const layout = streamLayout(name, { project: opts.project, projectDir });
      const cacheKey = `${layout.project.projectDir}::${name}`;
      const cached = _registry.get(cacheKey);
      if (cached !== undefined) return cached;
      checkProfileConflict(layout.streamYaml, opts.profile);
      ensureProjectStreamOnDisk(name, {
        project: opts.project,
        projectDir,
        ...(opts.profile !== undefined ? { profile: opts.profile } : {}),
      });
      const tn = await Tn.init(layout.streamYaml, opts);
      _registry.set(cacheKey, tn);
      return tn;
    }

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
      throw new Error(`Tn.use: legacy layout migration failed: ${(e as Error).message}`, {
        cause: e,
      });
    }

    const yamlPath = ceremonyYamlPath(name, projectDir);
    const defaultYamlPath = ceremonyYamlPath("default", projectDir);
    if (name !== "default" && !existsSync(yamlPath) && !existsSync(defaultYamlPath)) {
      return Tn.use(name, {
        ...opts,
        project: defaultProjectName(projectDir),
        projectDir,
      });
    }
    checkProfileConflict(yamlPath, opts?.profile);
    const ensureOpts: { projectDir?: string; profile?: string } = { projectDir };
    if (opts?.profile !== undefined) ensureOpts.profile = opts.profile;

    // Will the default ceremony get auto-minted as a side effect?
    // Bug 2 fix: surface a loud, one-time notice so the operator
    // sees that a fresh project DID was just created.
    const willMintDefault = !existsSync(defaultYamlPath);

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
    opts?: TnInitOptions & { projectDir?: string; profile?: string; project?: string },
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
   * Enable or disable strict mode programmatically.
   *
   * When strict mode is on, `Tn.init()` with no yaml path THROWS if
   * the discovery chain finds no file — rather than silently minting
   * a fresh ceremony. Use in production to ensure no accidental
   * fresh-ceremony minting on a misconfigured deploy.
   *
   * Precedence (mirror of `python/tn/_autoinit.is_strict()`):
   *
   * 1. {@link Tn.setStrict} programmatic override.
   * 2. `TN_STRICT` env var — truthy when lowercased value is in
   *    `{"1", "true", "yes", "on"}`.
   * 3. Default: false (auto-mint allowed).
   *
   * @param enabled - new programmatic-override value.
   *
   * @example
   * ```ts
   * // Production: block any accidental fresh-mint.
   * Tn.setStrict(true);
   * await Tn.init();   // throws if no yaml found
   *
   * // Test: undo the override.
   * Tn.clearStrict();  // falls back to env
   * ```
   *
   * @see {@link Tn.clearStrict} {@link Tn.isStrict}
   * @public
   */
  static setStrict(enabled: boolean): void {
    _strictOverride = enabled;
  }

  /**
   * Drop the programmatic strict-mode override. After this, strict
   * mode is determined solely by the `TN_STRICT` env var.
   *
   * @example
   * ```ts
   * beforeEach(() => Tn.clearStrict());   // tests start neutral
   * ```
   *
   * @see {@link Tn.setStrict}
   *
   * @remarks
   * Mirrors `python/tn/_autoinit.reset_state_for_tests`.
   *
   * @public
   */
  static clearStrict(): void {
    _strictOverride = null;
  }

  /**
   * Read the effective strict-mode flag.
   *
   * @returns The programmatic override if set; otherwise the
   *   `TN_STRICT` env-var truthy check; otherwise `false`.
   *
   * @example
   * ```ts
   * if (Tn.isStrict()) {
   *   // Don't auto-mint; require an explicit yaml path.
   * }
   * ```
   *
   * @see {@link Tn.setStrict}
   * @public
   */
  static isStrict(): boolean {
    return _strictMode();
  }

  /**
   * Static dirt-easy entry point: absorb a self-contained bootstrap
   * bundle (``identity_seed`` / ``project_seed``) and return a usable
   * ``Tn`` bound to the freshly-absorbed layout.
   *
   *     const tn = await Tn.absorb('Agentic20.project.tnpkg');
   *     tn.info("hello.world", { who: "alice" });
   *     for (const e of tn.read()) console.log(`${e}`);
   *
   * The returned instance behaves exactly like ``await Tn.init(yamlPath)``
   * would, where ``yamlPath`` is the just-written ``./tn.yaml``. The
   * absorb receipt is exposed on the instance as ``tn.lastAbsorbReceipt``
   * for callers that need to inspect ``acceptedCount`` /
   * ``rejectedReason`` / etc.
   *
   * Bootstrap kinds:
   *
   * * ``project_seed`` — the dashboard's "Create Project" bundle. Ships
   *   a complete ``tn.yaml`` + keystore. Loaded as-is.
   * * ``identity_seed`` — minimal "I am DID X" bundle. The yaml stub
   *   isn't a loadable ceremony; this method promotes it to a real
   *   ceremony bound to the absorbed identity (similar to running
   *   ``tn init`` against a pre-existing keystore).
   *
   * For non-bootstrap kinds (kit_bundle, admin_log_snapshot, etc.),
   * call ``await Tn.init(yamlPath)`` first then use the instance
   * method ``tn.pkg.absorb(source)``.
   *
   * Throws if the bundle is rejected (signature failure, tamper, kind
   * not supported standalone). Inspect ``e.message`` for the reason.
   */
  static async absorb(
    source: string | Uint8Array,
    opts: { cwd?: string } & TnInitOptions = {},
  ): Promise<Tn> {
    const { absorbBootstrap } = await import("./runtime/absorb_bootstrap.js");
    const { createFreshCeremony } = await import("./runtime/node_runtime.js");
    const cwd = pathResolve(opts.cwd ?? process.cwd());
    const receipt = absorbBootstrap(source, { cwd });
    if (receipt.rejectedReason) {
      throw new Error(`Tn.absorb: bundle rejected: ${receipt.rejectedReason}`);
    }

    const yamlPath = pathResolve(cwd, "tn.yaml");

    if (receipt.kind === "identity_seed") {
      // Stub yaml from identity_seed is not a loadable ceremony.
      // Replace it with a real ceremony bound to the absorbed device
      // key (mirrors Python ``_bind_after_bootstrap_absorb``).
      const keysDir = pathResolve(cwd, ".tn", "tn", "keys");
      const privPath = pathResolve(keysDir, "local.private");
      if (existsSync(privPath)) {
        const seed = new Uint8Array(readFileSync(privPath));
        // createFreshCeremony refuses if local.private already
        // exists; remove the absorbed keypair, then mint with the
        // same seed so the ceremony adopts the absorbed identity.
        try {
          rmSync(privPath, { force: true });
        } catch {
          /* best effort */
        }
        const pubPath = pathResolve(keysDir, "local.public");
        try {
          rmSync(pubPath, { force: true });
        } catch {
          /* best effort */
        }
        try {
          rmSync(yamlPath, { force: true });
        } catch {
          /* best effort */
        }
        createFreshCeremony(yamlPath, { devicePrivateBytes: seed });
      }
    }

    const initOpts: TnInitOptions = {};
    if (opts.stdout !== undefined) initOpts.stdout = opts.stdout;
    const tn = await Tn.init(yamlPath, initOpts);
    tn._lastAbsorbReceipt = receipt;
    return tn;
  }

  /** Receipt from the most recent ``Tn.absorb`` static-factory call,
   *  or ``undefined`` for instances minted via ``Tn.init`` /
   *  ``Tn.use`` / ``Tn.ephemeral``. */
  get lastAbsorbReceipt(): import("./core/results.js").AbsorbReceipt | undefined {
    return this._lastAbsorbReceipt;
  }
  private _lastAbsorbReceipt: import("./core/results.js").AbsorbReceipt | undefined;

  // -------------------------------------------------------------------------
  // Identity / lifecycle
  // -------------------------------------------------------------------------

  get did(): string {
    return this._rt.did;
  }

  get logPath(): string {
    return this._rt.config.logPath;
  }

  /** Absolute path to this ceremony's `tn.yaml`. Mirrors Python's
   *  `TN.yaml_path`. */
  get yamlPath(): string {
    return (this._rt.config as { yamlPath?: string }).yamlPath ?? "";
  }

  /** Registry name of this ceremony (e.g. `"payments"`, `"default"`).
   *
   *  Mirrors Python's `TN.name`. Derived from `yamlPath`:
   *    `<...>/.tn/<NAME>/tn.yaml` → `NAME`
   *    anything else → `"default"` (the legacy single-yaml layout).
   */
  get name(): string {
    const yp = this.yamlPath;
    // Match Windows + POSIX separators. `.tn/<name>/tn.yaml` is the
    // canonical multi-ceremony layout.
    const m = yp.match(/[/\\]\.tn[/\\]([^/\\]+)[/\\]tn\.yaml$/);
    // Under tsc's noUncheckedIndexedAccess (or strict regex-result
    // typing), m[1] is `string | undefined` even when the match
    // succeeded. Fall back to the project-stream layout for safety.
    if (m?.[1]) return m[1];
    // Project-stream layout: `.tn/<project>/streams/<name>.yaml`
    // (see multi.ts streamLayout). The stream name is the ceremony name.
    const s = yp.match(/[/\\]\.tn[/\\][^/\\]+[/\\]streams[/\\]([^/\\]+)\.ya?ml$/);
    return s?.[1] ?? "default";
  }

  /** True iff this is the default ceremony. */
  get isDefault(): boolean {
    return this.name === "default";
  }

  /** Returns the underlying NodeRuntime config. */
  config(): unknown {
    return this._rt.config;
  }

  /**
   * Spawn a per-DID scoped capability handle over this project.
   *
   * The returned {@link ScopeBuilder} collects the DIDs to scope to;
   * `.spawn()` resolves them against this project's groups and returns a
   * read-only {@link ScopedTn} that opens ONLY the groups those DIDs are
   * recipients of. Pass several DIDs to union their capabilities — a
   * governance tier scoping to `scopeTo(userDid, tierDid)` opens the
   * user's groups plus its own, and nothing else.
   */
  scopeTo(...dids: string[]): ScopeBuilder {
    const cfg = this._rt.config;
    return new ScopeBuilder({ groups: cfg.groups, keystorePath: cfg.keystorePath }, dids);
  }

  /** True iff this ceremony's runtime has an attached Rust/WASM core
   *  servicing the emit path. False before the first emit (wasm attaches
   *  lazily) and after an admin-driven runtime reset. Mirrors Python's
   *  `using_rust`. The read path remains pure-TS today. */
  usingRust(): boolean {
    return this._rt.isWasmActive();
  }

  /**
   * Back up this ceremony to a vault as a pending claim and return a
   * claim URL. Mirrors Python's `tn init` vault flow / `init_upload`.
   *
   * Mints a fresh BEK, exports an AES-256-GCM-encrypted `full_keystore`
   * tnpkg, POSTs it UNAUTHENTICATED to `/api/v1/pending-claims`, and
   * returns `{vaultId, expiresAt, claimUrl, passwordB64}`. The claim URL
   * fragment carries the BEK; the vault never sees it.
   */
  async initUpload(opts: InitUploadOptions): Promise<InitUploadResult> {
    return _initUpload(this._rt, opts);
  }

  /** Flush handlers and (for ephemeral instances) remove the tempdir.
   *
   * Also evicts this instance from the process-level handle registry
   * so a subsequent ``Tn.use(name, opts)`` call mints a fresh
   * runtime rather than returning a stale closed handle.
   */
  async close(opts: { timeoutMs?: number } = {}): Promise<void> {
    await this._rt.closeAsync(opts);
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
   * Split the trailing `(msgOrFields, fieldsIfMessage, opts)` arguments into
   * the merged field dict and the per-emit aad. Supports both call shapes:
   *
   *   - `info(evt, "message", fields?, opts?)`  — opts is the 4th arg
   *   - `info(evt, fields, opts?)`              — opts is the 3rd arg
   *
   * When `msgOrFields` is an object (the fields case) and no explicit 4th
   * `opts` was given, the 3rd argument is treated as `EmitOpts`. This mirrors
   * Python's `tn.info("evt", field=..., aad={...})` where aad rides alongside
   * the fields rather than being a positional.
   */
  private _resolveEmitArgs(
    msgOrFields: string | Record<string, unknown> | undefined,
    fieldsIfMessage: Record<string, unknown> | undefined,
    opts: EmitOpts | undefined,
  ): { fields: Record<string, unknown>; aad: Record<string, unknown> | undefined } {
    let resolvedOpts = opts;
    let resolvedFieldsArg = fieldsIfMessage;
    if (typeof msgOrFields !== "string" && msgOrFields !== undefined && opts === undefined) {
      // Fields-object call: the 3rd argument, if present, is the options bag.
      resolvedOpts = fieldsIfMessage as EmitOpts | undefined;
      resolvedFieldsArg = undefined;
    }
    return {
      fields: this._mergeForEmit(normalizeLogFields(msgOrFields, resolvedFieldsArg)),
      aad: resolvedOpts?.aad,
    };
  }

  /**
   * Severity-less attested event. Always emits regardless of `setLevel()`.
   * Mirrors Python `tn.log(event_type, **fields)`.
   */
  log(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
    opts?: EmitOpts,
  ): EmitReceipt {
    const { fields, aad } = this._resolveEmitArgs(msgOrFields, fieldsIfMessage, opts);
    return this._rt.emit("", eventType, fields, aad);
  }

  debug(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
    opts?: EmitOpts,
  ): EmitReceipt {
    if (10 < _tnLogLevelThreshold) return _nullReceipt();
    const { fields, aad } = this._resolveEmitArgs(msgOrFields, fieldsIfMessage, opts);
    return this._rt.emit("debug", eventType, fields, aad);
  }

  info(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
    opts?: EmitOpts,
  ): EmitReceipt {
    if (20 < _tnLogLevelThreshold) return _nullReceipt();
    const { fields, aad } = this._resolveEmitArgs(msgOrFields, fieldsIfMessage, opts);
    return this._rt.emit("info", eventType, fields, aad);
  }

  warning(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
    opts?: EmitOpts,
  ): EmitReceipt {
    if (30 < _tnLogLevelThreshold) return _nullReceipt();
    const { fields, aad } = this._resolveEmitArgs(msgOrFields, fieldsIfMessage, opts);
    return this._rt.emit("warning", eventType, fields, aad);
  }

  error(
    eventType: string,
    msgOrFields?: string | Record<string, unknown>,
    fieldsIfMessage?: Record<string, unknown>,
    opts?: EmitOpts,
  ): EmitReceipt {
    if (40 < _tnLogLevelThreshold) return _nullReceipt();
    const { fields, aad } = this._resolveEmitArgs(msgOrFields, fieldsIfMessage, opts);
    return this._rt.emit("error", eventType, fields, aad);
  }

  /**
   * Foundational emit. Routes through `_mergeForEmit` so context fields and
   * the per-client `run_id` are auto-injected — same behavior as the level
   * wrappers above.
   */
  emit(level: string, eventType: string, fields: Record<string, unknown>): EmitReceipt {
    return this._rt.emit(level, eventType, this._mergeForEmit(fields));
  }

  /** Async-compatible sibling of {@link emit}. All cipher operations use the
   * same implementation as the synchronous write verbs. */
  async emitAsync(
    level: string,
    eventType: string,
    fields: Record<string, unknown>,
    aad?: Record<string, unknown> | null,
  ): Promise<EmitReceipt> {
    return this._rt.emitAsync(level, eventType, this._mergeForEmit(fields), aad ?? undefined);
  }

  /** Async-compatible `info` (see {@link emitAsync}). */
  infoAsync(
    eventType: string,
    fields: Record<string, unknown> = {},
    aad?: Record<string, unknown> | null,
  ): Promise<EmitReceipt> {
    return this.emitAsync("info", eventType, fields, aad);
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
   * - `verify`       — `true` (default) / `"raise"` (throw
   *                    `VerifyError` on first failure), `"skip"` (drop
   *                    validation failures and emit a
   *                    `tn.read.tampered_row_skipped` admin event), or
   *                    explicit `false` to disable verification.
   * - `raw`          — yield envelope dict instead of `Entry`.
   * - `log`          — alternate log path.
   * - `asRecipient`  — keystore directory to decrypt with (foreign-log mode).
   * - `group`        — group plaintext to surface (with `asRecipient`).
   * - `allRuns`      — default `true`: scan every entry on disk. Pass
   *                    `false` to restrict to this process's current run.
   */
  *read(opts: ReadOptions = {}): IterableIterator<Entry | Record<string, unknown>> {
    // Streams whose profile has no replay surface (e.g. ``telemetry``
    // writes only to stdout) yield an empty iterator rather than going
    // to the reader.
    if (!this._hasReplaySurface()) return;

    const verify = opts.verify ?? true;
    _checkVerifyKwarg(verify);
    const raw = opts.raw ?? false;
    const logPath = opts.log;
    const asRecipient = opts.asRecipient;
    const group = opts.group;
    const allRuns = opts.allRuns ?? true;
    const expectGenesis = opts.expectGenesis ?? false;
    const where = opts.where;
    const selector = opts.selector;
    const filter = opts.filter;
    const rt = this._rt;

    // Choose the source of {envelope, plaintext, valid} triples.
    let triples: Iterable<ReadEntry>;
    let usingRecipient = false;
    if (asRecipient !== undefined || (logPath !== undefined && _isForeignLog(logPath, this.did))) {
      const keystorePath = asRecipient ?? this._rt.config.keystorePath;
      const path = logPath ?? this._rt.config.logPath;
      usingRecipient = true;
      const foreignIter = readAsRecipient(path, keystorePath, {
        ...(group === undefined ? {} : { group }),
        verifySignatures: verify !== false,
        expectGenesis,
        ...(opts.trustedPublisherDids === undefined
          ? {}
          : { trustedPublisherDids: opts.trustedPublisherDids }),
        ...(opts.unsafeAllowUnverifiedPublisher === undefined
          ? {}
          : { unsafeAllowUnverifiedPublisher: opts.unsafeAllowUnverifiedPublisher }),
      });
      triples = (function* () {
        for (const entry of foreignIter) {
          const rEntry: ReadEntry = {
            envelope: entry.envelope,
            plaintext: entry.plaintext,
            valid: {
              signature: entry.valid.signature,
              rowHash: entry.valid.rowHash,
              chain: entry.valid.chain,
            },
          };
          yield rEntry;
        }
      })();
    } else {
      triples = rt.read(logPath, expectGenesis);
    }

    // Iterator wrapper that handles parser-level errors per `verify` policy.
    const safeIter = function* (this: Tn): IterableIterator<ReadEntry> {
      const it = (triples as Iterable<ReadEntry>)[Symbol.iterator]();
      while (true) {
        let next: IteratorResult<ReadEntry>;
        try {
          next = it.next();
        } catch (exc) {
          if (verify === "skip") {
            try {
              this._emitTamperedRowSkipped({ event_type: "<parse-error>" }, [
                `parse: ${(exc as Error).name}: ${(exc as Error).message}`,
              ]);
            } catch {
              // best-effort
            }
            continue;
          }
          if (verify === true || verify === "raise") {
            throw new VerifyError(0, "<parse-error>", [
              `parse: ${(exc as Error).name}: ${(exc as Error).message}`,
            ]);
          }
          throw exc;
        }
        if (next.done) return;
        yield next.value;
      }
    }.call(this);

    for (const r of safeIter) {
      const out = this._finishReadRow(r, usingRecipient, {
        allRuns,
        verify,
        raw,
        where,
        selector,
        filter,
      });
      if (out !== undefined) yield out;
    }
  }

  /** Async-compatible sibling of {@link read}. It has the same cipher support,
   * verification, filtering, and foreign-recipient behavior as `read()`. */
  async *readAsync(opts: ReadOptions = {}): AsyncIterableIterator<Entry | Record<string, unknown>> {
    if (!this._hasReplaySurface()) return;
    const verify = opts.verify ?? true;
    _checkVerifyKwarg(verify);
    const raw = opts.raw ?? false;
    const allRuns = opts.allRuns ?? true;
    const expectGenesis = opts.expectGenesis ?? false;
    const where = opts.where;
    const selector = opts.selector;
    const filter = opts.filter;

    // Foreign-log read (asRecipient, or a log that isn't ours): decrypt with an
    // absorbed reader kit via readAsRecipientAsync (handles btn/hibe/jwe).
    let usingRecipient = false;
    let source: AsyncIterable<ReadEntry>;
    if (
      opts.asRecipient !== undefined ||
      (opts.log !== undefined && _isForeignLog(opts.log, this.did))
    ) {
      usingRecipient = true;
      const keystorePath = opts.asRecipient ?? this._rt.config.keystorePath;
      const path = opts.log ?? this._rt.config.logPath;
      const group = opts.group;
      source = (async function* () {
        for await (const fe of readAsRecipientAsync(path, keystorePath, {
          ...(group === undefined ? {} : { group }),
          verifySignatures: verify !== false,
          expectGenesis,
          ...(opts.trustedPublisherDids === undefined
            ? {}
            : { trustedPublisherDids: opts.trustedPublisherDids }),
          ...(opts.unsafeAllowUnverifiedPublisher === undefined
            ? {}
            : { unsafeAllowUnverifiedPublisher: opts.unsafeAllowUnverifiedPublisher }),
        })) {
          yield {
            envelope: fe.envelope,
            plaintext: fe.plaintext,
            valid: {
              signature: fe.valid.signature,
              rowHash: fe.valid.rowHash,
              chain: fe.valid.chain,
            },
          } as ReadEntry;
        }
      })();
    } else {
      source = this._rt.readAsync(opts.log, expectGenesis);
    }

    for await (const r of source) {
      const out = this._finishReadRow(r, usingRecipient, {
        allRuns,
        verify,
        raw,
        where,
        selector,
        filter,
      });
      if (out !== undefined) yield out;
    }
  }

  // -------------------------------------------------------------------------
  // Sealed objects (portable standalone envelopes)
  // -------------------------------------------------------------------------

  /**
   * Seal `fields` into a portable attested object — a signed,
   * per-group-encrypted standalone envelope returned to the caller
   * instead of appended to the log. Mirrors Python `tn.seal`.
   *
   * Fields route into groups and encrypt exactly as a write verb
   * would; the object is always signed; the ceremony's chain state is
   * never touched. By default one `tn.object.sealed` receipt row is
   * chained through the normal write path (`receipt: false` skips it).
   * Promise-shaped for API compatibility; every cipher uses the same core
   * primitives as the ordinary write/read surfaces.
   */
  async seal(
    objectType: string,
    fields: Record<string, unknown> = {},
    opts: SealOptions = {},
  ): Promise<SealedObject> {
    return sealWithRuntime(this._rt, objectType, fields, opts);
  }

  /**
   * Verify a sealed object and open every group block a held key fits.
   * Mirrors Python `tn.unseal`.
   *
   * Holding no fitting key is not an error — the verified public frame
   * comes back with the blocks left sealed (`Entry.hidden_groups`).
   * Malformed input throws `SealedObjectError`; failed verification
   * (with `verify: true`, the default) throws `VerifyError`. Pass
   * `raw: true` for the `{envelope, plaintext, valid}` triple, and
   * `asRecipient` (+ `group`) to open one kit directory directly.
   */
  async unseal(source: UnsealSource, opts: UnsealOptions = {}): Promise<Entry | SealedTriple> {
    return unsealWithRuntime(this._rt, source, opts);
  }

  /** Run-id filter for local reads: keep only rows from this client's current
   *  run (checks each group body's `run_id`, then the envelope). */
  private _matchesRun(r: ReadEntry, allRuns: boolean): boolean {
    if (allRuns) return true;
    for (const body of Object.values(r.plaintext ?? {})) {
      if (body && typeof body === "object" && "run_id" in body) {
        return (body as Record<string, unknown>)["run_id"] === this._runId;
      }
    }
    const envRid = r.envelope["run_id"];
    return typeof envRid === "string" && envRid === this._runId;
  }

  /** Shared per-row post-processing for `read` / `readAsync`. Everything after a
   *  row is decrypted is synchronous and identical: run-id filter, selector +
   *  filter gate, the verify policy (raise / skip / off), and raw-vs-Entry
   *  shaping. Returns the value to yield, or undefined to skip the row. Throws
   *  VerifyError under `verify: true | "raise"`. */
  private _finishReadRow(
    r: ReadEntry,
    usingRecipient: boolean,
    o: {
      allRuns: boolean;
      verify: ReadOptions["verify"];
      raw: boolean;
      where: ReadOptions["where"];
      selector: ReadOptions["selector"];
      filter: ReadOptions["filter"];
    },
  ): Entry | Record<string, unknown> | undefined {
    // run_id filter — only on local reads. Recipient-mode reads cross
    // publishers, so filtering by your local run_id makes no sense.
    if (!usingRecipient && !this._matchesRun(r, o.allRuns)) return undefined;
    // Authoritative selector + filter gate on the envelope's public fields,
    // applied before verify so a rejected row never surfaces (parity with
    // Python read.py `_passes_selector_filter`).
    if (!_passesSelectorFilter(r.envelope, o.selector, o.filter)) return undefined;

    const v = r.valid;
    const allValid = Boolean(v.signature) && Boolean(v.rowHash) && Boolean(v.chain);
    if (!allValid && o.verify !== false) {
      const reasons: string[] = [];
      if (!v.signature) reasons.push("signature");
      if (!v.rowHash) reasons.push("row_hash");
      if (!v.chain) reasons.push("chain");
      if (o.verify === true || o.verify === "raise") {
        throw new VerifyError(
          Number(r.envelope["sequence"] ?? 0),
          String(r.envelope["event_type"] ?? ""),
          reasons,
        );
      }
      if (o.verify === "skip") {
        // Avoid looping our own tampered-row event back through.
        if (String(r.envelope["event_type"] ?? "") === "tn.read.tampered_row_skipped") {
          return undefined;
        }
        try {
          this._emitTamperedRowSkipped(r.envelope, reasons);
        } catch {
          // best-effort
        }
        return undefined;
      }
    }

    if (o.raw) {
      if (o.where && !o.where(r.envelope)) return undefined;
      return r.envelope;
    }
    let entry: Entry;
    try {
      entry = Entry.fromRaw(r);
    } catch {
      return undefined; // malformed entry, skip rather than abort
    }
    if (o.where && !o.where(entry)) return undefined;
    return entry;
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
    const selector = opts.selector;
    const filter = opts.filter;

    const flatOpts: _WatchFlatOptions = {};
    if (opts.since !== undefined) flatOpts.since = opts.since;
    if (opts.log !== undefined) flatOpts.logPath = opts.log;
    if (opts.pollIntervalMs !== undefined) flatOpts.pollIntervalMs = opts.pollIntervalMs;
    // _watchFlat does its own sig check when `verify` is truthy. We
    // currently best-effort verify on watch (Python parity — there's no
    // raw-triples access post-flatten on this path).
    flatOpts.verify = verify !== false;

    for await (const flat of _watchFlat(this._rt, flatOpts)) {
      // Selector + filter gate on the flattened entry's public fields (parity
      // with Python watch, which re-applies `_passes_selector_filter`).
      if (!_passesSelectorFilter(flat, selector, filter)) continue;
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
  private _emitTamperedRowSkipped(envelope: Record<string, unknown>, reasons: string[]): void {
    this._rt.emit(
      "warning",
      "tn.read.tampered_row_skipped",
      this._mergeForEmit({
        envelope_event_id: envelope["event_id"] ?? null,
        envelope_device_identity: envelope["device_identity"] ?? null,
        envelope_event_type: envelope["event_type"] ?? null,
        envelope_sequence: envelope["sequence"] ?? null,
        invalid_reasons: [...new Set(reasons)].sort(),
      }),
    );
  }

  /**
   * Look up the most-recent `tn.agents.policy_published` content_hash in
   * the local logs. Walks every log file the ceremony might write to
   * (main log + the entire protocol_events_location tree), mirroring
   * Python's read_all() semantics. Walking only the main log + a
   * `*.admin.ndjson` sibling missed events routed to a templated PEL
   * (e.g. `./.tn/admin/{event_type}.ndjson`), causing the de-dupe to
   * mis-fire under wasm-routed emit.
   */
  private _lastPolicyPublishedHash(): string | null {
    let lastTs = "";
    let lastHash: string | null = null;
    for (const path of iterLogFiles(this._rt.config)) {
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
