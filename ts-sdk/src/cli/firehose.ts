// `tn firehose stats|list|get` — gated firehose-worker diagnostic probes.
//
// TypeScript parity port of Python's `cmd_firehose_stats`,
// `cmd_firehose_list`, `cmd_firehose_get` (python/tn/cli.py) plus their
// `p_stats` / `p_list` / `p_get` parsers and the shared helpers
// `_firehose_base`, `_firehose_token`, `_firehose_headers`, `_die`.
//
//     tn firehose stats <tenant>
//     tn firehose list  <tenant> [--did <did>]
//     tn firehose get   <tenant> <ceremony> <name> [--did <did>] [--out <path>]
//
// Like Python these are *gated* diagnostics: the verb group is only wired
// into the parser when `TN_FIREHOSE_ENABLED=1` (mirrors Python's
// `_firehose_enabled()` / `_register_firehose_subcommands`). Each subcommand
// does a single HTTP GET against the firehose worker carrying an optional
// `Authorization: Bearer <TN_FIREHOSE_TOKEN>` header. `stats` is anonymous
// (token optional); `list` / `get` require the token. stdout, the
// JSON-vs-raw fallback, byte download, and exit codes mirror Python exactly.
//
// The TS SDK's existing firehose surface (src/handlers/firehose.ts) is the
// streaming PRODUCER (WS frames out); it has no inbox-GET client, so these
// reader probes are built fresh to match Python's urllib/httpx GETs — the
// one genuine gap noted in the port.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { Buffer } from "node:buffer";

/** Minimal structural type for the `fetch` Response we consume. */
export interface FirehoseFetchResponse {
  readonly status: number;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/** Minimal `fetch` signature (injectable for tests; defaults to global). */
export type FirehoseFetch = (
  url: string,
  init: { method: string; headers: Record<string, string>; signal?: AbortSignal },
) => Promise<FirehoseFetchResponse>;

/** Injectable side-effects so the handlers run network-free under test. */
export interface FirehoseDeps {
  /** Environment lookup (default: `process.env`). */
  env: Record<string, string | undefined>;
  /** HTTP GET impl (default: global `fetch`). */
  fetch: FirehoseFetch;
  /** stdout sink for JSON / text bodies (default: `process.stdout.write`). */
  stdout: (s: string) => void;
  /** stderr sink for `_die` (default: `process.stderr.write`). */
  stderr: (s: string) => void;
  /** Raw-bytes stdout sink for `get` without `--out` (default: stdout buffer). */
  stdoutBytes: (b: Uint8Array) => void;
  /** Write `data` to `path` (parents created); default: node fs. */
  writeFile: (path: string, data: Uint8Array) => void;
}

/**
 * Raised by `_die` to unwind a failed probe. Carries the exit code Python
 * would have passed to `sys.exit`. Callers (the CLI dispatcher / tests)
 * inspect `.code` instead of the process being torn down mid-call.
 *
 * @public
 */
export class FirehoseExit extends Error {
  readonly code: number;
  constructor(message: string, code: number) {
    super(message);
    this.name = "FirehoseExit";
    this.code = code;
  }
}

function defaultDeps(): FirehoseDeps {
  return {
    env: process.env,
    fetch: globalThis.fetch as unknown as FirehoseFetch,
    stdout: (s) => void process.stdout.write(s),
    stderr: (s) => void process.stderr.write(s),
    stdoutBytes: (b) => void process.stdout.write(Buffer.from(b)),
    writeFile: (path, data) => {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
    },
  };
}

/** Mirror of Python `_die`: print `tn: error: <msg>` to stderr, exit `code`. */
function die(deps: FirehoseDeps, msg: string, code = 1): never {
  deps.stderr(`tn: error: ${msg}\n`);
  throw new FirehoseExit(msg, code);
}

/** Mirror of Python `_firehose_base`: `TN_FIREHOSE_URL` (trailing-slash trimmed). */
function firehoseBase(deps: FirehoseDeps): string {
  const base = (deps.env.TN_FIREHOSE_URL || "").replace(/\/+$/, "");
  if (!base) {
    die(
      deps,
      "TN_FIREHOSE_URL is not set. Point it at the firehose-worker " +
        "base URL (e.g. https://firehose-worker.<account>.workers.dev).",
    );
  }
  return base;
}

/** Mirror of Python `_firehose_token`: `TN_FIREHOSE_TOKEN` or null. */
function firehoseToken(deps: FirehoseDeps): string | null {
  return deps.env.TN_FIREHOSE_TOKEN || null;
}

/**
 * Mirror of Python `_firehose_headers`: always `accept: application/json`;
 * add bearer when a token is present; `_die` when `require_token` and none.
 */
function firehoseHeaders(deps: FirehoseDeps, requireToken: boolean): Record<string, string> {
  const headers: Record<string, string> = { accept: "application/json" };
  const token = firehoseToken(deps);
  if (token) {
    headers.authorization = `Bearer ${token}`;
  } else if (requireToken) {
    die(
      deps,
      "TN_FIREHOSE_TOKEN is required for inbox routes. Mint one via " +
        "the worker's /api/v1/auth/challenge + /api/v1/auth/verify " +
        "handshake.",
    );
  }
  return headers;
}

/** One GET with a timeout; maps fetch rejections onto Python's HTTPError `_die`. */
async function fetchGet(
  deps: FirehoseDeps,
  label: string,
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<FirehoseFetchResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await deps.fetch(url, { method: "GET", headers, signal: controller.signal });
  } catch (exc) {
    return die(deps, `firehose ${label} request failed: ${exc instanceof Error ? exc.message : String(exc)}`);
  } finally {
    clearTimeout(timer);
  }
}

/** Options for `tn firehose stats` (positional `tenant`). */
export interface FirehoseStatsOptions {
  tenant: string;
}

/** Options for `tn firehose list` (positional `tenant`, `--did`). */
export interface FirehoseListOptions {
  tenant: string;
  did?: string | null;
}

/** Options for `tn firehose get` (positionals + `--did` / `--out`). */
export interface FirehoseGetOptions {
  tenant: string;
  ceremony: string;
  name: string;
  did?: string | null;
  out?: string | null;
}

/**
 * `tn firehose stats <tenant>` — GET `/stats/<tenant>` from the worker.
 * Token is optional. Pretty-prints JSON (sorted keys, indent 2) or falls
 * back to the raw text body. Mirrors Python `cmd_firehose_stats`.
 */
export async function firehoseStatsCmd(
  opts: FirehoseStatsOptions,
  deps: Partial<FirehoseDeps> = {},
): Promise<number> {
  const d = { ...defaultDeps(), ...deps };
  const base = firehoseBase(d);
  const url = `${base}/stats/${opts.tenant}`;
  const resp = await fetchGet(d, "stats", url, firehoseHeaders(d, false), 10_000);
  if (resp.status !== 200) {
    const body = await resp.text();
    die(d, `firehose stats returned ${resp.status}: ${body.slice(0, 200)}`, 2);
  }
  const text = await resp.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    d.stdout(`${text}\n`);
    return 0;
  }
  d.stdout(`${jsonDumps(body)}\n`);
  return 0;
}

/**
 * `tn firehose list <tenant> [--did]` — GET the worker inbox
 * `/api/v1/inbox/<did>/incoming`. Requires the token. Mirrors Python
 * `cmd_firehose_list`.
 */
export async function firehoseListCmd(
  opts: FirehoseListOptions,
  deps: Partial<FirehoseDeps> = {},
): Promise<number> {
  const d = { ...defaultDeps(), ...deps };
  const base = firehoseBase(d);
  const did = opts.did || opts.tenant;
  const url = `${base}/api/v1/inbox/${did}/incoming`;
  const resp = await fetchGet(d, "list", url, firehoseHeaders(d, true), 15_000);
  if (resp.status !== 200) {
    const body = await resp.text();
    die(d, `firehose list returned ${resp.status}: ${body.slice(0, 200)}`, 2);
  }
  const text = await resp.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    d.stdout(`${text}\n`);
    return 0;
  }
  d.stdout(`${jsonDumps(body)}\n`);
  return 0;
}

/**
 * `tn firehose get <tenant> <ceremony> <name> [--did] [--out]` — download a
 * single tnpkg snapshot from `/api/v1/inbox/<did>/snapshots/<ceremony>/<name>`.
 * Requires the token. Writes bytes to `--out` (parents created) or stdout.
 * Mirrors Python `cmd_firehose_get`.
 */
export async function firehoseGetCmd(
  opts: FirehoseGetOptions,
  deps: Partial<FirehoseDeps> = {},
): Promise<number> {
  const d = { ...defaultDeps(), ...deps };
  const base = firehoseBase(d);
  const did = opts.did || opts.tenant;
  const url = `${base}/api/v1/inbox/${did}/snapshots/${opts.ceremony}/${opts.name}`;
  const resp = await fetchGet(d, "get", url, firehoseHeaders(d, true), 60_000);
  if (resp.status !== 200) {
    const body = await resp.text();
    die(d, `firehose get returned ${resp.status}: ${body.slice(0, 200)}`, 2);
  }
  const data = new Uint8Array(await resp.arrayBuffer());
  if (opts.out) {
    d.writeFile(opts.out, data);
    d.stdout(`wrote ${data.length} bytes to ${opts.out}\n`);
  } else {
    d.stdoutBytes(data);
  }
  return 0;
}

/**
 * Single `firehose <sub>` dispatcher — convenience wrapper mirroring the
 * `fhverb` subparser. Unknown subcommands `_die` like an argparse error.
 */
export async function firehoseCmd(
  sub: "stats" | "list" | "get",
  opts: FirehoseStatsOptions & Partial<FirehoseListOptions & FirehoseGetOptions>,
  deps: Partial<FirehoseDeps> = {},
): Promise<number> {
  switch (sub) {
    case "stats":
      return firehoseStatsCmd(opts, deps);
    case "list":
      return firehoseListCmd(opts, deps);
    case "get":
      return firehoseGetCmd(opts as FirehoseGetOptions, deps);
    default: {
      const d = { ...defaultDeps(), ...deps };
      return die(d, `unknown firehose subcommand: ${String(sub)}`, 2);
    }
  }
}

/**
 * Mirror of Python's `json.dumps(body, indent=2, sort_keys=True)`: 2-space
 * indent, keys sorted recursively. JS `JSON.stringify` does not sort keys,
 * so we sort via a replacer-built ordered structure.
 */
function jsonDumps(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 2);
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

/** True when the gated firehose verb group is enabled. Mirrors Python `_firehose_enabled`. */
export function firehoseEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env.TN_FIREHOSE_ENABLED === "1";
}
