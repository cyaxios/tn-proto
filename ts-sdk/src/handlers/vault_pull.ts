// `vault.pull` handler — fetch admin-log snapshots from a TN vault.
//
// Mirrors `python/tn/handlers/vault_pull.py`. On a schedule, GETs new
// `.tnpkg` files from the vault inbox addressed to this DID and calls
// the host-supplied `absorber.absorb(bytes)` for each. Cursor
// persistence at `<cursorDir>/vault_pull.cursor.json` mirrors Python.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join, dirname } from "node:path";

import { getInboxCursor, setInboxCursor } from "../sync_state.js";
import { BaseTNHandler, type FilterSpec } from "./base.js";

/** One incoming snapshot pointer. */
export interface VaultInboxItem {
  path: string;
  head_row_hash?: string | null;
  received_at?: string | null;
  /**
   * Server-supplied opaque, order-preserving cursor (per spec §4.1).
   * The handler advances its `?since=...` cursor by this value when present.
   * Falls back to `received_at` for vaults that don't emit `since_marker`.
   */
  since_marker?: string | null;
}

/** Server-shape returned by `list_incoming`. */
export interface VaultInboxListing {
  items: VaultInboxItem[];
}

export interface VaultInboxClient {
  listIncoming(did: string, since?: string | null): Promise<VaultInboxItem[]>;
  download(path: string): Promise<Uint8Array>;
}

export interface VaultPullAbsorbReceipt {
  rejectedReason?: string | null;
}

export interface VaultPullAbsorber {
  absorb(bytes: Uint8Array): VaultPullAbsorbReceipt;
}

export type OnAbsorbError = "log" | "raise";

export interface VaultPullHandlerOptions {
  endpoint: string;
  projectId: string;
  did: string;
  client: VaultInboxClient;
  absorber: VaultPullAbsorber;
  /** Where the legacy cursor file lives. Default `<cwd>/.tn/admin/`. */
  cursorDir?: string;
  /**
   * Path to the ceremony's tn.yaml. When supplied, the handler also
   * reads/writes `inbox_cursor` in `<yamlDir>/.tn/sync/state.json`
   * (the unified sync state, mirroring Python per spec §4.9 + §10
   * item 5). Reads prefer the unified state; writes go to BOTH the
   * unified state and the legacy `vault_pull.cursor.json` for
   * backward compat. Without yamlPath, the handler keeps using the
   * legacy file only (legacy behavior).
   */
  yamlPath?: string;
  pollIntervalMs?: number;
  onAbsorbError?: OnAbsorbError;
  filter?: FilterSpec;
  /** Start the scheduler immediately. Tests pass false. */
  autostart?: boolean;
}

const CURSOR_FILE = "vault_pull.cursor.json";

/** Poll a vault inbox + absorb new snapshots. */
export class VaultPullHandler extends BaseTNHandler {
  private readonly endpoint: string;
  /** Project enrolment id — kept on the handler for parity with Python / Rust. */
  readonly projectId: string;
  private readonly did: string;
  private readonly client: VaultInboxClient;
  private readonly absorber: VaultPullAbsorber;
  private readonly cursorPath: string;
  private readonly yamlPath: string | null;
  private readonly pollIntervalMs: number;
  private readonly onAbsorbError: OnAbsorbError;
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private closed = false;

  constructor(name: string, opts: VaultPullHandlerOptions) {
    super(name, opts.filter);
    this.endpoint = opts.endpoint.replace(/\/$/, "");
    this.projectId = opts.projectId;
    this.did = opts.did;
    this.client = opts.client;
    this.absorber = opts.absorber;
    const cursorDir = opts.cursorDir ?? join(process.cwd(), ".tn", "admin");
    this.cursorPath = join(cursorDir, CURSOR_FILE);
    this.yamlPath = opts.yamlPath ?? null;
    this.pollIntervalMs = opts.pollIntervalMs ?? 60_000;
    this.onAbsorbError = opts.onAbsorbError ?? "log";
    if (opts.autostart !== false) this.start();
  }

  override accepts(_envelope: Record<string, unknown>): boolean {
    return false;
  }

  emit(_envelope: Record<string, unknown>, _rawLine: string): void {
    // No-op: all work happens on the scheduler tick.
  }

  override close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  get vaultEndpoint(): string {
    return this.endpoint;
  }

  get cursorFilePath(): string {
    return this.cursorPath;
  }

  /** Start the polling timer + run an immediate tick. Idempotent. */
  start(): void {
    if (this.timer !== null || this.closed) return;
    void this.maybeTick();
    this.timer = setInterval(() => void this.maybeTick(), this.pollIntervalMs);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }

  private async maybeTick(): Promise<void> {
    if (this.inFlight || this.closed) return;
    this.inFlight = true;
    try {
      await this.tickOnce();
    } catch (e) {
      if (this.onAbsorbError === "raise") throw e;
      console.warn(`[${this.name}] vault.pull tick failed:`, e);
    } finally {
      this.inFlight = false;
    }
  }

  /** One fetch + absorb cycle. Returns the count of newly absorbed items. */
  async tickOnce(): Promise<number> {
    const cursor = this.loadCursor();
    let items: VaultInboxItem[];
    try {
      items = await this.client.listIncoming(this.did, cursor);
    } catch (e) {
      if (this.onAbsorbError === "raise") throw e;
      console.warn(`[${this.name}] vault.pull list_incoming failed:`, e);
      return 0;
    }
    if (items.length === 0) return 0;
    let absorbed = 0;
    let highest = cursor;
    for (const item of items) {
      let blob: Uint8Array;
      try {
        blob = await this.client.download(item.path);
      } catch (e) {
        if (this.onAbsorbError === "raise") throw e;
        console.warn(`[${this.name}] vault.pull download ${item.path} failed:`, e);
        // Stop advancing — retry on the next tick.
        return absorbed;
      }
      let receipt: VaultPullAbsorbReceipt;
      try {
        receipt = this.absorber.absorb(blob);
      } catch (e) {
        if (this.onAbsorbError === "raise") throw e;
        console.warn(`[${this.name}] vault.pull absorb crashed for ${item.path}:`, e);
        continue;
      }
      if (receipt.rejectedReason && receipt.rejectedReason.length > 0) {
        console.warn(
          `[${this.name}] vault.pull absorb rejected ${item.path}: ${receipt.rejectedReason}`,
        );
        continue;
      }
      absorbed += 1;
      // Per spec §4.1: prefer server-supplied since_marker (opaque,
      // order-preserving). Fall back to received_at for backward compat
      // with vaults that don't emit since_marker yet.
      const cursorValue = item.since_marker ?? item.received_at ?? null;
      if (cursorValue !== null) {
        if (highest === null || cursorValue > highest) highest = cursorValue;
      }
    }
    if (highest !== cursor && highest !== null) {
      this.saveCursor(highest);
    }
    return absorbed;
  }

  private loadCursor(): string | null {
    // Prefer the unified sync state file (§4.9 + §10 item 5 part 2)
    // when yamlPath is configured. Falls back to the legacy cursor
    // file for backward compat / tests.
    if (this.yamlPath !== null) {
      const fromUnified = getInboxCursor(this.yamlPath);
      if (fromUnified !== null) return fromUnified;
    }
    if (!existsSync(this.cursorPath)) return null;
    try {
      const doc = JSON.parse(readFileSync(this.cursorPath, "utf8")) as {
        last_seen?: string;
      };
      return doc.last_seen ?? null;
    } catch {
      // Corrupt cursor — start fresh, mirroring Python.
      console.warn(`[${this.name}] vault.pull: cursor at ${this.cursorPath} is corrupt; resetting`);
      return null;
    }
  }

  private saveCursor(lastSeen: string): void {
    // Write to BOTH the unified sync state (canonical going forward
    // when yamlPath is configured) AND the legacy cursor file (so any
    // tooling reading vault_pull.cursor.json directly keeps working
    // during the transition). Mirrors the Python pull-side behavior.
    if (this.yamlPath !== null) {
      setInboxCursor(this.yamlPath, lastSeen);
    }
    const dir = dirname(this.cursorPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const tmp = `${this.cursorPath}.tmp`;
    writeFileSync(tmp, JSON.stringify({ last_seen: lastSeen }, null, 2), "utf8");
    renameSync(tmp, this.cursorPath);
  }
}

/** Build a VaultInboxClient backed by Node `fetch`. */
export function makeFetchVaultInboxClient(opts: {
  baseUrl: string;
  token?: string;
  fetcher?: typeof fetch;
}): VaultInboxClient {
  const base = opts.baseUrl.replace(/\/$/, "");
  const fetchImpl: typeof fetch = opts.fetcher ?? fetch;
  const headers: Record<string, string> = {};
  if (opts.token !== undefined) headers["Authorization"] = `Bearer ${opts.token}`;
  return {
    async listIncoming(did: string, since?: string | null): Promise<VaultInboxItem[]> {
      const url =
        since !== null && since !== undefined
          ? `${base}/api/v1/inbox/${did}/incoming?since=${encodeURIComponent(since)}`
          : `${base}/api/v1/inbox/${did}/incoming`;
      const resp = await fetchImpl(url, { method: "GET", headers });
      if (!resp.ok) throw new Error(`vault.pull: GET ${url} -> HTTP ${resp.status}`);
      const doc = (await resp.json()) as VaultInboxListing;
      return doc.items ?? [];
    },
    async download(path: string): Promise<Uint8Array> {
      const url = `${base}${path}`;
      const resp = await fetchImpl(url, { method: "GET", headers });
      if (!resp.ok) throw new Error(`vault.pull: GET ${url} -> HTTP ${resp.status}`);
      const buf = await resp.arrayBuffer();
      return new Uint8Array(buf);
    },
  };
}

/** Yaml spec shape. */
export interface VaultPullSpec {
  kind: "vault.pull";
  name?: string;
  endpoint: string;
  project_id: string;
  poll_interval?: string | number;
  on_absorb_error?: OnAbsorbError;
  filter?: FilterSpec;
}
