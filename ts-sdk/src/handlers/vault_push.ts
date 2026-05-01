// `vault.push` handler — POST `.tnpkg` admin snapshots to a TN vault.
//
// Mirrors `python/tn/handlers/vault_push.py`. The HTTP transport is
// abstracted via [`VaultPostClient`] so tests can capture POSTs without
// speaking real HTTP. The default client is [`makeFetchVaultPostClient`]
// which uses Node 20+'s built-in `fetch` and a static bearer token.
//
// On schedule (default) or on each accepted emit, build a snapshot via
// the host-supplied builder, then POST to:
//
//     {endpoint}/api/v1/inbox/{from_did}/snapshots/{ceremony_id}/{ts}.tnpkg
//
// Idempotency: re-shipping the same `head_row_hash` is suppressed.

import { existsSync, mkdirSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";

import { getLastPushedAdminHead, setLastPushedAdminHead } from "../sync_state.js";
import { BaseTNHandler, type FilterSpec } from "./base.js";
import { type SnapshotBuilder } from "./fs_drop.js";

/** Trigger mode. */
export type VaultPushTrigger = "on_emit" | "on_schedule";

/** Query params travel as a string-keyed bag. */
export type QueryParams = Record<string, string>;

/** HTTP transport surface. */
export interface VaultPostClient {
  /** POST one snapshot. The implementation prefixes the vault base URL. */
  postSnapshot(path: string, query: QueryParams, body: Uint8Array): Promise<void>;
}

export interface VaultPushHandlerOptions {
  endpoint: string;
  projectId: string;
  builder: SnapshotBuilder;
  /** HTTP client. Default: NullClient that errors on every call. */
  client?: VaultPostClient;
  /** Output directory for staged snapshots. Default: `<cwd>/.tn/admin/outbox`. */
  outboxDir?: string;
  /**
   * Path to the ceremony's tn.yaml. When supplied, the handler
   * persists `lastShippedHead` to `<yamlDir>/.tn/sync/state.json`
   * so process restart picks up where it left off (mirrors Python
   * `tn.sync_state` per spec §4.9 / §10 item 5). Without it, the
   * handler keeps in-memory state only (legacy behavior).
   */
  yamlPath?: string;
  trigger?: VaultPushTrigger;
  pollIntervalMs?: number;
  scope?: string;
  filter?: FilterSpec;
  /** Start the scheduler immediately. Tests pass false. */
  autostart?: boolean;
}

/** POST admin-log snapshots to a vault inbox. */
export class VaultPushHandler extends BaseTNHandler {
  private readonly endpoint: string;
  // projectId is not used in the URL path today (the vault scopes by DID),
  // but we keep it on the handler so the registry round-trip stays
  // lossless and downstream readers / logs can surface it.
  readonly projectId: string;
  private readonly builder: SnapshotBuilder;
  private readonly client: VaultPostClient;
  private readonly outboxDir: string;
  private readonly yamlPath: string | null;
  private readonly trigger: VaultPushTrigger;
  private readonly pollIntervalMs: number;
  private readonly scope: string;
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private lastShippedHead: string | null = null;
  private lastShippedHeadLoaded = false;
  private closed = false;

  constructor(name: string, opts: VaultPushHandlerOptions) {
    super(name, opts.filter);
    this.endpoint = opts.endpoint.replace(/\/$/, "");
    this.projectId = opts.projectId;
    this.builder = opts.builder;
    this.client = opts.client ?? new NullVaultPostClient();
    this.outboxDir = opts.outboxDir ?? join(process.cwd(), ".tn", "admin", "outbox");
    this.yamlPath = opts.yamlPath ?? null;
    this.trigger = opts.trigger ?? "on_schedule";
    this.pollIntervalMs = opts.pollIntervalMs ?? 60_000;
    this.scope = opts.scope ?? "admin";
    if (opts.autostart !== false && this.trigger === "on_schedule") this.startScheduler();
  }

  override accepts(envelope: Record<string, unknown>): boolean {
    if (!super.accepts(envelope)) return false;
    const et = String(envelope["event_type"] ?? "");
    return et.startsWith("tn.");
  }

  emit(_envelope: Record<string, unknown>, _rawLine: string): void {
    if (this.trigger !== "on_emit") return;
    void this.pushSnapshot().catch((e) => {
      console.warn(`[${this.name}] vault.push on_emit failed:`, e);
    });
  }

  override close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Endpoint accessor (for tests / logging). */
  get vaultEndpoint(): string {
    return this.endpoint;
  }

  /** Start the on-schedule polling timer. Idempotent. */
  startScheduler(): void {
    if (this.timer !== null || this.closed) return;
    this.timer = setInterval(() => {
      if (this.inFlight) return;
      this.inFlight = true;
      void this.pushSnapshot()
        .catch((e) => {
          console.warn(`[${this.name}] vault.push tick failed:`, e);
        })
        .finally(() => {
          this.inFlight = false;
        });
    }, this.pollIntervalMs);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }

  /** Build, sign, and POST a snapshot. Returns true when something shipped. */
  async pushSnapshot(): Promise<boolean> {
    if (!existsSync(this.outboxDir)) mkdirSync(this.outboxDir, { recursive: true });
    // Lazy-load persisted lastShippedHead on first push so process
    // restart doesn't re-ship the same snapshot. Only when yamlPath
    // was supplied; otherwise stay in-memory-only (legacy behavior).
    if (this.yamlPath !== null && !this.lastShippedHeadLoaded) {
      const persisted = getLastPushedAdminHead(this.yamlPath);
      if (persisted !== null && this.lastShippedHead === null) {
        this.lastShippedHead = persisted;
      }
      this.lastShippedHeadLoaded = true;
    }
    const ts = nowStampMicro();
    const outPath = join(this.outboxDir, `snapshot_${ts}.tnpkg`);
    const { manifest } = this.builder.buildSnapshot(outPath, this.scope);
    const head = manifest.headRowHash ?? null;
    if (head !== null && this.lastShippedHead === head) {
      try {
        unlinkSync(outPath);
      } catch {
        // best-effort
      }
      return false;
    }
    const bytes = readFileSync(outPath);
    const urlPath =
      `/api/v1/inbox/${manifest.fromDid}/snapshots/${manifest.ceremonyId}/${ts}.tnpkg`;
    const query: QueryParams = {};
    if (head !== null) query["head_row_hash"] = head;
    await this.client.postSnapshot(urlPath, query, bytes);
    this.lastShippedHead = head;
    // Persist so process restart skips re-shipping. Best-effort;
    // setLastPushedAdminHead logs and swallows write errors.
    if (this.yamlPath !== null && head !== null) {
      setLastPushedAdminHead(this.yamlPath, head);
    }
    return true;
  }
}

/** Default no-op client; errors on every call. Hosts must inject a real one. */
export class NullVaultPostClient implements VaultPostClient {
  async postSnapshot(_path: string, _query: QueryParams, _body: Uint8Array): Promise<void> {
    throw new Error(
      "vault.push: no HTTP client wired (NullVaultPostClient). " +
        "Pass `client: makeFetchVaultPostClient({...})` in handler options.",
    );
  }
}

/** Build a VaultPostClient backed by Node's built-in `fetch`. */
export function makeFetchVaultPostClient(opts: {
  baseUrl: string;
  token?: string;
  /** Optional `fetch` override (tests). */
  fetcher?: typeof fetch;
}): VaultPostClient {
  const base = opts.baseUrl.replace(/\/$/, "");
  const fetchImpl: typeof fetch = opts.fetcher ?? fetch;
  return {
    async postSnapshot(path: string, query: QueryParams, body: Uint8Array) {
      const qs = new URLSearchParams(query).toString();
      const url = qs.length > 0 ? `${base}${path}?${qs}` : `${base}${path}`;
      const headers: Record<string, string> = {
        "Content-Type": "application/octet-stream",
      };
      if (opts.token !== undefined) headers["Authorization"] = `Bearer ${opts.token}`;
      const resp = await fetchImpl(url, {
        method: "POST",
        body,
        headers,
      });
      if (!resp.ok) {
        throw new Error(`vault.push: POST ${url} -> HTTP ${resp.status}`);
      }
    },
  };
}

function nowStampMicro(): string {
  const d = new Date();
  const pad = (n: number, w: number) => String(n).padStart(w, "0");
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1, 2)}${pad(d.getUTCDate(), 2)}` +
    `T${pad(d.getUTCHours(), 2)}${pad(d.getUTCMinutes(), 2)}${pad(d.getUTCSeconds(), 2)}` +
    `${pad(d.getUTCMilliseconds(), 3)}000Z`
  );
}

/** Yaml spec shape. */
export interface VaultPushSpec {
  kind: "vault.push";
  name?: string;
  endpoint: string;
  project_id: string;
  trigger?: VaultPushTrigger;
  poll_interval?: string | number;
  scope?: string;
  filter?: FilterSpec;
}
