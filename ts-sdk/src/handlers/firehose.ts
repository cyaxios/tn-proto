// TN firehose handler: encrypted log streaming to the TN vault.
//
// Port of python/tn/handlers/firehose.py. Streams each accepted envelope as
// an AES-256-GCM-encrypted binary frame over a WebSocket to the vault's
// per-project firehose stream (`wss://<vault>/firehose/<project_id>`), which
// forwards to the CF firehose Worker. Zero-knowledge: the vault/Worker only
// ever see ciphertext.
//
// Scaffold status (mirrors Python): the BEK is a deterministic *test stub*
// (`_stub_bek`, "do-not-use-in-prod") shared with the Python handler so
// frames are mutually decryptable; real keystore-BEK lookup by `key_id`
// lands later. The frame format is final and byte-identical to
// Python: `nonce(12) || AES-256-GCM(raw_line, aad)`, aad =
// `"<project_id>|<key_id|'stub'>|<event_type>"`.
//
// Like the TS `vault.push` handler (and unlike Python's AsyncHandler), this
// follows the lighter TS pattern: no DurableOutbox/worker. Sends are
// best-effort fire-and-forget on the caller's emit; a dropped connection is
// reopened on the next frame. Durable retry is a documented TS-vs-Python
// divergence tracked with the rest of the async-handler subsystem.

import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";

import { AsyncTNHandler, type FilterSpec } from "./base.js";

const _PROJECT_ID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const _KEY_ID_RE = /^fhk_[A-Za-z2-7]+$/;

/**
 * Deterministic test-stub BEK. Mirrors
 * python/tn/handlers/firehose.py::_stub_bek byte-for-byte so a TS-encrypted
 * frame decrypts under the Python handler's key and vice versa. NOT a real
 * key - the real path swaps this for a keystore lookup by `key_id`.
 *
 * @public
 */
export function stubBek(projectId: string, keyId: string | null): Uint8Array {
  const seed = `${projectId}:${keyId ?? "stub-default"}`;
  return new Uint8Array(
    createHash("sha256")
      .update(Buffer.concat([Buffer.from("phase-a-stub-bek-do-not-use-in-prod:"), Buffer.from(seed)]))
      .digest(),
  );
}

/** `https://host` + project -> `wss://host/firehose/<project>`. Mirrors Python `_ws_url`. */
export function firehoseWsUrl(endpoint: string, projectId: string): string {
  const u = new URL(endpoint);
  const scheme = u.protocol === "https:" ? "wss:" : "ws:";
  const basePath = u.pathname.replace(/\/+$/, "");
  return `${scheme}//${u.host}${basePath}/firehose/${projectId}`;
}

/**
 * Build one firehose wire frame: `nonce(12) || AES-256-GCM(rawLine, aad)`.
 * AAD = `"<projectId>|<keyId|'stub'>|<eventType>"`. Byte-identical to
 * Python's `_publish`. `nonce` is injectable for deterministic tests; omit
 * for a fresh random nonce.
 *
 * @public
 */
export function encryptFirehoseFrame(
  bek: Uint8Array,
  projectId: string,
  keyId: string | null,
  eventType: string,
  rawLine: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  if (bek.length !== 32) throw new Error(`firehose frame: bek must be 32 bytes, got ${bek.length}`);
  const iv = nonce ?? new Uint8Array(randomBytes(12));
  const aad = Buffer.from(`${projectId}|${keyId ?? "stub"}|${eventType}`, "utf-8");
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(bek), Buffer.from(iv));
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(Buffer.from(rawLine)), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Wire: nonce || ciphertext || tag (AES-GCM tag appended, matching Python's
  // AESGCM.encrypt which returns ciphertext+tag).
  return Uint8Array.from(Buffer.concat([Buffer.from(iv), ct, tag]));
}

export interface FirehoseHandlerOptions {
  endpoint: string;
  projectId: string;
  keyId?: string | null;
  filter?: FilterSpec;
  /** Durable-outbox directory. Frames are enqueued here and delivered with
   *  at-least-once retry by the worker. Required for durability. */
  outboxDir: string;
  maxRetries?: number;
  backoffInitialMs?: number;
  backoffMaxMs?: number;
}

/** Minimal structural type for the WebSocket we send binary frames on. */
interface WsLike {
  send(data: Uint8Array): void;
  close(): void;
  readyState: number;
  addEventListener?(type: string, cb: (...a: unknown[]) => void): void;
  on?(type: string, cb: (...a: unknown[]) => void): void;
}

/**
 * Streaming firehose handler. Mirrors python/tn/handlers/firehose.py.
 */
export class TnFirehoseHandler extends AsyncTNHandler {
  private readonly _endpoint: string;
  private readonly _projectId: string;
  private readonly _keyId: string | null;
  private readonly _bek: Uint8Array;
  private _ws: WsLike | null = null;
  private _connecting: Promise<WsLike> | null = null;

  constructor(name: string, opts: FirehoseHandlerOptions) {
    // Validate before super() (no `this` access — pure arg checks).
    if (typeof opts.endpoint !== "string" || !/^https?:\/\//.test(opts.endpoint)) {
      throw new Error(`tn.firehose[${name}]: endpoint must be an http(s) URL, got ${String(opts.endpoint)}`);
    }
    if (!_PROJECT_ID_RE.test(opts.projectId)) {
      throw new Error(`tn.firehose[${name}]: project_id must be a UUID string, got ${opts.projectId}`);
    }
    if (opts.keyId != null && !_KEY_ID_RE.test(opts.keyId)) {
      throw new Error(`tn.firehose[${name}]: key_id ${opts.keyId} not in expected shape (fhk_<base32>)`);
    }
    const asyncOpts: ConstructorParameters<typeof AsyncTNHandler>[1] = { outboxDir: opts.outboxDir };
    if (opts.filter !== undefined) asyncOpts.filter = opts.filter;
    if (opts.maxRetries !== undefined) asyncOpts.maxRetries = opts.maxRetries;
    if (opts.backoffInitialMs !== undefined) asyncOpts.backoffInitialMs = opts.backoffInitialMs;
    if (opts.backoffMaxMs !== undefined) asyncOpts.backoffMaxMs = opts.backoffMaxMs;
    super(name, asyncOpts);
    this._endpoint = opts.endpoint.replace(/\/+$/, "");
    this._projectId = opts.projectId;
    this._keyId = opts.keyId ?? null;
    this._bek = stubBek(this._projectId, this._keyId);
  }

  override resolved_address(): string | null {
    return firehoseWsUrl(this._endpoint, this._projectId);
  }

  /**
   * Encrypt the frame and send it over the WS. Throws on any
   * connect/send failure so the outbox worker retries with backoff (the
   * frame stays durably queued until a send succeeds).
   */
  protected override async publish(
    envelope: Record<string, unknown>,
    rawLine: string,
  ): Promise<void> {
    const eventType = String(envelope["event_type"] ?? "");
    const frame = encryptFirehoseFrame(
      this._bek,
      this._projectId,
      this._keyId,
      eventType,
      new TextEncoder().encode(rawLine),
    );
    let ws: WsLike;
    try {
      ws = await this._ensureConnected();
      ws.send(frame);
    } catch (e) {
      // Drop the connection so the retry reopens, then re-throw so the
      // outbox holds the frame for redelivery.
      this._ws = null;
      throw e instanceof Error ? e : new Error(String(e));
    }
  }

  protected override finalFlush(): void {
    this._closeWs();
  }

  private _closeWs(): void {
    const ws = this._ws;
    this._ws = null;
    if (ws) {
      try {
        ws.close();
      } catch {
        /* best-effort */
      }
    }
  }

  private async _ensureConnected(): Promise<WsLike> {
    if (this._ws && this._ws.readyState === 1) return this._ws;
    if (this._connecting) return this._connecting;
    this._connecting = this._openWs();
    try {
      this._ws = await this._connecting;
      return this._ws;
    } finally {
      this._connecting = null;
    }
  }

  private async _openWs(): Promise<WsLike> {
    const url = firehoseWsUrl(this._endpoint, this._projectId);
    // Prefer the global WebSocket (Node 22+); fall back to the optional `ws`
    // package (mirrors Python's optional `websocket-client` extra).
    const Ctor =
      (globalThis as { WebSocket?: new (u: string) => WsLike }).WebSocket ??
      (await _loadWsPackage());
    const ws = new Ctor(url) as WsLike & { binaryType?: string };
    if ("binaryType" in ws) ws.binaryType = "arraybuffer";
    await new Promise<void>((resolve, reject) => {
      const onOpen = () => resolve();
      const onErr = (e: unknown) => reject(e instanceof Error ? e : new Error("firehose WS error"));
      if (ws.addEventListener) {
        ws.addEventListener("open", onOpen);
        ws.addEventListener("error", onErr);
      } else if (ws.on) {
        ws.on("open", onOpen);
        ws.on("error", onErr);
      } else {
        resolve();
      }
    });
    return ws;
  }
}

async function _loadWsPackage(): Promise<new (u: string) => WsLike> {
  try {
    // Non-literal specifier so tsc doesn't try to resolve the optional `ws`
    // package at build time (it's not a declared dependency — mirrors
    // Python's optional `websocket-client` extra).
    const wsModule = "ws";
    const mod = (await import(wsModule)) as unknown as { default: new (u: string) => WsLike };
    return mod.default;
  } catch (e) {
    throw new Error(
      "tn.firehose requires a WebSocket implementation. Either run on Node 22+ " +
        "(global WebSocket) or install the optional `ws` package.",
      { cause: e },
    );
  }
}
