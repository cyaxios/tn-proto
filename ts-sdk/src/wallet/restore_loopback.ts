// One-shot loopback HTTP receiver for the multi-device restore flow.
// Port of python/tn/wallet_restore_loopback.py.
//
// The CLI can't run WebAuthn-PRF, so `tn-js wallet restore`:
//   1. Starts this receiver on 127.0.0.1:<random port>.
//   2. Opens the vault's `/restore` page with
//      `return_to=http://127.0.0.1:<port>/cb&state=<nonce>`.
//   3. The browser completes OAuth + passkey-PRF unwrap and POSTs a
//      TransferToken (vault_jwt, account_id, project_id, raw_bek_b64) to /cb.
//   4. The CLI receives the token, shuts the server down, fetches the
//      encrypted blob and decrypts it with the raw BEK.
//
// Security (mirrors Python):
//   * Bound to 127.0.0.1 — the kernel refuses off-host connections.
//   * `state` nonce echoed in the POST so a stale/cross-run token can't land.
//   * CORS Access-Control-Allow-Origin is echoed ONLY for the configured
//     vault origin so the browser fetch runs `mode:"cors"` and sees real
//     status (no opaque no-cors masking). Defense-in-depth client-host check.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";

/** Payload the browser POSTs back to /cb. Mirrors Python's TransferToken. */
export interface TransferToken {
  vaultJwt: string;
  accountId: string;
  projectId: string;
  rawBekB64: string;
  packageDid?: string | null;
  state?: string | null;
}

function _b64urlState(): string {
  return Buffer.from(randomBytes(16)).toString("base64url");
}

function _isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  const h = host.replace(/^::ffff:/, "");
  return h === "127.0.0.1" || h === "::1" || h.startsWith("127.");
}

export interface LoopbackStartOptions {
  /** Override the random state nonce (tests). */
  state?: string;
  /** Vault page origin to echo in CORS headers, e.g. https://vault.tn-proto.org. */
  allowOrigin?: string;
  /** Bind a specific port (tests); default 0 = kernel picks. */
  port?: number;
}

/**
 * One-shot loopback receiver. `await LoopbackReceiver.start(...)` binds the
 * port before resolving (so the URL is safe to print immediately), then
 * `waitForToken()` blocks until the browser delivers the token.
 */
export class LoopbackReceiver {
  readonly port: number;
  readonly state: string;
  private readonly _server: Server;
  private readonly _allowOrigin: string;
  private _resolveToken: ((t: TransferToken) => void) | null = null;
  private _tokenPromise: Promise<TransferToken>;

  private constructor(server: Server, port: number, state: string, allowOrigin: string) {
    this._server = server;
    this.port = port;
    this.state = state;
    this._allowOrigin = allowOrigin;
    this._tokenPromise = new Promise<TransferToken>((resolve) => {
      this._resolveToken = resolve;
    });
  }

  get callbackUrl(): string {
    return `http://127.0.0.1:${this.port}/cb`;
  }

  /** Spin up the server (bound before resolving). */
  static start(opts: LoopbackStartOptions = {}): Promise<LoopbackReceiver> {
    const state = opts.state ?? _b64urlState();
    const allowOrigin = (opts.allowOrigin ?? "").replace(/\/+$/, "");
    return new Promise<LoopbackReceiver>((resolve, reject) => {
      let receiver: LoopbackReceiver;
      const server = createServer((req, res) => receiver._handle(req, res));
      server.on("error", reject);
      // Bind to 127.0.0.1 only; port 0 lets the kernel pick.
      server.listen(opts.port ?? 0, "127.0.0.1", () => {
        const addr = server.address();
        const port = typeof addr === "object" && addr ? addr.port : 0;
        receiver = new LoopbackReceiver(server, port, state, allowOrigin);
        resolve(receiver);
      });
    });
  }

  private _corsHeaders(originHeader: string | undefined): Record<string, string> {
    if (!this._allowOrigin) return {};
    const allow =
      originHeader && originHeader === this._allowOrigin ? originHeader : this._allowOrigin;
    return {
      "Access-Control-Allow-Origin": allow,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      Vary: "Origin",
    };
  }

  private _reject(res: ServerResponse, code: number, message: string, origin?: string): void {
    const body = Buffer.from(message, "utf-8");
    res.writeHead(code, {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Length": String(body.length),
      ...this._corsHeaders(origin),
    });
    res.end(body);
  }

  private _handle(req: IncomingMessage, res: ServerResponse): void {
    const origin = req.headers.origin;
    const clientHost = req.socket.remoteAddress ?? "";
    const path = (req.url ?? "").split("?")[0];

    if (req.method === "OPTIONS") {
      if (!_isLoopbackHost(clientHost)) return this._reject(res, 403, "non-loopback origin", origin);
      res.writeHead(204, { "Content-Length": "0", ...this._corsHeaders(origin) });
      res.end();
      return;
    }
    if (req.method === "GET") {
      return this._reject(res, path === "/" || path?.startsWith("/cb") ? 405 : 404, "POST only", origin);
    }
    if (req.method !== "POST") {
      return this._reject(res, 405, "POST only", origin);
    }
    if (!_isLoopbackHost(clientHost)) return this._reject(res, 403, "non-loopback origin", origin);
    if (!path?.startsWith("/cb")) return this._reject(res, 404, "not found", origin);

    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 64 * 1024) {
        aborted = true;
        this._reject(res, 413, "body too large", origin);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (aborted) return;
      let payload: Record<string, unknown>;
      try {
        payload = JSON.parse(Buffer.concat(chunks).toString("utf-8")) as Record<string, unknown>;
      } catch {
        return this._reject(res, 400, "invalid JSON", origin);
      }
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        return this._reject(res, 400, "expected JSON object", origin);
      }
      if (payload["state"] !== this.state) {
        return this._reject(res, 400, "state mismatch", origin);
      }
      const required = ["vault_jwt", "account_id", "project_id", "raw_bek_b64"] as const;
      const missing = required.filter((k) => !payload[k]);
      if (missing.length) {
        return this._reject(res, 400, `missing fields: ${missing.join(",")}`, origin);
      }

      const token: TransferToken = {
        vaultJwt: String(payload["vault_jwt"]),
        accountId: String(payload["account_id"]),
        projectId: String(payload["project_id"]),
        rawBekB64: String(payload["raw_bek_b64"]),
        packageDid: (payload["package_did"] as string | null | undefined) ?? null,
        state: (payload["state"] as string | null | undefined) ?? null,
      };
      const body = Buffer.from("Restore initiated. You can close this tab.", "utf-8");
      res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": String(body.length),
        ...this._corsHeaders(origin),
      });
      res.end(body);
      this._resolveToken?.(token);
    });
  }

  /** Block until the browser POSTs a valid token, or reject on timeout. */
  waitForToken(opts: { timeoutMs?: number } = {}): Promise<TransferToken> {
    const timeoutMs = opts.timeoutMs ?? 300_000;
    let timer: NodeJS.Timeout;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new Error(
              `no transfer token received within ${Math.round(timeoutMs / 1000)}s — ` +
                `closing the tab cancels the restore`,
            ),
          ),
        timeoutMs,
      );
    });
    return Promise.race([this._tokenPromise, timeout]).finally(() => clearTimeout(timer));
  }

  /** Stop the server. Idempotent. */
  shutdown(): void {
    try {
      this._server.close();
    } catch {
      /* best-effort */
    }
  }
}
