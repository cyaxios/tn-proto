// Port of tn_proto/python/tn/vault_client.py — VaultClient + VaultError.
//
// PHASE 1 (this file): the unsealed surface — auth (challenge/verify),
// projects (create/list/get/delete), restore_manifest, and the raw
// request plumbing. These are the methods needed for `wallet.link`.
//
// PHASE 2 (deferred): the sealed surface — upload_file / download_file /
// upload_sealed / download_sealed. Those need the wrap-key + AAD bind
// (identity.vault_wrap_key in Python). Required for wallet.sync /
// wallet.restore. Tracked separately so this PR stays reviewable.
//
// Python parity is the contract: when in doubt, do it the way
// vault_client.py does. Tests interop the two clients against the same
// running vault.

import type { DeviceKey } from "../core/signing.js";
import { signatureB64 } from "../core/signing.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_HEADERS: Record<string, string> = {
  "User-Agent": "tnproto-sdk-ts/0.4.3",
  Accept: "application/json",
};

/** Mirror of Python's `VaultError`. Carries the HTTP status + raw body. */
export class VaultError extends Error {
  readonly status: number | null;
  readonly body: string;
  constructor(message: string, opts: { status?: number | null; body?: string | null } = {}) {
    super(message);
    this.name = "VaultError";
    this.status = opts.status ?? null;
    this.body = opts.body ?? "";
  }
}

/** Subset of the Python `Identity` surface that VaultClient needs. */
export interface VaultIdentity {
  /** did:key:... — used as the auth-challenge subject. */
  readonly did: string;
  /** Sign a byte string with the identity's Ed25519 key. */
  signNonce(message: Uint8Array): Uint8Array;
}

/** Build a VaultIdentity from a TS SDK DeviceKey. */
export function vaultIdentityFromDeviceKey(device: DeviceKey): VaultIdentity {
  return {
    did: device.did,
    signNonce: (msg) => device.sign(msg),
  };
}

export interface VaultClientOptions {
  baseUrl: string;
  identity: VaultIdentity;
  /** Optional pre-existing JWT — skip auto-auth if present. */
  token?: string | null;
  /** Per-request timeout in ms. Default: 30_000. */
  timeoutMs?: number;
  /** Override fetch (tests). Default: globalThis.fetch. */
  fetchImpl?: typeof fetch;
}

interface RequestOpts {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  jsonBody?: unknown;
  body?: Uint8Array | string;
  headers?: Record<string, string>;
  reauthOn401?: boolean;
}

/**
 * Session-scoped vault client.
 *
 * Construct with `await VaultClient.forIdentity(...)` to get an authed
 * client. Tokens auto-refresh on 401.
 *
 * Mirrors `tn.vault_client.VaultClient` from the Python SDK. Phase 1
 * covers auth + projects + restore_manifest; sealed file ops land in
 * Phase 2.
 */
export class VaultClient {
  readonly baseUrl: string;
  readonly identity: VaultIdentity;
  private _token: string | null;
  private readonly _timeoutMs: number;
  private readonly _fetch: typeof fetch;

  private constructor(opts: VaultClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.identity = opts.identity;
    this._token = opts.token ?? null;
    this._timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this._fetch = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  /** Get the cached JWT (null until authenticate() runs). */
  get token(): string | null {
    return this._token;
  }

  /**
   * Build a VaultClient for `identity` against `baseUrl`. With
   * `autoAuth: true` (default) runs the challenge/verify dance before
   * returning so callers can issue authenticated requests immediately.
   *
   * Mirrors Python `VaultClient.for_identity(identity, base_url, auto_auth=True)`.
   */
  static async forIdentity(
    identity: VaultIdentity,
    baseUrl: string,
    opts: { autoAuth?: boolean; timeoutMs?: number; fetchImpl?: typeof fetch } = {},
  ): Promise<VaultClient> {
    const c = new VaultClient({ baseUrl, identity, ...opts });
    if (opts.autoAuth !== false) {
      await c.authenticate();
    }
    return c;
  }

  /** Convenience for tests / advanced callers: build without auth. */
  static unauthed(opts: VaultClientOptions): VaultClient {
    return new VaultClient(opts);
  }

  // ── Auth (DID challenge/verify) ──────────────────────────────────

  /**
   * Run the DID challenge/verify dance and cache the JWT.
   *
   *   POST /api/v1/auth/challenge {did} -> {nonce, expires_in}
   *   sign utf8(nonce) with identity's Ed25519 key
   *   POST /api/v1/auth/verify {did, nonce, signature_b64} -> {token, ...}
   *
   * Mirrors `VaultClient.authenticate` in Python. Called automatically
   * by the 401-retry path inside `_request`.
   */
  async authenticate(): Promise<string> {
    const did = this.identity.did;

    const challengeResp = await this._rawRequest({
      method: "POST",
      path: "/api/v1/auth/challenge",
      jsonBody: { did },
    });
    if (challengeResp.status >= 400) {
      throw new VaultError(
        `POST /api/v1/auth/challenge returned ${challengeResp.status}`,
        { status: challengeResp.status, body: await challengeResp.text() },
      );
    }
    const challengeJson = (await challengeResp.json()) as { nonce: string };
    const nonce = challengeJson.nonce;
    if (typeof nonce !== "string" || !nonce) {
      throw new VaultError(`auth/challenge: bad response shape`, {
        status: 200,
        body: JSON.stringify(challengeJson),
      });
    }

    const nonceBytes = new TextEncoder().encode(nonce);
    const sigBytes = this.identity.signNonce(nonceBytes);
    const sigB64 = signatureB64(sigBytes);

    const verifyResp = await this._rawRequest({
      method: "POST",
      path: "/api/v1/auth/verify",
      jsonBody: { did, nonce, signature: sigB64 },
    });
    if (verifyResp.status >= 400) {
      throw new VaultError(
        `POST /api/v1/auth/verify returned ${verifyResp.status}`,
        { status: verifyResp.status, body: await verifyResp.text() },
      );
    }
    const verifyJson = (await verifyResp.json()) as { token?: string };
    if (typeof verifyJson.token !== "string" || !verifyJson.token) {
      throw new VaultError(`auth/verify: response missing token`, {
        status: 200,
        body: JSON.stringify(verifyJson),
      });
    }
    this._token = verifyJson.token;
    return verifyJson.token;
  }

  // ── Projects (CRUD) ──────────────────────────────────────────────

  /**
   * Create a new project under the authed identity.
   *
   * Mirrors Python `create_project(name, *, ceremony_id=None)`.
   * Returns the project dict (with `id` or `_id`).
   */
  async createProject(name: string, opts: { ceremonyId?: string } = {}): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = { name };
    if (opts.ceremonyId !== undefined) body.ceremony_id = opts.ceremonyId;
    const resp = await this._request({ method: "POST", path: "/api/v1/projects", jsonBody: body });
    return (await resp.json()) as Record<string, unknown>;
  }

  /** Mirrors Python `list_projects()` -> list of project dicts. */
  async listProjects(): Promise<Record<string, unknown>[]> {
    const resp = await this._request({ method: "GET", path: "/api/v1/projects" });
    const raw = (await resp.json()) as unknown;
    if (!Array.isArray(raw)) {
      throw new VaultError(`list_projects: expected array; got ${typeof raw}`);
    }
    return raw as Record<string, unknown>[];
  }

  /** Mirrors Python `get_project(project_id)`. */
  async getProject(projectId: string): Promise<Record<string, unknown>> {
    const resp = await this._request({ method: "GET", path: `/api/v1/projects/${encodeURIComponent(projectId)}` });
    return (await resp.json()) as Record<string, unknown>;
  }

  /** Mirrors Python `delete_project(project_id)`. */
  async deleteProject(projectId: string): Promise<void> {
    await this._request({ method: "DELETE", path: `/api/v1/projects/${encodeURIComponent(projectId)}` });
  }

  // ── Restore manifest (read-only) ─────────────────────────────────

  /**
   * List files in a project for restore. Mirrors Python `restore_manifest`.
   * Returns the manifest dict; callers consult `.files` (list).
   */
  async restoreManifest(projectId: string): Promise<Record<string, unknown>> {
    const resp = await this._request({
      method: "GET",
      path: `/api/v1/projects/${encodeURIComponent(projectId)}/restore-manifest`,
    });
    return (await resp.json()) as Record<string, unknown>;
  }

  // ── AWK/BEK account surface (D-20 / D-22) ────────────────────────
  // The supported whole-body model. All routes authenticate with the
  // account JWT — and a DID-challenge token resolves to the bound
  // account server-side (require_account_id), so the existing
  // authenticate() flow is sufficient. Logic mirrors Python
  // wallet_restore_passphrase.py (GETs) + the browser minter (PUTs).

  /**
   * Pull a credential row INCLUDING its wrapping material. Mirror of
   * Python `_fetch_credential_with_wrap`. With no `credentialId`, returns
   * the unique `is_primary` row (or the sole row), erroring on 0 / >1.
   */
  async getCredentialWrap(opts: { credentialId?: string } = {}): Promise<Record<string, unknown>> {
    if (opts.credentialId === undefined) {
      const resp = await this._request({
        method: "GET",
        path: "/api/v1/account/credentials?include=wrap",
      });
      const rows = (await resp.json()) as Record<string, unknown>[];
      if (!Array.isArray(rows)) throw new VaultError("credentials list: expected array");
      const primary = rows.filter((r) => r.is_primary);
      const candidates = primary.length > 0 ? primary : rows;
      if (candidates.length === 0) {
        throw new VaultError(
          "no credentials registered for this account — register one via the browser flow first",
        );
      }
      if (candidates.length > 1) {
        throw new VaultError(
          `${candidates.length} primary credentials found; pass credentialId to choose one`,
        );
      }
      return candidates[0]!;
    }
    const resp = await this._request({
      method: "GET",
      path: `/api/v1/account/credentials/${encodeURIComponent(opts.credentialId)}/wrap`,
    });
    return (await resp.json()) as Record<string, unknown>;
  }

  /** GET /api/v1/projects/{id}/wrapped-key. Mirror of Python `_fetch_wrapped_key`. */
  async getWrappedKey(projectId: string): Promise<Record<string, unknown>> {
    const resp = await this._request({
      method: "GET",
      path: `/api/v1/projects/${encodeURIComponent(projectId)}/wrapped-key`,
    });
    return (await resp.json()) as Record<string, unknown>;
  }

  /** PUT /api/v1/projects/{id}/wrapped-key — store the BEK wrapped under the AWK. */
  async putWrappedKey(
    projectId: string,
    body: { wrapped_bek_b64: string; wrap_nonce_b64: string; cipher_suite?: string; label?: string; package_did?: string },
  ): Promise<Record<string, unknown>> {
    const resp = await this._request({
      method: "PUT",
      path: `/api/v1/projects/${encodeURIComponent(projectId)}/wrapped-key`,
      jsonBody: { cipher_suite: "aes-256-gcm", ...body },
    });
    return (await resp.json()) as Record<string, unknown>;
  }

  /** GET /api/v1/projects/{id}/encrypted-blob — the BEK-encrypted body envelope. */
  async getEncryptedBlob(projectId: string): Promise<Record<string, unknown>> {
    const resp = await this._request({
      method: "GET",
      path: `/api/v1/projects/${encodeURIComponent(projectId)}/encrypted-blob`,
    });
    return (await resp.json()) as Record<string, unknown>;
  }

  /**
   * PUT /api/v1/projects/{id}/encrypted-blob-account — write the
   * BEK-encrypted body. `ifMatch` is the integer generation, or "*" for
   * the first write (428 if omitted, 412 on mismatch).
   */
  async putEncryptedBlobAccount(
    projectId: string,
    body: Record<string, unknown>,
    opts: { ifMatch: string | number },
  ): Promise<Record<string, unknown>> {
    const resp = await this._request({
      method: "PUT",
      path: `/api/v1/projects/${encodeURIComponent(projectId)}/encrypted-blob-account`,
      jsonBody: body,
      headers: { "If-Match": String(opts.ifMatch) },
    });
    return (await resp.json()) as Record<string, unknown>;
  }

  /** GET /api/v1/account/projects — restorable projects for this account. */
  async listAccountProjects(): Promise<Record<string, unknown>[]> {
    const resp = await this._request({ method: "GET", path: "/api/v1/account/projects" });
    const raw = (await resp.json()) as unknown;
    // The account-projects route returns either a bare list or {items:[...]}.
    if (Array.isArray(raw)) return raw as Record<string, unknown>[];
    const items = (raw as { items?: unknown }).items;
    return Array.isArray(items) ? (items as Record<string, unknown>[]) : [];
  }

  /** GET /api/v1/account/inbox — every snapshot addressed to an owned DID. */
  async listAccountInbox(): Promise<{ items: Record<string, unknown>[] }> {
    const resp = await this._request({ method: "GET", path: "/api/v1/account/inbox" });
    const raw = (await resp.json()) as { items?: Record<string, unknown>[] };
    return { items: Array.isArray(raw.items) ? raw.items : [] };
  }

  /** GET a staged account-inbox snapshot's raw .tnpkg bytes. */
  async downloadAccountInboxSnapshot(fromDid: string, ceremonyId: string, ts: string): Promise<Uint8Array> {
    const path =
      `/api/v1/account/inbox/${encodeURIComponent(fromDid)}` +
      `/${encodeURIComponent(ceremonyId)}/${encodeURIComponent(ts)}.tnpkg`;
    const resp = await this._request({ method: "GET", path });
    return new Uint8Array(await resp.arrayBuffer());
  }

  /**
   * POST a `.tnpkg` snapshot to a DID's inbox — the steady-state authenticated
   * publish that rides the account-inbox MERGE path. Mirrors Python's
   * `VaultClient.post_inbox_snapshot` (python/tn/handlers/vault_push.py:762).
   *
   *   POST /api/v1/inbox/{did}/snapshots/{ceremony}/{name}.tnpkg
   *
   * `body` is the raw `.tnpkg` bytes (octet-stream). `params` (e.g.
   * `head_row_hash`) ride as a query string for server-side idempotency.
   */
  async postInboxSnapshot(
    did: string,
    ceremonyId: string,
    name: string,
    body: Uint8Array,
    opts: { params?: Record<string, string> } = {},
  ): Promise<void> {
    let path =
      `/api/v1/inbox/${encodeURIComponent(did)}` +
      `/snapshots/${encodeURIComponent(ceremonyId)}/${encodeURIComponent(name)}`;
    if (opts.params && Object.keys(opts.params).length > 0) {
      const qs = new URLSearchParams(opts.params).toString();
      path = `${path}?${qs}`;
    }
    await this._request({
      method: "POST",
      path,
      body,
      headers: { "Content-Type": "application/octet-stream" },
    });
  }

  // ── Internals ────────────────────────────────────────────────────

  private _authHeaders(extra?: Record<string, string>): Record<string, string> {
    const h: Record<string, string> = { ...DEFAULT_HEADERS };
    if (this._token) h.Authorization = `Bearer ${this._token}`;
    if (extra) Object.assign(h, extra);
    return h;
  }

  private async _rawRequest(opts: { method: string; path: string; jsonBody?: unknown; body?: string | Uint8Array; headers?: Record<string, string> }): Promise<Response> {
    const url = `${this.baseUrl}${opts.path}`;
    const headers: Record<string, string> = { ...DEFAULT_HEADERS, ...(opts.headers ?? {}) };
    let body: string | Uint8Array | undefined;
    if (opts.jsonBody !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.jsonBody);
    } else if (opts.body !== undefined) {
      body = opts.body;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this._timeoutMs);
    try {
      const init: RequestInit = { method: opts.method, headers, signal: ctrl.signal };
      if (body !== undefined) init.body = body;
      return await this._fetch(url, init);
    } finally {
      clearTimeout(timer);
    }
  }

  private async _request(opts: RequestOpts): Promise<Response> {
    const headers = this._authHeaders(opts.headers);
    const callOnce = async (): Promise<Response> => {
      const reqHeaders = { ...headers };
      if (opts.jsonBody !== undefined) reqHeaders["Content-Type"] = "application/json";
      const inner: { method: string; path: string; jsonBody?: unknown; body?: string | Uint8Array; headers: Record<string, string> } = {
        method: opts.method,
        path: opts.path,
        headers: reqHeaders,
      };
      if (opts.jsonBody !== undefined) inner.jsonBody = opts.jsonBody;
      else if (opts.body !== undefined) inner.body = opts.body;
      return this._rawRequest(inner);
    };
    let resp = await callOnce();
    if (
      resp.status === 401 &&
      (opts.reauthOn401 ?? true) &&
      this._token !== null
    ) {
      this._token = null;
      await this.authenticate();
      const refreshed = this._authHeaders(opts.headers);
      Object.assign(headers, refreshed);
      resp = await callOnce();
    }
    if (resp.status >= 400) {
      let body = "";
      try {
        body = (await resp.text()).slice(0, 512);
      } catch {
        // Body read failure is non-fatal; report what we have.
      }
      throw new VaultError(
        `${opts.method} ${opts.path} returned ${resp.status}`,
        { status: resp.status, body },
      );
    }
    return resp;
  }
}
