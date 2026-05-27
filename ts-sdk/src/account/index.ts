// Port of tn_proto/python/tn/vault_client.py::redeem_connect_code +
// tn_proto/python/tn/cli.py::cmd_account_connect + the relevant
// sync_state helpers (mark_account_bound, get_account_id, is_account_bound).
//
// The redeem endpoint is INTENTIONALLY UNAUTHENTICATED — the code +
// signature ARE the authorization. So this namespace does not need a
// pre-authed VaultClient; a plain fetch is enough.
//
// Wire format: POST /api/v1/account/connect-codes/redeem with body
//   { code, did, signature_b64 }
// where signature_b64 is STANDARD base64 (not url-safe) of the Ed25519
// signature of SHA-256(code.utf8()). The server uses Python
// `base64.b64decode`, which requires the standard alphabet.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

import type { DeviceKey } from "../core/signing.js";

const DEFAULT_HEADERS: Record<string, string> = {
  "User-Agent": "tnproto-sdk-ts/0.4.3",
  Accept: "application/json",
  "Content-Type": "application/json",
};

export class AccountConnectError extends Error {
  readonly status: number | null;
  readonly body: string;
  constructor(message: string, opts: { status?: number | null; body?: string | null } = {}) {
    super(message);
    this.name = "AccountConnectError";
    this.status = opts.status ?? null;
    this.body = opts.body ?? "";
  }
}

export interface ConnectResult {
  /** Vault account id the DID is now bound to. */
  accountId: string;
  /** Echo of the redeemed code's project_id (if the code was project-scoped). */
  projectId?: string;
  /** Display name of the project (if any). */
  projectName?: string;
  /** DID that was bound. */
  did: string;
  /** Raw vault response, in case the caller wants additional fields. */
  raw: Record<string, unknown>;
}

export interface ConnectOptions {
  /** Optional fetch override (tests). Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Optional ceremony yaml path; when supplied, the binding is persisted
   *  via the equivalent of Python's `sync_state.mark_account_bound`. */
  yamlPath?: string;
}

/** Standard base64 (not url-safe) — what the Python server's
 *  `base64.b64decode` expects on the wire. */
function _toStandardBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/** Build the message that gets signed: SHA-256 of code.utf8(). */
function _connectMessage(code: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(code, "utf8").digest());
}

/** SYNC_STATE helpers (mirror of tn.sync_state — only the bits we need). */
const SYNC_DIR = "sync";
const STATE_FILE = "state.json";

function _stateDir(yamlPath: string): string {
  return join(dirname(yamlPath), ".tn", SYNC_DIR);
}

function _statePath(yamlPath: string): string {
  return join(_stateDir(yamlPath), STATE_FILE);
}

function _loadSyncState(yamlPath: string): Record<string, unknown> {
  const p = _statePath(yamlPath);
  if (!existsSync(p)) return {};
  try {
    const raw = readFileSync(p, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    // Corrupt file = treat as empty, matching Python's load_sync_state.
    return {};
  }
}

function _saveSyncState(yamlPath: string, state: Record<string, unknown>): void {
  const dir = _stateDir(yamlPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(_statePath(yamlPath), JSON.stringify(state, null, 2), "utf-8");
}

/** Mirror of Python `mark_account_bound`: stamp account_id + clear any
 *  in-flight pending_claim (the bind consumes the link). */
export function markAccountBound(yamlPath: string, accountId: string): void {
  const state = _loadSyncState(yamlPath);
  state.account_id = accountId;
  state.account_bound = true;
  delete state.pending_claim;
  _saveSyncState(yamlPath, state);
}

/** Mirror of Python `get_account_id`. */
export function getAccountId(yamlPath: string): string | null {
  const state = _loadSyncState(yamlPath);
  const v = state.account_id;
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Mirror of Python `is_account_bound`. */
export function isAccountBound(yamlPath: string): boolean {
  const state = _loadSyncState(yamlPath);
  return state.account_bound === true;
}

export class AccountNamespace {
  /**
   * Redeem a connect code against the vault to bind ``device.did`` to an
   * account. Mirrors Python ``tn.cli.cmd_account_connect`` end-to-end:
   *
   *   1. message = SHA-256(code.utf8())
   *   2. signature = Ed25519.sign(deviceKey, message)
   *   3. POST /api/v1/account/connect-codes/redeem with
   *      { code, did, signature_b64 (standard base64) }
   *   4. On success, persist `account_id` into ceremony sync state
   *      (only when `yamlPath` is supplied).
   *
   * The redeem endpoint is unauthenticated — the signature is the
   * authorization. Server-side: 400 (bad sig), 401 (sig verify failed),
   * 404 (unknown code), 409 (consumed / DID bound elsewhere), 410 (expired).
   */
  static async connect(
    code: string,
    vaultBaseUrl: string,
    deviceKey: DeviceKey,
    opts: ConnectOptions = {},
  ): Promise<ConnectResult> {
    const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    const baseUrl = vaultBaseUrl.replace(/\/+$/, "");
    const did = deviceKey.did;

    const message = _connectMessage(code);
    const sigBytes = deviceKey.sign(message);
    const signatureB64 = _toStandardBase64(sigBytes);

    const url = `${baseUrl}/api/v1/account/connect-codes/redeem`;
    const resp = await fetchImpl(url, {
      method: "POST",
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({ code, did, signature_b64: signatureB64 }),
    });

    if (resp.status >= 400) {
      let body = "";
      try {
        body = (await resp.text()).slice(0, 512);
      } catch {
        // ignore read errors
      }
      throw new AccountConnectError(
        `POST /api/v1/account/connect-codes/redeem returned ${resp.status}`,
        { status: resp.status, body },
      );
    }

    const raw = (await resp.json()) as Record<string, unknown>;
    const accountId = raw.account_id;
    if (typeof accountId !== "string" || !accountId) {
      throw new AccountConnectError(
        `vault accepted redeem but response missing account_id: ${JSON.stringify(raw)}`,
        { status: resp.status },
      );
    }

    if (opts.yamlPath) {
      markAccountBound(opts.yamlPath, accountId);
    }

    const result: ConnectResult = { accountId, did, raw };
    if (typeof raw.project_id === "string") result.projectId = raw.project_id;
    if (typeof raw.project_name === "string") result.projectName = raw.project_name;
    return result;
  }
}
