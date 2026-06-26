// OAuth 2.0 Device Authorization Grant (RFC 8628) client — the browser
// `tn auth login` flow. Idiomatic with `az login` / `gh auth login`:
//
//   1. POST /api/v1/device/code  → { device_code, user_code, verification_uri,
//      verification_uri_complete, interval, expires_in }. The request is SIGNED
//      by the device key so the vault enrolls a DID the caller provably owns.
//   2. The CLI opens `verification_uri_complete` (best-effort) AND always prints
//      the short `user_code` + `verification_uri` so a non-opening browser is a
//      non-event — sign in on any device.
//   3. POST /api/v1/device/token  (poll with `device_code`) → RFC error bodies
//      `authorization_pending` / `slow_down` until approved, then 200
//      `{ account_id, did }`. The device key stays the principal — no token to
//      store; enrollment is the result.
//
// The wire shapes here are the contract of record; the vault implements the
// same field + error names.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";

import type { DeviceKey } from "../core/signing.js";

/** Successful `/device/code` response (RFC 8628 §3.2 fields, snake_case wire). */
export interface DeviceCodeResponse {
  /** Opaque secret the CLI polls the token endpoint with. */
  deviceCode: string;
  /** Short, human-typeable code (e.g. `WDJB-MJHT`) the user enters in the browser. */
  userCode: string;
  /** The stable URL to visit (e.g. `https://vault…/device`). */
  verificationUri: string;
  /** `verification_uri` with `user_code` pre-filled — for the auto-open path. */
  verificationUriComplete: string;
  /** Minimum seconds between token polls. */
  interval: number;
  /** Seconds until the device_code expires. */
  expiresIn: number;
}

/** Device-flow failure. `code` carries the RFC 8628 error slug when the vault
 *  returned one (`expired_token`, `access_denied`, …). */
export class DeviceFlowError extends Error {
  readonly code: string | null;
  constructor(message: string, code: string | null = null) {
    super(message);
    this.name = "DeviceFlowError";
    this.code = code;
  }
}

const DEFAULT_HEADERS: Record<string, string> = { "Content-Type": "application/json" };

/** Standard (not url-safe) base64 — what the Python vault's `b64decode` expects. */
function toStandardBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/** The message the device key signs to prove DID ownership at `/device/code`:
 *  SHA-256 of `tn:device-code:<did>`. */
function deviceCodeMessage(did: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(`tn:device-code:${did}`, "utf8").digest());
}

/**
 * Start a device-authorization request. Signs `tn:device-code:<did>` with the
 * device key so the vault binds the pending login to a DID the caller owns.
 */
export async function requestDeviceCode(
  vaultBase: string,
  deviceKey: DeviceKey,
  opts: { fetchImpl?: typeof fetch; label?: string } = {},
): Promise<DeviceCodeResponse> {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const base = vaultBase.replace(/\/+$/, "");
  const did = deviceKey.did;
  const signatureB64 = toStandardBase64(deviceKey.sign(deviceCodeMessage(did)));

  const body: Record<string, unknown> = { did, signature_b64: signatureB64 };
  if (opts.label) body["label"] = opts.label;

  const resp = await fetchImpl(`${base}/api/v1/device/code`, {
    method: "POST",
    headers: DEFAULT_HEADERS,
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new DeviceFlowError(
      `device/code returned ${resp.status}: ${text.slice(0, 256)}`,
    );
  }
  const j = (await resp.json()) as Record<string, unknown>;
  const deviceCode = j["device_code"];
  const userCode = j["user_code"];
  const verificationUri = j["verification_uri"];
  if (typeof deviceCode !== "string" || typeof userCode !== "string" || typeof verificationUri !== "string") {
    throw new DeviceFlowError(`device/code response missing fields: ${JSON.stringify(j)}`);
  }
  return {
    deviceCode,
    userCode,
    verificationUri,
    verificationUriComplete:
      typeof j["verification_uri_complete"] === "string"
        ? (j["verification_uri_complete"] as string)
        : `${verificationUri}?code=${encodeURIComponent(userCode)}`,
    interval: typeof j["interval"] === "number" ? j["interval"] : 5,
    expiresIn: typeof j["expires_in"] === "number" ? j["expires_in"] : 900,
  };
}

/** Result of a completed device-flow login. */
export interface DeviceTokenResult {
  accountId: string;
  did: string;
  /** Base64 key-id for a pre-sealed AWK pickup, or null if the vault didn't
   *  include one (older vault or no AWK enrolled yet). */
  awkPickupKeyId: string | null;
}

/**
 * Poll `/device/token` until the user approves in the browser, the code
 * expires, or approval is denied. Honors RFC 8628 `authorization_pending`
 * (keep waiting) and `slow_down` (add 5s to the interval). `sleep` is injectable
 * for tests; a monotonic clock isn't needed — the loop bounds itself on
 * `expiresIn` poll-budget so a stubbed sleep can't spin forever.
 */
export async function pollDeviceToken(
  vaultBase: string,
  dc: DeviceCodeResponse,
  opts: { fetchImpl?: typeof fetch; sleep?: (ms: number) => Promise<void> } = {},
): Promise<DeviceTokenResult> {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const base = vaultBase.replace(/\/+$/, "");
  let interval = dc.interval;
  let elapsed = 0;

  for (;;) {
    if (elapsed >= dc.expiresIn) {
      throw new DeviceFlowError("device code expired before approval", "expired_token");
    }
    await sleep(interval * 1000);
    elapsed += interval;

    const resp = await fetchImpl(`${base}/api/v1/device/token`, {
      method: "POST",
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({ device_code: dc.deviceCode }),
    });

    if (resp.status === 200) {
      const j = (await resp.json()) as Record<string, unknown>;
      const accountId = j["account_id"];
      const did = j["did"];
      if (typeof accountId !== "string" || !accountId) {
        throw new DeviceFlowError(`device/token ok but missing account_id: ${JSON.stringify(j)}`);
      }
      return {
        accountId,
        did: typeof did === "string" ? did : "",
        awkPickupKeyId: typeof j["awk_pickup_key_id"] === "string" ? (j["awk_pickup_key_id"] as string) : null,
      };
    }

    // RFC 8628 §3.5: pending/slow_down are normal; everything else is terminal.
    let errCode = "";
    try {
      errCode = String(((await resp.json()) as Record<string, unknown>)["error"] ?? "");
    } catch {
      // non-JSON error body — treat as terminal below
    }
    if (errCode === "authorization_pending") continue;
    if (errCode === "slow_down") {
      interval += 5;
      continue;
    }
    if (errCode === "expired_token") {
      throw new DeviceFlowError("device code expired before approval", "expired_token");
    }
    if (errCode === "access_denied") {
      throw new DeviceFlowError("sign-in was denied in the browser", "access_denied");
    }
    throw new DeviceFlowError(
      `device/token returned ${resp.status}${errCode ? ` (${errCode})` : ""}`,
      errCode || null,
    );
  }
}

/**
 * Best-effort browser open (the auto path). Returns true if a launcher was
 * spawned, false if none is available — the caller ALWAYS prints the code + URL
 * regardless, so a false here is a non-event. Never throws.
 */
export function openBrowser(url: string): boolean {
  // Headless / no display → don't even try; the printed URL is the path.
  if (process.env["TN_NO_BROWSER"] === "1") return false;
  const plat = process.platform;
  let cmd: string;
  let args: string[];
  if (plat === "win32") {
    // `start` is a cmd builtin; the empty "" is the window-title arg.
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else if (plat === "darwin") {
    cmd = "open";
    args = [url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {
      /* launcher missing — best-effort, the printed URL covers it */
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}
