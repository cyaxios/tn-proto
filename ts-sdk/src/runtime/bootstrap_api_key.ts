// Cold-start keystore bootstrap from a TN_API_KEY bearer.
//
// TS port of python/tn/bootstrap.py. Mirrors the flow on a fresh node
// that has only $TN_API_KEY in env:
//
//   1. Caller has an empty keystore + a yaml that declares vault.sync.
//   2. The handler-builder spots the empty keystore + the env var and
//      calls bootstrapFromApiKey() BEFORE constructing the vault.sync
//      handler (which would otherwise raise on a missing local.private).
//   3. We split the bearer into seed + key_id, derive the DID, run the
//      standard /api/v1/auth/{challenge,verify} flow to mint a JWT,
//      pull the sealed kit_bundle via
//      /api/v1/api-keys/{key_id}/sealed-bundle, and hand the bytes to
//      the absorb path. The absorb path knows how to unseal recipient-
//      wrapped bundles via the device seed.
//   4. Absorb installs the body into the keystore (a project_seed
//      tnpkg with the publisher's keys + tn.yaml). The keystore is now
//      hot.
//
// We never throw — failures return False so the caller can fall
// through to the existing INIT-UPLOAD-and-claim-URL path. Contract is
// "best-effort cold start": a stale / revoked / consumed bearer leaves
// the keystore in whatever state it was in (typically still empty), and
// the existing flow takes over.
//
// **PARTIAL PORT — see end of this file.** The Python implementation
// chains into `_absorb_dispatch -> _maybe_unseal_recipient_wrap` which
// recovers the BEK from `manifest.state.body_encryption.recipient_wraps`
// using the bearer's seed and decrypts the project_seed body. The TS
// `absorbBootstrap` (src/runtime/absorb_bootstrap.ts) does NOT yet
// integrate the unseal step from `core/recipient_seal.ts`, so this
// module does the env-var-honoring half — read TN_API_KEY, derive DID,
// challenge/verify, fetch the sealed bundle — and surfaces a clearly-
// named `UnsealNotWiredError` once the bundle is in hand. Filling in
// the unseal+install bridge is a follow-up task; see the doc-comment at
// the bottom for the exact integration sketch.
//
// This module is internal — there is no public `Tn.bootstrapFromApiKey`
// symbol. The handler-builder is the only caller; users discover the
// feature by setting TN_API_KEY.

import { Buffer } from "node:buffer";

import { DeviceKey } from "../core/signing.js";
import { resolveDidEndpoint } from "../vault/url.js";
import { signatureB64 } from "../raw.js";
import { absorbSealedBootstrap } from "./absorb_bootstrap.js";
import type { AbsorbReceipt } from "../core/results.js";

const _BEARER_PREFIX = "tn_apikey_";
const _HTTP_TIMEOUT_MS = 15_000;

/** Self-identifying User-Agent so the Cloudflare edge stops 403'ing us
 *  with `error code: 1010`. Mirrors python/tn/bootstrap.py:_tn_user_agent.
 *  UA is NOT an auth boundary — the real boundary stays at the DID
 *  signature on /auth/verify. */
function _tnUserAgent(): string {
  // Use the SDK package name as a stable, public-API identifier. We
  // could read the version from package.json but the file's location
  // varies (installed vs editable); the bare name is enough for the
  // edge's UA filter.
  return "tn-protocol-ts/dev";
}

const _DEFAULT_HEADERS: Record<string, string> = {
  "User-Agent": _tnUserAgent(),
};

/**
 * Parsed bearer payload. `seed` is the 32-byte Ed25519 seed; `keyIdB64`
 * is the URL-safe-no-pad base64 string (used verbatim in the sealed-
 * bundle GET URL so the server's lookup matches its stored encoding);
 * `keyIdBytes` is the decoded 16-byte key id (returned for callers that
 * want it but currently unused).
 */
export interface ParsedBearer {
  seed: Uint8Array;
  keyIdB64: string;
  keyIdBytes: Uint8Array;
}

/**
 * Split `tn_apikey_<seed_43chars>_<key_id_22chars>` into raw bytes.
 * Returns `null` on shape failure. Length-pinned: seed_b64 is exactly
 * 43 chars (32 bytes URL-safe-no-pad), key_id_b64 is exactly 22 chars
 * (16 bytes URL-safe-no-pad).
 *
 * Mirrors python/tn/bootstrap.py:_parse_bearer line-for-line.
 */
export function parseBearer(bearer: string): ParsedBearer | null {
  if (typeof bearer !== "string" || !bearer.startsWith(_BEARER_PREFIX)) return null;
  const rest = bearer.slice(_BEARER_PREFIX.length);
  // seed_b64 IS urlsafe base64 (no padding) of 32 bytes — exactly 43
  // chars, can contain "_" or "-". So splitting on the LAST "_" is
  // wrong; pin by length. seed_b64 must be 43 chars, then "_", then
  // key_id_b64 (22 chars from 16 raw bytes).
  const SEED_LEN = 43;
  const KEY_ID_LEN = 22;
  const expectedTotal = SEED_LEN + 1 + KEY_ID_LEN;
  if (rest.length !== expectedTotal || rest[SEED_LEN] !== "_") return null;
  const seedB64 = rest.slice(0, SEED_LEN);
  const kidB64 = rest.slice(SEED_LEN + 1);
  if (!seedB64 || !kidB64) return null;
  try {
    const seed = _b64UrlNoPad(seedB64);
    const kid = _b64UrlNoPad(kidB64);
    if (seed.length !== 32 || kid.length !== 16) return null;
    return { seed, keyIdB64: kidB64, keyIdBytes: kid };
  } catch {
    return null;
  }
}

/** URL-safe base64 (no padding) decode. */
function _b64UrlNoPad(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  // Node Buffer accepts urlsafe via "base64url"; do that explicitly so
  // we don't rely on the standard b64 decoder being lenient about "-_".
  return new Uint8Array(Buffer.from(s + pad, "base64url"));
}

interface HttpResult {
  status: number;
  body: Uint8Array;
}

async function _httpPost(
  url: string,
  body: Uint8Array,
  headers?: Record<string, string>,
): Promise<HttpResult> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), _HTTP_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ..._DEFAULT_HEADERS,
        ...(headers ?? {}),
      },
      body,
      signal: ac.signal,
    });
    const bodyBytes = new Uint8Array(await resp.arrayBuffer());
    return { status: resp.status, body: bodyBytes };
  } finally {
    clearTimeout(timer);
  }
}

async function _httpGet(
  url: string,
  headers?: Record<string, string>,
): Promise<HttpResult> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), _HTTP_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      method: "GET",
      headers: {
        ..._DEFAULT_HEADERS,
        ...(headers ?? {}),
      },
      signal: ac.signal,
    });
    const bodyBytes = new Uint8Array(await resp.arrayBuffer());
    return { status: resp.status, body: bodyBytes };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run /auth/challenge + /auth/verify against `base`, return JWT on
 * success or `null` on any failure path.
 *
 * Mirrors python/tn/bootstrap.py:_challenge_verify.
 */
export async function challengeVerify(
  base: string,
  did: string,
  seed: Uint8Array,
): Promise<string | null> {
  // 1. POST /api/v1/auth/challenge { did } -> { nonce }
  const chPayload = new TextEncoder().encode(JSON.stringify({ did }));
  let ch: HttpResult;
  try {
    ch = await _httpPost(`${base}/api/v1/auth/challenge`, chPayload);
  } catch (err) {
    console.warn(
      `bootstrap: /auth/challenge threw (${(err as Error).message ?? String(err)})`,
    );
    return null;
  }
  if (ch.status !== 200) {
    console.warn(
      `bootstrap: /auth/challenge failed HTTP ${ch.status}: ` +
        `${new TextDecoder().decode(ch.body.subarray(0, 200))}`,
    );
    return null;
  }
  let nonce: string;
  try {
    const doc = JSON.parse(new TextDecoder().decode(ch.body)) as { nonce?: string };
    if (typeof doc.nonce !== "string") {
      console.warn("bootstrap: /auth/challenge response missing nonce");
      return null;
    }
    nonce = doc.nonce;
  } catch (err) {
    console.warn(
      `bootstrap: /auth/challenge response malformed: ${(err as Error).message ?? String(err)}`,
    );
    return null;
  }

  // 2. Sign nonce, POST /api/v1/auth/verify { did, nonce, signature } -> { token }
  const nonceBytes = new TextEncoder().encode(nonce);
  const dk = DeviceKey.fromSeed(seed);
  const sigBytes = dk.sign(nonceBytes);
  const sigB64 = signatureB64(sigBytes);

  const vrPayload = new TextEncoder().encode(
    JSON.stringify({ did, nonce, signature: sigB64 }),
  );
  let vr: HttpResult;
  try {
    vr = await _httpPost(`${base}/api/v1/auth/verify`, vrPayload);
  } catch (err) {
    console.warn(
      `bootstrap: /auth/verify threw (${(err as Error).message ?? String(err)})`,
    );
    return null;
  }
  if (vr.status !== 200) {
    console.warn(
      `bootstrap: /auth/verify failed HTTP ${vr.status}: ` +
        `${new TextDecoder().decode(vr.body.subarray(0, 200))}`,
    );
    return null;
  }
  try {
    const doc = JSON.parse(new TextDecoder().decode(vr.body)) as { token?: string };
    if (typeof doc.token !== "string") {
      console.warn("bootstrap: /auth/verify response missing token");
      return null;
    }
    return doc.token;
  } catch (err) {
    console.warn(
      `bootstrap: /auth/verify response malformed: ${(err as Error).message ?? String(err)}`,
    );
    return null;
  }
}

/**
 * Result of the full api-key flow: every step from `parseBearer`
 * through the on-disk install. `receipt` is the same shape any other
 * `Tn.absorb` returns — accepted/deduped counts, conflicts, rejection
 * reason (if any).
 */
export interface ApiKeyFetchResult {
  did: string;
  vaultBase: string;
  token: string;
  sealedBytes: Uint8Array;
  /** Optional `kind` field the server reports alongside the bundle
   *  (e.g. "project_seed"). Diagnostic. */
  kind?: string;
  /** The on-disk install receipt. `rejectedReason` populated only on
   *  failure — caller can `if (!result.receipt.rejectedReason)` to gate
   *  follow-on actions like sync-state stamping. */
  receipt: AbsorbReceipt;
}

/**
 * Thrown when the unseal+install bridge isn't available — i.e. the
 * caller is on an older TS SDK that hasn't been rebuilt against the
 * sealed-bundle absorb path. Today's `bootstrapFromApiKey` always
 * completes the install in-process, so this is unreachable on this
 * branch; kept exported for type compatibility with the previous shape.
 *
 * @deprecated Reachable on older branches only; this branch lands the
 * unseal+install integration so the success path returns an
 * `ApiKeyFetchResult` directly.
 */
export class UnsealNotWiredError extends Error {
  readonly result: ApiKeyFetchResult | { sealedBytes: Uint8Array; vaultBase: string; did: string };
  constructor(result: ApiKeyFetchResult | { sealedBytes: Uint8Array; vaultBase: string; did: string }) {
    super(`UnsealNotWiredError (deprecated): unseal+install is now wired in absorbSealedBootstrap.`);
    this.name = "UnsealNotWiredError";
    this.result = result;
  }
}

/**
 * Read $TN_API_KEY from env (if set), run the full cold-start: parse
 * bearer, derive DID, /auth/challenge + /auth/verify, GET sealed
 * bundle, unseal it with the bearer's seed, decrypt the body, install
 * the keystore + yaml at `opts.cwd`. Returns the merged
 * {@link ApiKeyFetchResult} on success, or `null` when there's no env
 * var / parse failure / network failure / vault rejection.
 *
 * Never throws on user / network / vault-rejection failures — these
 * surface as `null` so the caller can fall through to the existing
 * INIT-UPLOAD path.
 *
 * `vaultDid` is the DID of the vault as written in the yaml (typically
 * `did:key:z...` or `did:web:host`). It's resolved to an HTTP base via
 * `resolveDidEndpoint`. `cwd` is the install root for the project_seed
 * absorb (yaml + keystore land under it); defaults to `process.cwd()`.
 *
 * Matches the contract of python/tn/bootstrap.py::bootstrap_from_api_key
 * (returns success / fall-through; never raises).
 */
export async function bootstrapFromApiKey(opts: {
  vaultDid: string;
  apiKey?: string | undefined;
  cwd?: string;
}): Promise<ApiKeyFetchResult | null> {
  const apiKey = opts.apiKey ?? process.env["TN_API_KEY"];
  if (!apiKey) return null;

  const parsed = parseBearer(apiKey);
  if (parsed === null) {
    console.warn("bootstrap: TN_API_KEY shape invalid; falling through");
    return null;
  }

  const dk = DeviceKey.fromSeed(parsed.seed);
  const did = dk.did;

  let base: string;
  try {
    base = await resolveDidEndpoint(opts.vaultDid);
  } catch (err) {
    console.warn(
      `bootstrap: could not resolve vault endpoint for ${opts.vaultDid}: ` +
        `${(err as Error).message ?? String(err)}`,
    );
    return null;
  }

  const token = await challengeVerify(base, did, parsed.seed);
  if (token === null) return null;

  // GET sealed bundle. Server semantics:
  //   200 -> { sealed_bundle_b64, kind, ... }
  //   404 -> single-pickup key already consumed (or never existed)
  //   410 -> revoked
  let gb: HttpResult;
  try {
    gb = await _httpGet(
      `${base}/api/v1/api-keys/${parsed.keyIdB64}/sealed-bundle`,
      { Authorization: `Bearer ${token}` },
    );
  } catch (err) {
    console.warn(
      `bootstrap: sealed-bundle GET threw (${(err as Error).message ?? String(err)})`,
    );
    return null;
  }
  if (gb.status === 410) {
    console.warn("bootstrap: api-key revoked at vault (HTTP 410); falling through");
    return null;
  }
  if (gb.status === 404) {
    console.warn("bootstrap: sealed bundle not found / already consumed (HTTP 404)");
    return null;
  }
  if (gb.status !== 200) {
    console.warn(
      `bootstrap: sealed-bundle GET failed HTTP ${gb.status}: ` +
        `${new TextDecoder().decode(gb.body.subarray(0, 200))}`,
    );
    return null;
  }

  let sealedBytes: Uint8Array;
  let kind: string | undefined;
  try {
    const doc = JSON.parse(new TextDecoder().decode(gb.body)) as {
      sealed_bundle_b64?: string;
      kind?: string;
    };
    if (typeof doc.sealed_bundle_b64 !== "string") {
      console.warn("bootstrap: sealed-bundle response missing sealed_bundle_b64");
      return null;
    }
    sealedBytes = new Uint8Array(Buffer.from(doc.sealed_bundle_b64, "base64"));
    kind = doc.kind;
  } catch (err) {
    console.warn(
      `bootstrap: sealed-bundle response malformed: ${(err as Error).message ?? String(err)}`,
    );
    return null;
  }

  // Unseal + install. The seed both authenticated the /auth/verify and
  // is the recipient seed for the sealed bundle — the wraps inside are
  // addressed to the DID we derived from it. Failure during unseal /
  // body decrypt / on-disk install all surface as a populated
  // receipt.rejectedReason rather than a thrown exception, so callers
  // can route on it the same way they handle any other absorb result.
  let receipt: AbsorbReceipt;
  try {
    receipt = await absorbSealedBootstrap(sealedBytes, {
      seed: parsed.seed,
      ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
    });
  } catch (err) {
    console.warn(
      `bootstrap: absorbSealedBootstrap threw (${(err as Error).message ?? String(err)}); ` +
        `falling through to INIT-UPLOAD`,
    );
    return null;
  }

  if (receipt.rejectedReason) {
    console.warn(`bootstrap: absorb rejected sealed bundle: ${receipt.rejectedReason}`);
    // Still return the result — caller may want to inspect the
    // receipt to decide whether to retry, log, or fall through. The
    // rejectedReason is the signal that the install didn't land.
  }

  return {
    did,
    vaultBase: base,
    token,
    sealedBytes,
    ...(kind !== undefined ? { kind } : {}),
    receipt,
  };
}

// ---------------------------------------------------------------------------
// Wired-in: the unseal+install bridge.
// ---------------------------------------------------------------------------
//
// The success path now calls `absorbSealedBootstrap(sealedBytes,
// {seed, cwd})` from `runtime/absorb_bootstrap.ts`. That function
// reads the tnpkg, picks the recipient wrap whose `recipient_identity`
// matches the seed-derived DID, unseals the BEK with `unsealBekFromWrap`
// (from `core/recipient_seal.ts`), decrypts `body/encrypted.bin` with
// `decryptBodyBlob` (from `core/body_encryption.ts`), and dispatches
// to the existing `_bootstrapProjectSeed` / `_bootstrapIdentitySeed`
// installers. Returns an `AbsorbReceipt` exactly like the rest of the
// absorb surface — `rejectedReason` populated on any failure path.
//
// The `UnsealNotWiredError` class above is retained as a deprecated
// no-op export for type compatibility with callers of older SDK
// versions; it is no longer thrown by this file.
