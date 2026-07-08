/**
 * Cold-start keystore bootstrap from a `TN_API_KEY` bearer.
 *
 * TS port of `python/tn/bootstrap.py`. Mirrors the flow on a fresh node
 * that has only `$TN_API_KEY` in env:
 *
 * 1. Caller has an empty keystore + a yaml that declares `vault.sync`.
 * 2. The handler-builder spots the empty keystore + the env var and
 *    calls {@link bootstrapFromApiKey} BEFORE constructing the
 *    `vault.sync` handler (which would otherwise raise on a missing
 *    `local.private`).
 * 3. We split the bearer into seed + key_id, derive the DID, run the
 *    standard `/api/v1/auth/{challenge,verify}` flow to mint a JWT,
 *    pull the sealed kit_bundle via
 *    `/api/v1/api-keys/{key_id}/sealed-bundle`, and hand the bytes to
 *    {@link absorbSealedBootstrap}, which unseals the recipient wrap
 *    with the bearer's seed and installs the project_seed body.
 * 4. The keystore is now hot — `local.private`, `local.public`, and a
 *    fresh `tn.yaml` live under the keystore dir.
 *
 * **Failure contract:** never throws. A stale / revoked / consumed
 * bearer leaves the keystore in whatever state it was in (typically
 * still empty), and the function returns `null` so the caller can
 * fall through to the existing INIT-UPLOAD-and-claim-URL path. The
 * only case that surfaces a populated {@link ApiKeyFetchResult} with
 * a `receipt.rejectedReason` is when every network step succeeded but
 * the absorb step rejected (e.g. malformed sealed bundle).
 *
 * This module is internal — there is no public
 * `Tn.bootstrapFromApiKey` symbol. The handler-builder is the only
 * caller; users discover the feature by setting `TN_API_KEY`.
 *
 * @packageDocumentation
 */

import { Buffer } from "node:buffer";
import { USER_AGENT } from "../version.js";

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
  // Shared SDK identifier (src/version.ts) — `tn-proto-ts/<version>`,
  // matching Python's dynamic `tn-proto/<version>`.
  return USER_AGENT;
}

const _DEFAULT_HEADERS: Record<string, string> = {
  "User-Agent": _tnUserAgent(),
};

/**
 * Parsed bearer payload returned by {@link parseBearer}.
 *
 * @public
 */
export interface ParsedBearer {
  /**
   * 32-byte Ed25519 seed. Pass to {@link DeviceKey.fromSeed} to derive
   * the bearer's DID, or to {@link absorbSealedBootstrap} as the
   * recipient seed for unsealing a sealed `.tnpkg`.
   */
  seed: Uint8Array;
  /**
   * URL-safe-no-pad base64 of the 16-byte key id (22 chars). Used
   * verbatim in the sealed-bundle GET URL — the server stores keys
   * under this exact encoding, so any re-encoding would miss.
   */
  keyIdB64: string;
  /**
   * Decoded 16-byte key id. Returned for callers that want it; the
   * bootstrap flow itself uses `keyIdB64`.
   */
  keyIdBytes: Uint8Array;
}

/**
 * Split a `tn_apikey_<seed_43chars>_<key_id_22chars>` bearer string
 * into its raw byte components.
 *
 * Length-pinned by design: the bearer is exactly
 * `len("tn_apikey_") + 43 + 1 + 22 = 76` characters. Splitting on the
 * last `_` would be wrong because the seed's URL-safe-no-pad base64
 * can legitimately contain `_` or `-`; we pin the split by length.
 *
 * @param bearer - the raw bearer string from `$TN_API_KEY` or an
 *   equivalent caller-supplied source.
 *
 * @returns The {@link ParsedBearer} on success, or `null` on shape
 *   failure (wrong prefix, wrong length, non-base64 chars, decoded
 *   lengths off). Never throws.
 *
 * @example
 * ```ts
 * import { parseBearer } from "tn-proto";
 *
 * const parsed = parseBearer(process.env.TN_API_KEY ?? "");
 * if (parsed === null) {
 *   console.warn("malformed TN_API_KEY");
 * } else {
 *   const did = DeviceKey.fromSeed(parsed.seed).did;
 * }
 * ```
 *
 * @see {@link bootstrapFromApiKey} - the full cold-start flow that
 *   uses this internally.
 *
 * @remarks
 * Mirrors `python/tn/bootstrap.py::_parse_bearer` line-for-line.
 *
 * @public
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
 * Run the vault's `/auth/challenge` + `/auth/verify` flow.
 *
 * 1. POST `/api/v1/auth/challenge` with `{did}` to get a nonce.
 * 2. Ed25519-sign the nonce with `seed`.
 * 3. POST `/api/v1/auth/verify` with `{did, nonce, signature}` to get
 *    a JWT.
 *
 * @param base - vault base URL. Typically resolved via
 *   {@link resolveDidEndpoint}.
 * @param did - the DID derived from `seed`. The vault echoes this
 *   back; mismatch would fail the verify step.
 * @param seed - 32-byte Ed25519 seed corresponding to `did`. Used
 *   to sign the nonce.
 *
 * @returns The JWT on success, or `null` on any failure (network
 *   error, non-200 response, malformed JSON, missing nonce/token).
 *   Never throws — every failure path logs at WARN and returns null.
 *
 * @example
 * ```ts
 * import { challengeVerify, resolveDidEndpoint, parseBearer } from "tn-proto";
 * import { DeviceKey } from "tn-proto";
 *
 * const parsed = parseBearer(process.env.TN_API_KEY!);
 * if (!parsed) throw new Error("bad bearer");
 * const did = DeviceKey.fromSeed(parsed.seed).did;
 * const base = await resolveDidEndpoint("did:web:vault.example.com");
 * const jwt = await challengeVerify(base, did, parsed.seed);
 * // jwt -> use as `Authorization: Bearer <jwt>` for subsequent requests
 * ```
 *
 * @see {@link bootstrapFromApiKey} - the full cold-start flow that
 *   uses this internally.
 *
 * @remarks
 * Mirrors `python/tn/bootstrap.py::_challenge_verify`. Uses the
 * self-identifying `tn-proto-ts/<version>` User-Agent so the Cloudflare
 * edge doesn't 1010-block the request.
 *
 * @public
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
 * Result of a successful (or post-install-rejected) {@link bootstrapFromApiKey}
 * call.
 *
 * Every step from {@link parseBearer} through the on-disk install
 * succeeded enough to produce a result. `receipt.rejectedReason`
 * populated when the bundle was fetched but the absorb step refused
 * to install — typically because the bundle was malformed or addressed
 * to a different DID.
 *
 * @public
 */
export interface ApiKeyFetchResult {
  /** The DID derived from the bearer's seed. Matches the wrap's
   *  intended recipient on a healthy round-trip. */
  did: string;
  /** Resolved vault base URL — what `resolveDidEndpoint(opts.vaultDid)`
   *  returned. Useful for diagnostic logs. */
  vaultBase: string;
  /** JWT the vault minted for the bearer's DID. Caller is free to
   *  reuse this for follow-up vault calls if it wants to. */
  token: string;
  /** Raw bytes of the sealed `.tnpkg` the vault delivered. Kept for
   *  diagnostics; the install was already attempted via
   *  {@link absorbSealedBootstrap}. */
  sealedBytes: Uint8Array;
  /** Optional `kind` the vault reports alongside the bundle (e.g.
   *  `"project_seed"`). Pure diagnostic. */
  kind?: string;
  /**
   * On-disk install receipt. `rejectedReason` is populated only when
   * the unseal/decrypt/install step refused; consumers can do
   * `if (!result.receipt.rejectedReason)` to gate follow-on actions
   * like sync-state stamping.
   */
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
 * Run the full cold-start from a `TN_API_KEY` bearer.
 *
 * 1. Read `TN_API_KEY` from env (or accept `opts.apiKey` for explicit
 *    callers — tests, CLIs).
 * 2. {@link parseBearer} — split the bearer into seed + key id.
 * 3. {@link DeviceKey.fromSeed} — derive the bearer's DID.
 * 4. {@link resolveDidEndpoint} — find the vault HTTP base from
 *    `opts.vaultDid`.
 * 5. {@link challengeVerify} — Ed25519-sign the challenge nonce, mint
 *    a JWT.
 * 6. GET `/api/v1/api-keys/{key_id_b64}/sealed-bundle` with the JWT —
 *    pull the recipient-sealed `.tnpkg`.
 * 7. {@link absorbSealedBootstrap} — unseal the BEK with the bearer's
 *    seed, decrypt the body, install the keystore + yaml at
 *    `opts.cwd`.
 *
 * Returns the merged {@link ApiKeyFetchResult} on success (with
 * `receipt.rejectedReason` populated only when step 7 refused), or
 * `null` when any of steps 1–6 fails (no env var, malformed bearer,
 * network failure, vault rejection).
 *
 * @param opts.vaultDid - the DID of the vault as written in the yaml
 *   (typically `did:key:z…` or `did:web:host`). Resolved to an HTTP
 *   base via {@link resolveDidEndpoint}.
 * @param opts.apiKey - explicit bearer. When omitted, reads
 *   `process.env.TN_API_KEY`. Pass explicitly when calling outside the
 *   env-var-driven flow (tests, CLI tools).
 * @param opts.cwd - install root for the project_seed absorb. Defaults
 *   to `process.cwd()`. The yaml and keystore land under it.
 *
 * @returns The {@link ApiKeyFetchResult} on success, or `null` on
 *   fallthrough (caller should try the next bootstrap path). Never
 *   throws on user / network / vault-rejection failures.
 *
 * @example
 * ```ts
 * import { bootstrapFromApiKey } from "tn-proto";
 *
 * const result = await bootstrapFromApiKey({
 *   vaultDid: "did:web:vault.example.com",
 * });
 *
 * if (result === null) {
 *   console.warn("TN_API_KEY missing or vault rejected; falling through");
 * } else if (result.receipt.rejectedReason) {
 *   console.error("sealed bundle install failed:", result.receipt.rejectedReason);
 * } else {
 *   console.log("cold-started keystore from api-key for", result.did);
 * }
 * ```
 *
 * @see {@link parseBearer}
 * @see {@link challengeVerify}
 * @see {@link absorbSealedBootstrap}
 *
 * @remarks
 * Mirrors `python/tn/bootstrap.py::bootstrap_from_api_key`. Same
 * never-throws contract; same `null`-on-failure semantics.
 *
 * @public
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
