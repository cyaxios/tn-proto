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
 * Result of the network-only portion of the api-key flow. `sealedBytes`
 * is the recipient-wrapped tnpkg the server delivered; turning it into
 * an installed keystore is the unseal+absorb step that hasn't been
 * wired up yet (see {@link UnsealNotWiredError} below and the doc at
 * the bottom of this file).
 */
export interface ApiKeyFetchResult {
  did: string;
  vaultBase: string;
  token: string;
  sealedBytes: Uint8Array;
  /** Optional `kind` field the server reports alongside the bundle
   *  (e.g. "project_seed"). Pure diagnostic; informational only. */
  kind?: string;
}

/**
 * Surface this when the network half of the bootstrap succeeded but the
 * unseal+install bridge in TS isn't yet ported. Caller (handler-builder)
 * should log + fall through to the existing INIT-UPLOAD path so users
 * aren't left with a half-bootstrapped node.
 */
export class UnsealNotWiredError extends Error {
  readonly result: ApiKeyFetchResult;
  constructor(result: ApiKeyFetchResult) {
    super(
      `bootstrap: fetched ${result.sealedBytes.length}-byte sealed bundle from ` +
        `${result.vaultBase} but TS hasn't yet wired the recipient-wrap unseal ` +
        `step in absorbBootstrap. See the doc-comment at the bottom of ` +
        `runtime/bootstrap_api_key.ts for the integration sketch (core/` +
        `recipient_seal.ts has the primitives — unsealBekFromWrap + ` +
        `manifestAadForWrap). Falling through to INIT-UPLOAD path until ` +
        `that bridge lands.`,
    );
    this.name = "UnsealNotWiredError";
    this.result = result;
  }
}

/**
 * Read $TN_API_KEY from env (if set), run the network flow, return the
 * fetched-but-not-yet-absorbed result OR `null` when there's no env
 * var / parse failure / network failure.
 *
 * Never throws on user / network / vault-rejection failures — these
 * surface as `null` so the caller can fall through to other paths.
 * THROWS exactly one kind: {@link UnsealNotWiredError} on the success-
 * path-with-pending-unseal case (so the caller can `instanceof`-route).
 *
 * `vaultDid` is the DID of the vault as written in the yaml (typically
 * `did:key:z...` or `did:web:host`). It's resolved to an HTTP base via
 * `resolveDidEndpoint`.
 */
export async function bootstrapFromApiKey(opts: {
  vaultDid: string;
  apiKey?: string | undefined;
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

  const result: ApiKeyFetchResult = {
    did,
    vaultBase: base,
    token,
    sealedBytes,
    ...(kind !== undefined ? { kind } : {}),
  };

  // Network half succeeded. Surface the bundle to the caller via the
  // pending-unseal exception so a typed catch can route it to either
  // (a) "log + INIT-UPLOAD fallback" today, or (b) a future
  // absorbBootstrapWithSeed call once the bridge lands.
  throw new UnsealNotWiredError(result);
}

// ---------------------------------------------------------------------------
// Follow-up integration sketch — for the next session that lands the
// sealed-bundle unseal+install pipeline.
// ---------------------------------------------------------------------------
//
// The Python flow at python/tn/bootstrap.py:336-388 does this:
//
//   1. Build a synthetic LoadedConfig with the API-key seed as the
//      device key. Empty everything else.
//   2. _absorb_dispatch(cfg, sealed_bytes) — routes by manifest.kind.
//   3. For kind="project_seed", _absorb_project_seed is called. That
//      function checks for manifest.state.body_encryption.recipient_wraps,
//      uses _maybe_unseal_recipient_wrap to recover the BEK using
//      cfg.device.private_bytes, decrypts the body with the BEK, then
//      installs the unsealed body/keys/local.private + body/tn.yaml.
//
// To port:
//   * Extend `src/runtime/absorb_bootstrap.ts::_bootstrapProjectSeed`
//     so it checks for `manifest.state.body_encryption.recipient_wraps`,
//     and if present:
//       - walks each wrap calling `unsealBekFromWrap(wrap, seed, aad)`
//         from `src/core/recipient_seal.ts`. The first one that
//         doesn't throw `UnsealError` is ours.
//       - decrypt body with the BEK (probably AES-GCM with a body-
//         level nonce; check `state.body_encryption.body_nonce_b64`
//         and Python's symmetric_decrypt_body in tnpkg or absorb).
//       - swap `body` for the decrypted map and continue down the
//         existing unsealed-body code path.
//   * Add a top-level `absorbBootstrapWithSeed(sealed, {seed, cwd})`
//     that takes the seed via opt instead of fishing it out of a cfg.
//     Internal — used by this module only.
//   * Replace the throw of `UnsealNotWiredError` here with:
//       const receipt = absorbBootstrapWithSeed(sealedBytes, {
//         seed: parsed.seed,
//         cwd,
//       });
//       if (receipt.rejectedReason) return null;
//       return result;
//
// The handler-builder caller (the function that today calls
// `bootstrapFromApiKey`) wraps the call in a try/catch on
// UnsealNotWiredError and treats it as "fetched but not installed —
// log, fall through to INIT-UPLOAD". When the bridge lands, the catch
// is unreachable and the success path returns a non-null result.
