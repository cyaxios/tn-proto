// Sealed-box recipient wrap over Ed25519 device keys.
//
// Browser-safe port of `tn_proto/python/tn/recipient_seal.py`. The
// scheme matches byte-for-byte:
//
//   * Ed25519 -> X25519 conversion via libsodium's birational map
//     (here: @noble/curves' `edwardsToMontgomery*` helpers, which
//     implement the same map). Used so a recipient's only existing
//     asymmetric key (the `did:key:z...` Ed25519 device key) becomes
//     a usable X25519 key.
//   * Ephemeral X25519 keypair on the producer side; ECDH against the
//     recipient's converted public key.
//   * HKDF-SHA256 with salt = ephemeral_pub || recipient_x_pub and
//     info = utf8("tn-kit-seal-v1"). Length 32.
//   * AES-256-GCM with the derived key, a 12-byte nonce, and AAD =
//     canonical bytes of the manifest with manifest_signature_b64,
//     state.body_encryption.recipient_wrap, and
//     state.body_encryption.recipient_wraps removed.
//
// The wrap output dict has the exact same keys (and base64 padding
// shape) as Python's so a wrap produced here unseals via Python and
// vice versa.
//
// Layer 1: no node:* imports. AES-GCM goes through globalThis.crypto
// (Web Crypto API; Node 20+ ships it as a global). HKDF goes through
// @noble/hashes/hkdf. Curve ops go through @noble/curves.

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from "@noble/curves/ed25519";

import { canonicalize } from "./canonical.js";
import { bytesToB64, b64ToBytes, randomBytes } from "./encoding.js";
import { parseEd25519DidKey } from "./trust.js";

export const WRAP_FRAME = "tn-sealed-box-v1";
const WRAP_HKDF_INFO = new TextEncoder().encode("tn-kit-seal-v1");

// ── Errors ──────────────────────────────────────────────────────────

/** Raised on any failure path of {@link unsealBekFromWrap} — bad
 * frame, bad recipient_identity, AEAD auth failure, malformed base64,
 * wrong-length fields, etc. Callers that walk a `recipient_wraps[]`
 * array catch this per-entry and try the next one. */
export class UnsealError extends Error {
  override name = "UnsealError";
}

// ── DID + curve helpers ─────────────────────────────────────────────

/** Decode a `did:key:z...` Ed25519 identity to its 32-byte public key.
 *
 * Delegates to the strict decoder in `core/trust.ts` — the single TS
 * base58btc/did:key implementation — so the sealed-box path accepts exactly
 * the same identities as the trusted-enrollment ceremonies (canonical
 * base58btc, Ed25519 multicodec, exactly 32 key bytes). Still pure JS, so it
 * works before wasm initializes. Throws (a `TrustError`, which is an
 * `Error`) on non-key DIDs, non-Ed25519 multicodecs, or bad lengths. */
export function didKeyToEd25519Pub(did: string): Uint8Array {
  return parseEd25519DidKey(did);
}

function ed25519PubToX25519Pub(edPub: Uint8Array): Uint8Array {
  if (edPub.length !== 32) {
    throw new Error(`ed25519PubToX25519Pub: expected 32-byte pub, got ${edPub.length}`);
  }
  return edwardsToMontgomeryPub(edPub);
}

function ed25519SeedToX25519Priv(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new Error(`ed25519SeedToX25519Priv: expected 32-byte seed, got ${seed.length}`);
  }
  // @noble/curves' edwardsToMontgomeryPriv takes the 32-byte seed (the
  // ed25519 private "scalar"). It internally hashes the seed per the
  // EdDSA spec and returns the resulting X25519 private scalar — same
  // output as libsodium's crypto_sign_ed25519_sk_to_curve25519 over the
  // 64-byte expanded secret key.
  return edwardsToMontgomeryPriv(seed);
}

// ── AAD: manifest minus signature minus recipient_wrap[s] ───────────

interface JsonObject {
  [key: string]: unknown;
}

function deepCopyPlainJson<T>(v: T): T {
  // Round-trip through JSON. The producer/consumer paths only ever
  // hand us plain JSON-shaped data (number/string/bool/null/array/
  // object), so this is safe and matches Python's
  // `json.loads(json.dumps(...))` deep copy.
  return JSON.parse(JSON.stringify(v)) as T;
}

/** Compute the AES-GCM AAD that binds a recipient_wrap to its
 * manifest. Strips:
 *
 *   - manifest_signature_b64 (signature is set after the wrap; can't
 *     be in AAD).
 *   - state.body_encryption.recipient_wrap (singular shadow).
 *   - state.body_encryption.recipient_wraps (plural array).
 *
 * Each entry in recipient_wraps[] binds against the same AAD; the
 * holder of any single matching key recovers the BEK independently.
 */
export function manifestAadForWrap(manifest: JsonObject): Uint8Array {
  const m = deepCopyPlainJson(manifest);
  delete (m as JsonObject).manifest_signature_b64;
  const state = (m as JsonObject).state;
  if (state && typeof state === "object" && !Array.isArray(state)) {
    const be = (state as JsonObject).body_encryption;
    if (be && typeof be === "object" && !Array.isArray(be)) {
      delete (be as JsonObject).recipient_wrap;
      delete (be as JsonObject).recipient_wraps;
    }
  }
  return canonicalize(m);
}

// ── AES-GCM via WebCrypto ───────────────────────────────────────────

async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const k = await globalThis.crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const ct = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad },
    k,
    plaintext,
  );
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const k = await globalThis.crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const pt = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad },
    k,
    ciphertext,
  );
  return new Uint8Array(pt);
}

// ── Wrap / unwrap ───────────────────────────────────────────────────

/** Wire shape of a single recipient wrap. Lives in
 * `manifest.state.body_encryption.recipient_wrap` (singular shadow when
 * len === 1) or as one entry of
 * `manifest.state.body_encryption.recipient_wraps[]`. */
export interface RecipientWrap {
  frame: string;
  recipient_identity: string;
  ephemeral_x25519_pub_b64: string;
  wrap_nonce_b64: string;
  wrapped_bek_b64: string;
}

/** Wrap `bek` so only `recipientDid`'s holder can recover it. The
 * returned object is suitable for embedding directly into the
 * manifest's recipient-wrap slot. */
export async function sealBekForRecipient(
  bek: Uint8Array,
  recipientDid: string,
  aad: Uint8Array,
): Promise<RecipientWrap> {
  if (bek.length !== 32) {
    throw new Error(`sealBekForRecipient: BEK must be 32 bytes; got ${bek.length}`);
  }

  const recipientEdPub = didKeyToEd25519Pub(recipientDid);
  const recipientXPub = ed25519PubToX25519Pub(recipientEdPub);

  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);

  const shared = x25519.getSharedSecret(ephPriv, recipientXPub);

  const salt = new Uint8Array(ephPub.length + recipientXPub.length);
  salt.set(ephPub, 0);
  salt.set(recipientXPub, ephPub.length);

  const key = hkdf(sha256, shared, salt, WRAP_HKDF_INFO, 32);

  const nonce = randomBytes(12);
  const wrapped = await aesGcmEncrypt(key, nonce, bek, aad);

  return {
    frame: WRAP_FRAME,
    recipient_identity: recipientDid,
    ephemeral_x25519_pub_b64: bytesToB64(ephPub),
    wrap_nonce_b64: bytesToB64(nonce),
    wrapped_bek_b64: bytesToB64(wrapped),
  };
}

/** Result shape from {@link buildRecipientWraps}. The caller embeds
 * `manifest` into the final tnpkg (after signing it), uses `aad` only
 * for debug / cross-language verification, and gets `wraps` separately
 * so it can attach them somewhere other than `state.body_encryption`
 * if a future kind needs that. */
export interface BuildRecipientWrapsResult {
  manifest: JsonObject;
  aad: Uint8Array;
  wraps: RecipientWrap[];
}

/** Build the producer-side multi-recipient wrap set for a manifest.
 *
 * Mirrors the fanout block in `tn_proto/python/tn/export.py`:
 *
 *   * Dedupes `recipientDids` while preserving first-seen order.
 *   * Sets `manifest.recipient_identity` to the first DID (arbitrary but
 *     deterministic; matches the preview AAD).
 *   * Computes AAD via {@link manifestAadForWrap}.
 *   * Seals the BEK once per DID, all bound against the same AAD.
 *   * Writes the plural `state.body_encryption.recipient_wraps[]`
 *     array unconditionally; ALSO writes the singular
 *     `state.body_encryption.recipient_wrap` shadow when there's
 *     exactly one entry, so consumers on older absorbers keep working.
 *
 * The returned `manifest` is a structured clone of the input — the
 * caller's manifest is not mutated.
 */
export async function buildRecipientWraps(
  bek: Uint8Array,
  recipientDids: readonly string[],
  manifestSkeleton: JsonObject,
): Promise<BuildRecipientWrapsResult> {
  if (bek.length !== 32) {
    throw new Error(`buildRecipientWraps: BEK must be 32 bytes; got ${bek.length}`);
  }
  if (!recipientDids || recipientDids.length === 0) {
    throw new Error("buildRecipientWraps: at least one recipient DID required");
  }
  // Dedupe while preserving first-seen order; validate each is a
  // did:key string (sealBekForRecipient enforces the multicodec).
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const d of recipientDids) {
    if (typeof d !== "string" || !d.startsWith("did:key:z")) {
      throw new Error(`buildRecipientWraps: ${JSON.stringify(d)} is not a did:key string`);
    }
    if (seen.has(d)) continue;
    seen.add(d);
    merged.push(d);
  }
  if (merged.length === 0) {
    // Defensive — would only fire if the input was empty after dedupe,
    // which the length check above already rejects. Keep it for symmetry
    // with the Python error path.
    throw new Error("buildRecipientWraps: no valid recipient DIDs after dedupe");
  }

  // Manifest is mutated locally; never touch the caller's copy.
  const manifest = deepCopyPlainJson(manifestSkeleton);
  manifest.recipient_identity = merged[0];

  const aad = manifestAadForWrap(manifest);

  const wraps: RecipientWrap[] = [];
  for (const did of merged) {
    wraps.push(await sealBekForRecipient(bek, did, aad));
  }

  // Inject into state.body_encryption. Create the path if absent.
  const state =
    manifest.state && typeof manifest.state === "object" && !Array.isArray(manifest.state)
      ? (manifest.state as JsonObject)
      : ({} as JsonObject);
  const bodyEnc =
    state.body_encryption && typeof state.body_encryption === "object" && !Array.isArray(state.body_encryption)
      ? (state.body_encryption as JsonObject)
      : ({} as JsonObject);
  bodyEnc.recipient_wraps = wraps;
  if (wraps.length === 1) {
    bodyEnc.recipient_wrap = wraps[0];
  }
  state.body_encryption = bodyEnc;
  manifest.state = state;

  return { manifest, aad, wraps };
}

/** Recover the BEK from a recipient_wrap. `devicePrivSeed` is the
 * 32-byte Ed25519 seed (same bytes the runtime stores in
 * `<keystore>/local.private`). Throws {@link UnsealError} on any
 * failure — wrap caller decides whether to treat that as "outsider"
 * (try the next entry) or "decrypt error" (surface to user). */
export async function unsealBekFromWrap(
  wrap: RecipientWrap | unknown,
  devicePrivSeed: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (!wrap || typeof wrap !== "object") {
    throw new UnsealError(`recipient_wrap is not an object: ${typeof wrap}`);
  }
  const w = wrap as Partial<RecipientWrap>;
  if (w.frame !== WRAP_FRAME) {
    throw new UnsealError(`unsupported sealed-box frame ${JSON.stringify(w.frame)}; expected ${WRAP_FRAME}`);
  }
  if (typeof w.recipient_identity !== "string") {
    throw new UnsealError("recipient_wrap.recipient_identity missing or not a string");
  }

  let ephPub: Uint8Array;
  let nonce: Uint8Array;
  let wrapped: Uint8Array;
  try {
    ephPub = b64ToBytes(w.ephemeral_x25519_pub_b64 ?? "");
    nonce = b64ToBytes(w.wrap_nonce_b64 ?? "");
    wrapped = b64ToBytes(w.wrapped_bek_b64 ?? "");
  } catch (e) {
    throw new UnsealError(`recipient_wrap fields malformed: ${(e as Error).message}`);
  }

  if (ephPub.length !== 32) {
    throw new UnsealError(`ephemeral_x25519_pub_b64 decoded to ${ephPub.length} bytes; expected 32`);
  }
  if (nonce.length !== 12) {
    throw new UnsealError(`wrap_nonce_b64 decoded to ${nonce.length} bytes; expected 12`);
  }

  let xPriv: Uint8Array;
  try {
    xPriv = ed25519SeedToX25519Priv(devicePrivSeed);
  } catch (e) {
    throw new UnsealError(`could not derive X25519 priv from device seed: ${(e as Error).message}`);
  }

  // Recipient's X25519 PUBLIC key is derived from the wrap's recipient_identity
  // (NOT from the device seed). Defends against a malicious wrap that names
  // a different DID than the device holds.
  let recipientXPub: Uint8Array;
  try {
    const edPub = didKeyToEd25519Pub(w.recipient_identity);
    recipientXPub = ed25519PubToX25519Pub(edPub);
  } catch (e) {
    throw new UnsealError(`could not derive recipient X25519 pub: ${(e as Error).message}`);
  }

  const shared = x25519.getSharedSecret(xPriv, ephPub);
  const salt = new Uint8Array(ephPub.length + recipientXPub.length);
  salt.set(ephPub, 0);
  salt.set(recipientXPub, ephPub.length);
  const key = hkdf(sha256, shared, salt, WRAP_HKDF_INFO, 32);

  let bek: Uint8Array;
  try {
    bek = await aesGcmDecrypt(key, nonce, wrapped, aad);
  } catch (e) {
    throw new UnsealError(`sealed-box decrypt failed: ${(e as Error).message}`);
  }
  if (bek.length !== 32) {
    throw new UnsealError(`recovered BEK is not 32 bytes (got ${bek.length})`);
  }
  return bek;
}
