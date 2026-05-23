import {
  deriveDidKey,
  deviceKeyFromSeed,
  generateDeviceKey,
  signMessage,
  signatureB64 as rawSignatureB64,
  signatureFromB64 as rawSignatureFromB64,
  verifyDid,
} from "../raw.js";
import { asDid, type Did, type SignatureB64, asSignatureB64 } from "./types.js";

interface RawDeviceKey {
  seed_b64: string;
  public_key_b64: string;
  did: string;
}

/**
 * Decode a standard-base64 string into raw bytes.
 *
 * Used to decode device-key material from the wasm-bindgen JSON shape
 * (the Rust glue returns seed and public key as standard-base64
 * strings; see `device_key_to_js` in `crypto/tn-wasm/src/lib.rs`).
 *
 * Pure JS + `atob` so the same code path runs in Node and in
 * browsers — we used to call `Buffer.from(s, "base64")` here, which
 * threw `ReferenceError: Buffer is not defined` when the SDK ran
 * inside a browser bundle without a Node polyfill.
 *
 * @param s - standard-base64 string (with or without padding; `atob`
 *   accepts both in practice).
 *
 * @returns The decoded bytes.
 *
 * @remarks
 * Not exported — only `DeviceKey.fromRaw` uses it. Internal to this
 * module.
 *
 * @internal
 */
function _decodeStandardBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Ed25519 device identity. Holds the 32-byte seed and exposes the
 * derived public key + did:key encoding. Signing is delegated to the
 * Rust core via WASM, which guarantees byte-identical output to
 * Python.
 */
export class DeviceKey {
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly did: Did;

  private constructor(seed: Uint8Array, publicKey: Uint8Array, did: Did) {
    this.seed = seed;
    this.publicKey = publicKey;
    this.did = did;
  }

  /** Fresh key from the host's RNG (browser crypto.getRandomValues / Node crypto). */
  static generate(): DeviceKey {
    const raw = generateDeviceKey() as RawDeviceKey;
    return DeviceKey.fromRaw(raw);
  }

  /** Load from a known 32-byte Ed25519 seed. */
  static fromSeed(seed: Uint8Array): DeviceKey {
    if (seed.length !== 32) {
      throw new Error(`seed must be 32 bytes, got ${seed.length}`);
    }
    const raw = deviceKeyFromSeed(seed) as RawDeviceKey;
    return DeviceKey.fromRaw(raw);
  }

  private static fromRaw(raw: RawDeviceKey): DeviceKey {
    const seed = _decodeStandardBase64(raw.seed_b64);
    const pk = _decodeStandardBase64(raw.public_key_b64);
    return new DeviceKey(seed, pk, asDid(raw.did));
  }

  /** Produce a 64-byte Ed25519 signature. */
  sign(message: Uint8Array): Uint8Array {
    return signMessage(this.seed, message);
  }

  /** URL-safe base64 (no padding) encoding of the signature. */
  signB64(message: Uint8Array): SignatureB64 {
    return asSignatureB64(rawSignatureB64(this.sign(message)));
  }
}

/**
 * Derive a `did:key:z…` encoding from a 32-byte Ed25519 public key.
 * Same output as DeviceKey.from(seed).did for the matching seed.
 */
export function didFromPublicKey(publicKey: Uint8Array): Did {
  return asDid(deriveDidKey(publicKey));
}

/**
 * Verify a signature against a did:key identity. Returns false (not an
 * error) for non-Ed25519 DIDs, matching the Rust core policy.
 */
export function verify(did: Did, message: Uint8Array, signature: Uint8Array): boolean {
  return verifyDid(did, message, signature);
}

/** URL-safe base64 (no padding) encoding helper. */
export function signatureB64(sig: Uint8Array): SignatureB64 {
  return asSignatureB64(rawSignatureB64(sig));
}

/** Decode URL-safe-no-padding base64 to a signature byte array. */
export function signatureFromB64(s: SignatureB64 | string): Uint8Array {
  return rawSignatureFromB64(s);
}
