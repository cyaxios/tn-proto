// TS port of python/tn/sealing.py — legacy per-file AES-256-GCM vault sealing.
//
// The AAD binds the ciphertext to its logical path inside the ceremony:
//
//     aad = `${did}/${ceremonyId}/${fileName}`
//
// so a renamed/relocated blob fails AES-GCM auth on unseal. Wire format (v1),
// JSON with base64url-unpadded fields:
//
//     {"v":1,"nonce":"<12 bytes>","ct":"<ciphertext + 16-byte GCM tag>","aad":"<string>"}
//
// NOTE: Python marks this per-file model DEPRECATED in favour of the
// whole-body BEK model. Ported on explicit request to back the legacy
// `wallet restore --mnemonic` flow; not for new code.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";

export const SEAL_VERSION = 1;
const NONCE_SIZE = 12;
const AES_KEY_SIZE = 32;
const TAG_SIZE = 16;

export class SealingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SealingError";
  }
}

function _b64e(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

function _b64d(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Build the AAD string. Mirrors Python `_make_aad`. */
export function makeAad(did: string, ceremonyId: string, fileName: string): string {
  if (ceremonyId.includes("/") || fileName.includes("/")) {
    throw new Error("ceremonyId and fileName must not contain '/'");
  }
  return `${did}/${ceremonyId}/${fileName}`;
}

/** A sealed blob. `ct` is the AES-GCM ciphertext WITH the 16-byte tag appended
 *  (the Python `cryptography` AESGCM layout). */
export interface SealedBlob {
  v: number;
  nonce: Uint8Array;
  ct: Uint8Array;
  aad: string;
}

/** Serialize to the wire JSON. Mirrors `SealedBlob.to_bytes`. */
export function sealedBlobToBytes(b: SealedBlob): Uint8Array {
  const json = JSON.stringify({ v: b.v, nonce: _b64e(b.nonce), ct: _b64e(b.ct), aad: b.aad });
  return new Uint8Array(Buffer.from(json, "utf8"));
}

/** Parse the wire JSON. Mirrors `SealedBlob.from_bytes`. */
export function sealedBlobFromBytes(data: Uint8Array): SealedBlob {
  let d: Record<string, unknown>;
  try {
    d = JSON.parse(Buffer.from(data).toString("utf8")) as Record<string, unknown>;
  } catch (e) {
    throw new SealingError(`not valid sealed blob JSON: ${(e as Error).message}`);
  }
  const v = Number(d["v"]);
  const nonceRaw = d["nonce"];
  const ctRaw = d["ct"];
  if (typeof nonceRaw !== "string" || typeof ctRaw !== "string" || d["aad"] === undefined) {
    throw new SealingError("malformed sealed blob fields");
  }
  const nonce = _b64d(nonceRaw);
  const ct = _b64d(ctRaw);
  const aad = String(d["aad"]);
  if (v !== SEAL_VERSION) {
    throw new SealingError(`sealed blob version ${v} unsupported (this build expects ${SEAL_VERSION})`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new SealingError(`sealed blob nonce size ${nonce.length} != ${NONCE_SIZE}`);
  }
  return { v, nonce, ct, aad };
}

/** Seal `plaintext` under `wrapKey`, bound to the logical path. Mirrors `_seal`. */
export function seal(
  plaintext: Uint8Array,
  opts: { wrapKey: Uint8Array; did: string; ceremonyId: string; fileName: string },
): SealedBlob {
  if (opts.wrapKey.length !== AES_KEY_SIZE) {
    throw new Error(`wrapKey must be ${AES_KEY_SIZE} bytes (got ${opts.wrapKey.length})`);
  }
  const aad = makeAad(opts.did, opts.ceremonyId, opts.fileName);
  const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(opts.wrapKey), Buffer.from(nonce));
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const ct = new Uint8Array(Buffer.concat([enc, cipher.getAuthTag()]));
  return { v: SEAL_VERSION, nonce, ct, aad };
}

/** Unseal a blob, optionally verifying the AAD matches expected values.
 *  Mirrors `_unseal`. Throws `SealingError` on any failure. */
export function unseal(
  blob: SealedBlob | Uint8Array,
  opts: {
    wrapKey: Uint8Array;
    expectedDid?: string;
    expectedCeremonyId?: string;
    expectedFileName?: string;
  },
): Uint8Array {
  const b = blob instanceof Uint8Array ? sealedBlobFromBytes(blob) : blob;
  if (opts.wrapKey.length !== AES_KEY_SIZE) {
    throw new Error(`wrapKey must be ${AES_KEY_SIZE} bytes (got ${opts.wrapKey.length})`);
  }
  const anyExpected =
    opts.expectedDid !== undefined ||
    opts.expectedCeremonyId !== undefined ||
    opts.expectedFileName !== undefined;
  if (anyExpected) {
    if (
      opts.expectedDid === undefined ||
      opts.expectedCeremonyId === undefined ||
      opts.expectedFileName === undefined
    ) {
      throw new Error("expectedDid/expectedCeremonyId/expectedFileName must be set together or not at all");
    }
    const expectedAad = makeAad(opts.expectedDid, opts.expectedCeremonyId, opts.expectedFileName);
    if (b.aad !== expectedAad) {
      throw new SealingError(`AAD mismatch: blob claims ${JSON.stringify(b.aad)}, expected ${JSON.stringify(expectedAad)}`);
    }
  }
  if (b.ct.length < TAG_SIZE) {
    throw new SealingError(`ciphertext too short (${b.ct.length} bytes; need a ${TAG_SIZE}-byte tag)`);
  }
  const enc = b.ct.subarray(0, b.ct.length - TAG_SIZE);
  const tag = b.ct.subarray(b.ct.length - TAG_SIZE);
  try {
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(opts.wrapKey), Buffer.from(b.nonce));
    decipher.setAAD(Buffer.from(b.aad, "utf8"));
    decipher.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(enc)), decipher.final()]));
  } catch (e) {
    throw new SealingError(`AES-GCM decrypt failed: ${(e as Error).constructor.name}`);
  }
}
