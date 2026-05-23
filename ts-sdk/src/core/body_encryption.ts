// AES-256-GCM body encryption for sealed tnpkg bundles.
//
// Mirrors python/tn/export.py:_encrypt_body_in_place + decrypt_body_blob
// byte-for-byte. Same frame, same nonce length, same outer "STORED zip
// of body files" plaintext. A bundle produced by Python decrypts here,
// and vice versa.
//
// Wire layout:
//
//   body/encrypted.bin = 12-byte AES-GCM nonce || ciphertext+tag
//
// Plaintext (inside the AEAD): a STORED zip of the body members at
// their original `body/<name>` keys, entries sorted by name so the
// plaintext bytes are deterministic for a given body (test-friendly
// and lets producers compare ciphertext hashes across implementations).
//
// AAD on the body AEAD is empty — the manifest's `ciphertext_sha256`
// hash, recorded in `state.body_encryption`, provides the integrity
// binding (the manifest itself is signed).

import { packTnpkg, parseTnpkg, type ZipEntry } from "./tnpkg_archive.js";

/** Cipher-suite identifier the manifest carries.
 *  Matches python/tn/export.py:_encrypt_body_in_place. */
export const BODY_CIPHER_SUITE = "aes-256-gcm";

/** Frame identifier baked into manifest.state.body_encryption.frame. */
export const BODY_FRAME = "tn-encrypted-body-v2-zip";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Pack `body` into a STORED zip and AES-GCM-encrypt it under `key`.
 *
 * `body` keys arrive as `body/<name>` (the same shape the outer tnpkg
 * uses); entries are sorted by name to keep the plaintext deterministic.
 *
 * Returns the bytes that should live at the outer tnpkg's
 * `body/encrypted.bin` slot.
 *
 * Mirror of `_encrypt_body_in_place` in python/tn/export.py.
 */
export async function encryptBodyBlob(
  body: Map<string, Uint8Array> | Record<string, Uint8Array>,
  key: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`encryptBodyBlob: key must be 32 bytes (AES-256); got ${key.length}`);
  }

  // Pack into a STORED zip, entries sorted by name for determinism.
  const entries: ZipEntry[] = [];
  const map: Map<string, Uint8Array> =
    body instanceof Map ? body : new Map(Object.entries(body));
  const names = [...map.keys()].sort();
  for (const name of names) {
    const data = map.get(name);
    if (data === undefined) continue;
    entries.push({ name, data });
  }
  const plaintext = packTnpkg(entries);

  // 12-byte nonce + AES-GCM encrypt, no AAD.
  const nonce = new Uint8Array(NONCE_BYTES);
  globalThis.crypto.getRandomValues(nonce);
  const k = await globalThis.crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      k,
      plaintext,
    ),
  );

  // Wire format: nonce || ciphertext+tag.
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

/**
 * Inverse of `encryptBodyBlob`. Returns a `{name: bytes}` map keyed by
 * the same `body/<name>` shape the producer started with.
 *
 * Mirror of `decrypt_body_blob` in python/tn/export.py.
 *
 * Throws on:
 *   * Input shorter than `NONCE_BYTES + TAG_BYTES` (12 + 16).
 *   * AES-GCM tag check failure (bad key, tampered ciphertext).
 *   * Inner-zip parse failure.
 *
 * Does NOT honor Python's legacy-binary-frame fallback — that branch
 * was for pre-2026-04-29 ciphertexts only and is documented in Python
 * as "drop after next state wipe." TS never produced the legacy frame,
 * so we never have to read it.
 */
export async function decryptBodyBlob(
  blob: Uint8Array,
  key: Uint8Array,
): Promise<Map<string, Uint8Array>> {
  if (key.length !== 32) {
    throw new Error(`decryptBodyBlob: key must be 32 bytes (AES-256); got ${key.length}`);
  }
  if (blob.length < NONCE_BYTES + TAG_BYTES) {
    throw new Error(
      `decryptBodyBlob: input too short (${blob.length} bytes; need at least ${NONCE_BYTES + TAG_BYTES})`,
    );
  }

  const nonce = blob.subarray(0, NONCE_BYTES);
  const ciphertext = blob.subarray(NONCE_BYTES);

  const k = await globalThis.crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        k,
        ciphertext,
      ),
    );
  } catch (err) {
    throw new Error(
      `decryptBodyBlob: AES-GCM decrypt failed (wrong key or tampered ciphertext): ${
        (err as Error).message ?? String(err)
      }`,
    );
  }

  // Verify the STORED-zip magic. Python's decrypt accepts a legacy
  // binary frame as a fallback; TS never produced it, so a non-PK
  // plaintext is just an error here.
  if (
    plaintext.length < 4 ||
    plaintext[0] !== 0x50 ||
    plaintext[1] !== 0x4b ||
    plaintext[2] !== 0x03 ||
    plaintext[3] !== 0x04
  ) {
    throw new Error(
      "decryptBodyBlob: plaintext is not a STORED zip (no PK\\x03\\x04 magic). " +
        "Pre-2026-04-29 legacy binary frame is not supported on the TS side.",
    );
  }

  const out = new Map<string, Uint8Array>();
  for (const entry of parseTnpkg(plaintext)) {
    out.set(entry.name, entry.data);
  }
  return out;
}
