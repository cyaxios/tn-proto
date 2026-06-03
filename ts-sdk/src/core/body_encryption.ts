/**
 * AES-256-GCM body encryption for sealed `.tnpkg` bundles.
 *
 * Mirrors `python/tn/export.py::_encrypt_body_in_place` +
 * `decrypt_body_blob` byte-for-byte. A bundle produced by Python
 * decrypts here, and vice versa.
 *
 * ## Wire layout
 *
 * ```text
 * body/encrypted.bin = 12-byte AES-GCM nonce || ciphertext+tag
 * ```
 *
 * The plaintext (inside the AEAD) is a STORED zip of the body members
 * at their original `body/<name>` keys. Entries are sorted by name so
 * the plaintext bytes are deterministic for a given body — test-friendly
 * and lets producers compare ciphertext hashes across implementations.
 *
 * AAD on the body AEAD is empty. The manifest's `ciphertext_sha256`
 * hash (recorded in `state.body_encryption`) provides the integrity
 * binding via the signed manifest.
 *
 * @packageDocumentation
 */

import { unzipSync, zipSync, type Zippable } from "fflate";

/**
 * Cipher-suite identifier recorded in `manifest.state.body_encryption.cipher_suite`.
 * Matches `python/tn/export.py::_encrypt_body_in_place`.
 *
 * @public
 */
export const BODY_CIPHER_SUITE = "aes-256-gcm";

/**
 * Frame identifier recorded in `manifest.state.body_encryption.frame`.
 * Identifies the v2 wire format (STORED-zip plaintext inside AES-GCM).
 *
 * @public
 */
export const BODY_FRAME = "tn-encrypted-body-v2-zip";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const BODY_ZIP_MTIME = new Date(1980, 0, 1, 0, 0, 0);

function validateBodyName(name: string): void {
  if (!name.startsWith("body/") || name === "body/") {
    throw new Error(
      `body encryption: invalid package member ${JSON.stringify(name)}; expected body/...`,
    );
  }
  if (
    name.startsWith("/") ||
    name.includes("\\") ||
    name.split("/").some((p) => p === "" || p === "." || p === "..")
  ) {
    throw new Error(
      `body encryption: invalid package member ${JSON.stringify(name)}; only POSIX relative body paths are allowed`,
    );
  }
}

/**
 * Canonical STORED-ZIP plaintext for sealed `.tnpkg` bodies.
 *
 * Entries are sorted and written through `fflate` as standard STORED ZIP
 * members with a fixed DOS timestamp. The body-encryption frame needs a
 * stock ZIP plaintext that any unzip tool can inspect after BEK recovery;
 * it does not require local ZIP record serialization.
 *
 * @public
 */
export function packBodyPlaintextZip(
  body: Map<string, Uint8Array> | Record<string, Uint8Array>,
): Uint8Array {
  const map: Map<string, Uint8Array> = body instanceof Map ? body : new Map(Object.entries(body));
  const entries: Zippable = {};
  for (const name of [...map.keys()].sort()) {
    validateBodyName(name);
    const data = map.get(name);
    if (data === undefined) continue;
    entries[name] = [data, { level: 0, mtime: BODY_ZIP_MTIME }];
  }
  return zipSync(entries, { level: 0, mtime: BODY_ZIP_MTIME });
}

/**
 * Pack `body` into a STORED zip and AES-GCM-encrypt it under `key`.
 *
 * The keys in `body` arrive as `body/<name>` (matching the outer tnpkg
 * layout); entries are sorted by name to keep the plaintext bytes
 * deterministic across implementations.
 *
 * @param body - the body members to encrypt. Keys are `body/<name>`
 *   logical paths (e.g. `body/keys/local.private`); values are the
 *   raw file bytes. Accepts either a `Map` or a plain object.
 * @param key - 32-byte AES-256 key (the Body Encryption Key, BEK).
 *   Typically supplied by {@link sealBekForRecipient} on the producer
 *   side and recovered by {@link unsealBekFromWrap} on the consumer.
 *
 * @returns The bytes that should be written to the outer tnpkg's
 *   `body/encrypted.bin` slot. Layout: `nonce || ciphertext+tag`.
 *
 * @throws Error - when `key.length !== 32`.
 *
 * @example
 * ```ts
 * import { encryptBodyBlob } from "@tnproto/sdk";
 *
 * const bek = crypto.getRandomValues(new Uint8Array(32));
 * const body = new Map([
 *   ["body/tn.yaml", new TextEncoder().encode("ceremony: ...")],
 *   ["body/keys/local.private", seedBytes],
 * ]);
 *
 * const encrypted = await encryptBodyBlob(body, bek);
 * // encrypted -> the bytes for tnpkg "body/encrypted.bin"
 * ```
 *
 * @see {@link decryptBodyBlob} - the inverse operation.
 * @see {@link BODY_CIPHER_SUITE} / {@link BODY_FRAME} - record these in
 *   the manifest's `state.body_encryption` so the consumer knows what
 *   to invoke.
 * @see [spec/body-encryption](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md) - the wire frame.
 *
 * @remarks
 * Mirrors `python/tn/export.py::_encrypt_body_in_place`. AAD is empty
 * (the manifest's `ciphertext_sha256` provides integrity via the
 * signed manifest, so the AEAD doesn't need to re-bind it).
 *
 * @public
 */
export async function encryptBodyBlob(
  body: Map<string, Uint8Array> | Record<string, Uint8Array>,
  key: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`encryptBodyBlob: key must be 32 bytes (AES-256); got ${key.length}`);
  }

  const plaintext = packBodyPlaintextZip(body);

  // 12-byte nonce + AES-GCM encrypt, no AAD.
  const nonce = new Uint8Array(NONCE_BYTES);
  globalThis.crypto.getRandomValues(nonce);
  const k = await globalThis.crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, plaintext),
  );

  // Wire format: nonce || ciphertext+tag.
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

/**
 * Decrypt a sealed body blob into its original member map.
 *
 * Inverse of {@link encryptBodyBlob}. Reads the 12-byte nonce prefix,
 * AES-GCM-decrypts the remainder with the supplied key, then parses
 * the resulting STORED zip back into a `{name: bytes}` map keyed by
 * the same `body/<name>` shape the producer started with.
 *
 * @param blob - the bytes from `body/encrypted.bin`. Must be at least
 *   `12 + 16` bytes (nonce + AEAD tag).
 * @param key - the 32-byte BEK used by the producer's
 *   {@link encryptBodyBlob}. Typically recovered via
 *   {@link unsealBekFromWrap}.
 *
 * @returns The original body member map. Keys are `body/<name>`
 *   matching what the producer passed in. Iteration order matches the
 *   sort order the producer used (alphabetical by name).
 *
 * @throws Error - when:
 *   - `key.length !== 32` (wrong key length)
 *   - `blob.length < 28` (truncated input)
 *   - AES-GCM tag check fails (wrong key, tampered ciphertext, or
 *     truncation past the `< 28` check)
 *   - The decrypted plaintext doesn't start with `PK\\x03\\x04` (not a
 *     STORED zip — likely a pre-2026-04-29 legacy frame, unsupported
 *     on the TS side)
 *
 * @example
 * ```ts
 * import { decryptBodyBlob, unsealBekFromWrap, manifestAadForWrap } from "@tnproto/sdk";
 *
 * // 1. Recover BEK from a recipient wrap using our seed.
 * const aad = manifestAadForWrap(manifest);
 * const bek = await unsealBekFromWrap(wrap, ourSeed, aad);
 *
 * // 2. Decrypt the encrypted body blob.
 * const body = await decryptBodyBlob(encryptedBytes, bek);
 *
 * // 3. Read installed members.
 * const seed = body.get("body/keys/local.private");
 * const yaml = body.get("body/tn.yaml");
 * ```
 *
 * @see {@link encryptBodyBlob}
 * @see {@link unsealBekFromWrap}
 * @see {@link absorbSealedBootstrap} - the full sealed-tnpkg install flow that
 *   composes BEK unseal + body decrypt + keystore write.
 * @see [spec/body-encryption](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md) - the wire frame this decrypts.
 *
 * @remarks
 * Mirrors `python/tn/export.py::decrypt_body_blob` for the v2 frame.
 * The pre-2026-04-29 legacy binary frame fallback that Python carries
 * is intentionally not implemented here — TS never produced the legacy
 * frame, so refusing to read it is correct.
 *
 * @public
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

  const k = await globalThis.crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, k, ciphertext),
    );
  } catch (err) {
    throw new Error(
      `decryptBodyBlob: AES-GCM decrypt failed (wrong key or tampered ciphertext): ${
        (err as Error).message ?? String(err)
      }`,
      { cause: err },
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
  const entries = unzipSync(plaintext);
  for (const [name, data] of Object.entries(entries).sort(([a], [b]) => a.localeCompare(b))) {
    validateBodyName(name);
    out.set(name, data);
  }
  return out;
}
