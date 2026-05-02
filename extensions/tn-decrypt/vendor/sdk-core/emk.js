// Extension Master Key (EMK) primitives — Web-Crypto-backed AES-GCM
// helpers for wrapping per-keystore secrets under a user-derived master
// key. Two derivation paths: WebAuthn PRF (no passphrase) or
// PBKDF2-SHA256 over a passphrase. Audited single source for browser
// extensions and dashboards that need the same EMK shape.
//
// Layer 1: Web Crypto only, no node:* imports. The extension at
// `extensions/tn-decrypt/` consumes this module via the dev-install
// relative path; production packaging vendors `dist/core/`.
import { bytesToB64, b64ToBytes, randomBytes } from "./encoding.js";
const VERIFIER_PT = new TextEncoder().encode("tn-decrypt:emk:v1");
/** Import a 32-byte buffer as an AES-GCM CryptoKey for encrypt+decrypt.
 * Non-extractable. */
export async function importEmk(rawBytes) {
    return globalThis.crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
/** PBKDF2-SHA256 derivation for the passphrase fallback path. */
export async function deriveEmkFromPassphrase(passphrase, saltBytes, iterations) {
    const pk = await globalThis.crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
    return globalThis.crypto.subtle.deriveKey({ name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" }, pk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
/** Take raw PRF output (ArrayBuffer or ArrayBufferView, typically 32 bytes
 * from WebAuthn's HMAC-SHA-256) and turn it into an AES-GCM CryptoKey.
 * SHA-256 normalizes to 32 bytes regardless of platform-specific PRF
 * output length. */
export async function emkFromPrfOutput(prfOutput) {
    const bytes = prfOutput instanceof ArrayBuffer
        ? new Uint8Array(prfOutput)
        : new Uint8Array(prfOutput.buffer);
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
    return importEmk(digest);
}
/** Make a verifier blob — a small AES-GCM ciphertext over a known
 * constant. Used to detect a wrong passphrase / cancelled passkey
 * before unwrapping any real keystore secrets. */
export async function makeVerifier(emk) {
    const nonce = randomBytes(12);
    const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, emk, VERIFIER_PT));
    return { nonce_b64: bytesToB64(nonce), ciphertext_b64: bytesToB64(ct) };
}
/** Check a verifier blob round-trips against the EMK. Returns false on
 * any decrypt error (wrong key) or content mismatch. */
export async function checkVerifier(emk, verifier) {
    try {
        const pt = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(verifier.nonce_b64) }, emk, b64ToBytes(verifier.ciphertext_b64)));
        if (pt.length !== VERIFIER_PT.length)
            return false;
        for (let i = 0; i < pt.length; i += 1)
            if (pt[i] !== VERIFIER_PT[i])
                return false;
        return true;
    }
    catch {
        return false;
    }
}
/** Wrap a per-keystore secret string under the EMK. Returns the wrapped
 * blob for storage. Optional `aad` enables domain-separated bindings
 * (e.g. `"tn-vault-body-v1"`) so ciphertexts from one layer cannot be
 * replayed against another. Backward-compatible: callers without `aad`
 * produce the same output as before. */
export async function wrapKeystoreSecret(emk, secretText, aad) {
    const nonce = randomBytes(12);
    const pt = new TextEncoder().encode(secretText);
    const params = { name: "AES-GCM", iv: nonce };
    if (aad !== undefined)
        params.additionalData = aad;
    const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt(params, emk, pt));
    return { nonce_b64: bytesToB64(nonce), ciphertext_b64: bytesToB64(ct) };
}
/** Unwrap a wrapped keystore-secret blob. Throws on decrypt failure.
 * If `aad` was supplied to `wrapKeystoreSecret`, the same value must be
 * passed here; mismatched AAD causes a decrypt error. */
export async function unwrapKeystoreSecret(emk, wrapped, aad) {
    const params = { name: "AES-GCM", iv: b64ToBytes(wrapped.nonce_b64) };
    if (aad !== undefined)
        params.additionalData = aad;
    const pt = new Uint8Array(await globalThis.crypto.subtle.decrypt(params, emk, b64ToBytes(wrapped.ciphertext_b64)));
    return new TextDecoder().decode(pt);
}
/** Wrap arbitrary bytes (vs `wrapKeystoreSecret` which wraps a string).
 * Use this for body-encryption / payload-encryption paths where the
 * plaintext is binary. The optional `aad` is bound into the AES-GCM
 * authentication tag — pass the same value when unwrapping. */
export async function wrapBytes(emk, plaintext, aad) {
    const nonce = randomBytes(12);
    const params = { name: "AES-GCM", iv: nonce };
    if (aad !== undefined)
        params.additionalData = aad;
    const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt(params, emk, plaintext));
    return { nonce_b64: bytesToB64(nonce), ciphertext_b64: bytesToB64(ct) };
}
/** Unwrap a `wrapBytes`-produced blob to its original plaintext bytes.
 * Throws on AES-GCM authentication failure (wrong EMK or wrong AAD). */
export async function unwrapBytes(emk, wrapped, aad) {
    const params = { name: "AES-GCM", iv: b64ToBytes(wrapped.nonce_b64) };
    if (aad !== undefined)
        params.additionalData = aad;
    return new Uint8Array(await globalThis.crypto.subtle.decrypt(params, emk, b64ToBytes(wrapped.ciphertext_b64)));
}
//# sourceMappingURL=emk.js.map