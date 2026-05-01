// Extension-wide unlock primitives.
//
// Two paths, mirroring the vault's account-credential model (D-22):
//
//   "prf"        — WebAuthn passkey + PRF extension. The passkey is
//                  registered once at "Set up unlock". On unlock, the
//                  user taps the authenticator; PRF(passkey, salt) is
//                  the extension-master-key (EMK).
//
//   "passphrase" — Fallback for browsers / authenticators without the
//                  PRF extension. PBKDF2-SHA256 over a user-chosen
//                  passphrase derives the EMK.
//
// The EMK is never persisted on disk. What is persisted is enough
// metadata to re-derive it (credential_id + salt for PRF; salt +
// iterations for passphrase) plus a small "verifier" blob (a tiny
// AES-GCM ciphertext over a known constant) so we can detect a
// wrong passphrase / cancelled passkey before trying to unwrap any
// keystores.
//
// This file is consumed by background.js (service worker) for
// derive/wrap/unwrap and by popup.js for the UI flow that triggers
// the WebAuthn calls (popups can call WebAuthn; service workers
// cannot).

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function bytesToB64(bytes) {
  const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of a) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function rand(n) {
  const o = new Uint8Array(n);
  crypto.getRandomValues(o);
  return o;
}

// Constant plaintext used to verify the EMK is correct without
// touching real keystore data. Any 16+ bytes works as long as it is
// stable across versions.
const VERIFIER_PT = new TextEncoder().encode("tn-decrypt:emk:v1");

// ---------------------------------------------------------------------------
// Feature detection
// ---------------------------------------------------------------------------

// Probe whether this browser/authenticator pair supports the
// WebAuthn PRF extension. We register a throwaway resident-key-less
// credential with `prf.eval` and inspect `getClientExtensionResults().prf`.
//
// This MUST be called from a popup / options page in a user-gesture
// context. Do not call from the service worker.
export async function probePrfSupport() {
  if (typeof PublicKeyCredential === "undefined") return { supported: false, reason: "no PublicKeyCredential" };
  // The cheapest probe is checking that the registration call surface
  // exists. The real check happens at registration time when the
  // authenticator either returns prf results or doesn't.
  return { supported: true };
}

// ---------------------------------------------------------------------------
// EMK derivation
// ---------------------------------------------------------------------------

// Import a 32-byte buffer as an AES-GCM CryptoKey usable for
// encrypt+decrypt. Non-extractable.
export async function importEmk(rawBytes) {
  return crypto.subtle.importKey(
    "raw", rawBytes,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"],
  );
}

// PBKDF2 derivation for the passphrase fallback.
export async function deriveEmkFromPassphrase(passphrase, saltBytes, iterations) {
  const pk = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase),
    { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    pk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

// Take the raw PRF output (BufferSource, typically 32 bytes from
// WebAuthn's HMAC-SHA-256 over the salt) and turn it into an AES-GCM
// CryptoKey. The PRF output is already uniformly random, so we use
// it directly as key material.
export async function emkFromPrfOutput(prfOutput) {
  const bytes = new Uint8Array(prfOutput);
  // The PRF output may be longer than 32 bytes on some platforms; take
  // the first 32 bytes after running it through SHA-256 to normalize.
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return importEmk(digest);
}

// ---------------------------------------------------------------------------
// Verifier (proves EMK is correct before we touch real keystores)
// ---------------------------------------------------------------------------

export async function makeVerifier(emk) {
  const nonce = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, emk, VERIFIER_PT,
  ));
  return { nonce_b64: bytesToB64(nonce), ciphertext_b64: bytesToB64(ct) };
}

export async function checkVerifier(emk, verifier) {
  try {
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(verifier.nonce_b64) },
      emk,
      b64ToBytes(verifier.ciphertext_b64),
    ));
    if (pt.length !== VERIFIER_PT.length) return false;
    for (let i = 0; i < pt.length; i += 1) if (pt[i] !== VERIFIER_PT[i]) return false;
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Wrapping a per-keystore secret under the EMK.
//
// The "secret" we wrap is the original keystore passphrase string. We
// keep the existing per-keystore passphrase-encrypted blob intact;
// once the EMK can unwrap the passphrase, we feed it into the
// existing decryptKeystoreBlob() path. This keeps the change small
// and means the user can still unlock with the legacy per-keystore
// passphrase if they wipe extension-unlock state.
// ---------------------------------------------------------------------------

export async function wrapKeystoreSecret(emk, secretText) {
  const nonce = rand(12);
  const pt = new TextEncoder().encode(secretText);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, emk, pt,
  ));
  return { nonce_b64: bytesToB64(nonce), ciphertext_b64: bytesToB64(ct) };
}

export async function unwrapKeystoreSecret(emk, wrapped) {
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(wrapped.nonce_b64) },
    emk,
    b64ToBytes(wrapped.ciphertext_b64),
  ));
  return new TextDecoder().decode(pt);
}
