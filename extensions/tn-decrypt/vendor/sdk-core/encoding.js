// Browser-safe base64 + random helpers. Layer 1: no node:* imports.
// Used by core/emk.ts, core/tnpkg.ts, and downstream Layer 2 callers.
/** Encode a Uint8Array to standard (non-URL-safe) base64.
 * Splits into 32 KB chunks to avoid String.fromCharCode stack overflow
 * on large inputs. Works in both browsers and Node (btoa is a global
 * in Node 16+). */
export function bytesToB64(bytes) {
    const CHUNK = 0x8000;
    let s = "";
    for (let i = 0; i < bytes.length; i += CHUNK) {
        s += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
    }
    return btoa(s);
}
/** Decode standard or URL-safe base64 (with or without padding) to a
 * Uint8Array. Works in both browsers and Node (atob is a global in
 * Node 16+). */
export function b64ToBytes(s) {
    // Normalise URL-safe → standard, and add padding if needed.
    const std = s.replace(/-/g, "+").replace(/_/g, "/");
    const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1)
        out[i] = bin.charCodeAt(i);
    return out;
}
/** Fill a new Uint8Array of length `n` with cryptographically strong
 * random bytes via the Web Crypto API. */
export function randomBytes(n) {
    const o = new Uint8Array(n);
    globalThis.crypto.getRandomValues(o);
    return o;
}
//# sourceMappingURL=encoding.js.map