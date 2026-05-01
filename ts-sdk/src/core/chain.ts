import { computeRowHash, zeroHash as rawZeroHash } from "../raw.js";
import { asRowHash, type RowHash, type RowHashInput } from "../types.js";

/** Zero-initialized prev_hash for the first entry in any chain. */
export const ZERO_HASH: RowHash = asRowHash(rawZeroHash());

// ---------------------------------------------------------------------------
// Minimal pure-JS SHA-256 — browser-safe, sync, no node:* imports.
// Based on the FIPS-180-4 spec. Used only by sha256Hex below.
// ---------------------------------------------------------------------------

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function _sha256Bytes(data: Uint8Array): Uint8Array {
  // Pre-processing: padding.
  const bitLen = data.length * 8;
  // Padded length: next multiple of 64 that fits data + 1 byte + 8 bytes.
  const padLen = data.length + 1 + 8;
  const blockLen = Math.ceil(padLen / 64) * 64;
  const padded = new Uint8Array(blockLen);
  padded.set(data);
  padded[data.length] = 0x80;
  // Write 64-bit big-endian bit length at the end.
  const view = new DataView(padded.buffer);
  // High 32 bits (bit length is at most 2^53-1, so high word fits in 32 bits).
  view.setUint32(blockLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(blockLen - 4, bitLen >>> 0, false);

  // Initial hash values (H0..H7).
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const w = new Uint32Array(64);

  for (let i = 0; i < blockLen; i += 64) {
    // Prepare message schedule.
    for (let j = 0; j < 16; j++) {
      w[j] = view.getUint32(i + j * 4, false);
    }
    for (let j = 16; j < 64; j++) {
      const s0 = (w[j - 15]! >>> 7 | w[j - 15]! << 25) ^
                 (w[j - 15]! >>> 18 | w[j - 15]! << 14) ^
                 (w[j - 15]! >>> 3);
      const s1 = (w[j - 2]! >>> 17 | w[j - 2]! << 15) ^
                 (w[j - 2]! >>> 19 | w[j - 2]! << 13) ^
                 (w[j - 2]! >>> 10);
      w[j] = (w[j - 16]! + s0 + w[j - 7]! + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (let j = 0; j < 64; j++) {
      const S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[j]! + w[j]!) >>> 0;
      const S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const digest = new Uint8Array(32);
  const dv = new DataView(digest.buffer);
  dv.setUint32(0, h0, false); dv.setUint32(4, h1, false);
  dv.setUint32(8, h2, false); dv.setUint32(12, h3, false);
  dv.setUint32(16, h4, false); dv.setUint32(20, h5, false);
  dv.setUint32(24, h6, false); dv.setUint32(28, h7, false);
  return digest;
}

/** Hex-encoded SHA-256 of the UTF-8 bytes of a string. Browser-safe —
 * pure-JS implementation, no node:* imports. Used by core/agents_policy.ts
 * to compute policy contentHash without reaching for `node:crypto`. */
export function sha256Hex(text: string): string {
  const bytes = new TextEncoder().encode(text);
  return sha256HexBytes(bytes);
}

/** Hex-encoded SHA-256 of a raw byte array. Browser-safe — pure-JS
 * implementation, no node:* imports. */
export function sha256HexBytes(bytes: Uint8Array): string {
  const digest = _sha256Bytes(bytes);
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Compute the row_hash from the parts that transitively cover every
 * envelope field.
 *
 * This mirrors `tn.chain.compute_row_hash` in Python byte for byte.
 */
export function rowHash(input: RowHashInput): RowHash {
  const groups: Record<string, { ciphertext_b64: string; field_hashes: Record<string, string> }> =
    {};
  for (const [gname, g] of Object.entries(input.groups ?? {})) {
    groups[gname] = {
      ciphertext_b64: Buffer.from(g.ciphertext).toString("base64"),
      field_hashes: g.fieldHashes ?? {},
    };
  }
  const flat = {
    did: input.did,
    timestamp: input.timestamp,
    event_id: input.eventId,
    event_type: input.eventType,
    level: input.level,
    prev_hash: input.prevHash,
    public_fields: input.publicFields ?? {},
    groups,
  };
  return asRowHash(computeRowHash(flat));
}
