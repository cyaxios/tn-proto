// Browser-safe utilities. One definition each — no copies elsewhere in src/local/.

export { bytesToHex } from "@noble/hashes/utils";

export function fromBase64(s: string): Uint8Array {
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
