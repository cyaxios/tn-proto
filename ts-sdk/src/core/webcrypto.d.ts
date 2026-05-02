// Minimal ambient declarations for the Web Crypto API (browsers, Web Workers,
// Node 20+). The full set lives in lib.dom.d.ts or the Node crypto module
// types, but including either pulls in conflicting globals. We declare only
// the surface used by core/emk.ts and core/encoding.ts, keeping the types
// structurally compatible with runtime behaviour.

type KeyUsage =
  | "decrypt"
  | "deriveBits"
  | "deriveKey"
  | "encrypt"
  | "sign"
  | "unwrapKey"
  | "verify"
  | "wrapKey";

interface CryptoKey {
  readonly algorithm: { name: string };
  readonly extractable: boolean;
  readonly type: "private" | "public" | "secret";
  readonly usages: KeyUsage[];
}

interface SubtleCrypto {
  importKey(
    format: "raw",
    keyData: Uint8Array,
    algorithm: { name: string; length?: number } | string,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  deriveKey(
    algorithm: {
      name: "PBKDF2";
      salt: Uint8Array;
      iterations: number;
      hash: string;
    },
    baseKey: CryptoKey,
    derivedKeyType: { name: string; length: number },
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  encrypt(
    algorithm: { name: "AES-GCM"; iv: Uint8Array },
    key: CryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: "AES-GCM"; iv: Uint8Array },
    key: CryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
}

interface WebCryptoGlobal {
  readonly subtle: SubtleCrypto;
  getRandomValues<T extends Uint8Array>(array: T): T;
}

// Augment the global scope so that `globalThis.crypto` is typed without
// requiring a node:crypto import (which is forbidden in Layer 1).
declare global {
  var crypto: WebCryptoGlobal;
}
