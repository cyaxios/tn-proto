import {
  jweDecrypt as rustJweDecrypt,
  jweEncrypt as rustJweEncrypt,
  jweKeygen as rustJweKeygen,
} from "./raw.js";
import {
  AuthenticationFailedError,
  LimitExceededError,
  MalformedError,
  NotEntitledError,
  PrimitiveError,
} from "./primitive_errors.js";

const MAX_KEYS = 1_024;
const MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024;
const MAX_AAD_BYTES = 64 * 1024;
const MAX_CIPHERTEXT_BYTES = 128 * 1024 * 1024;

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function keygen(): KeyPair {
  try {
    const generated = rustJweKeygen() as unknown;
    if (generated === null || typeof generated !== "object") {
      throw new Error("invalid keygen result");
    }
    const value = generated as Record<string, unknown>;
    requireRawKey(value["publicKey"], "generated public key");
    requireRawKey(value["privateKey"], "generated private key");
    return {
      publicKey: new Uint8Array(value["publicKey"]),
      privateKey: new Uint8Array(value["privateKey"]),
    };
  } catch (error) {
    throw mapJweError(error, "key generation");
  }
}

function requireBytes(
  value: unknown,
  label: string,
  maxBytes?: number,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new MalformedError(`${label} must be a Uint8Array`);
  }
  if (maxBytes !== undefined && value.length > maxBytes) {
    throw new LimitExceededError(`${label} exceeds its configured size limit`);
  }
}

function collectBoundedKeys(keys: Iterable<Uint8Array>, label: string): Uint8Array[] {
  const collected: Uint8Array[] = [];
  try {
    for (const key of keys) {
      if (collected.length === MAX_KEYS) {
        throw new LimitExceededError(`${label} cannot contain more than ${MAX_KEYS} keys`);
      }
      if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new MalformedError(`${label} must contain raw 32-byte X25519 keys`);
      }
      collected.push(new Uint8Array(key));
    }
  } catch (error) {
    if (error instanceof PrimitiveError) throw error;
    throw new MalformedError(`${label} must be an iterable of raw X25519 keys`);
  }
  if (collected.length === 0) throw new MalformedError(`${label} cannot be empty`);
  return collected;
}

function requireRawKey(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new MalformedError(`${label} must be a raw 32-byte X25519 key`);
  }
}

function nativeMessage(error: unknown): string {
  return error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
}

function mapJweError(error: unknown, operation: string): PrimitiveError {
  if (error instanceof PrimitiveError) return error;
  const message = nativeMessage(error);
  if (
    message.includes("exceeds") ||
    message.includes("maximum is") ||
    message.includes("size limit")
  ) {
    return new LimitExceededError(`JWE ${operation} exceeded a configured limit`);
  }
  if (message.includes("aad does not match") || message.includes("authentication failed")) {
    return new AuthenticationFailedError(`JWE ${operation} failed authentication`);
  }
  if (message.includes("not entitled")) {
    return new NotEntitledError("subscriber keys cannot open ciphertext");
  }
  return new MalformedError(`JWE ${operation} failed: ${message || "invalid input"}`);
}

/** Encrypt immediately through the Rust/WASM RFC 7516 implementation. */
export function encryptSync(
  plaintext: Uint8Array,
  recipients: Iterable<Uint8Array>,
  aad?: Uint8Array,
): Uint8Array {
  requireBytes(plaintext, "plaintext", MAX_PLAINTEXT_BYTES);
  if (aad !== undefined) requireBytes(aad, "additional authenticated data", MAX_AAD_BYTES);
  const recipientKeys = collectBoundedKeys(recipients, "recipients");
  try {
    return rustJweEncrypt(plaintext, recipientKeys, aad);
  } catch (error) {
    throw mapJweError(error, "encryption");
  }
}

/** Backward-compatible async delegate to {@link encryptSync}. */
export async function encrypt(
  plaintext: Uint8Array,
  recipients: Iterable<Uint8Array>,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return encryptSync(plaintext, recipients, aad);
}

export class Subscriber {
  readonly #privateKeys: Uint8Array[];

  constructor(privateKeys: Iterable<Uint8Array>) {
    this.#privateKeys = collectBoundedKeys(privateKeys, "private keys");
  }

  /** Decrypt immediately through the Rust/WASM RFC 7516 implementation. */
  decryptSync(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    requireBytes(ciphertext, "ciphertext", MAX_CIPHERTEXT_BYTES);
    if (aad !== undefined) requireBytes(aad, "additional authenticated data", MAX_AAD_BYTES);
    try {
      return rustJweDecrypt(ciphertext, this.#privateKeys, aad);
    } catch (error) {
      throw mapJweError(error, "decryption");
    }
  }

  /** Backward-compatible async delegate to {@link decryptSync}. */
  async decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    return this.decryptSync(ciphertext, aad);
  }
}

export function subscribe(privateKeys: Iterable<Uint8Array>): Subscriber {
  return new Subscriber(privateKeys);
}
