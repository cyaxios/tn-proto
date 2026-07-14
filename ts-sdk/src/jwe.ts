import { x25519 } from "@noble/curves/ed25519";
import type { JWK } from "jose";

import {
  generateX25519KeyPair,
  isUsableX25519PublicKey,
  jweDecryptManyDetailed,
  jweSeal,
  okpPrivateJwk,
} from "./core/jwe.js";
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
  return generateX25519KeyPair();
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

function validateRecipientKeys(recipients: Uint8Array[]): void {
  for (const recipient of recipients) {
    if (!isUsableX25519PublicKey(recipient)) {
      throw new MalformedError("recipient key material is invalid");
    }
  }
}

export async function encrypt(
  plaintext: Uint8Array,
  recipients: Iterable<Uint8Array>,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  requireBytes(plaintext, "plaintext", MAX_PLAINTEXT_BYTES);
  if (aad !== undefined) requireBytes(aad, "additional authenticated data", MAX_AAD_BYTES);
  const recipientKeys = collectBoundedKeys(recipients, "recipients");
  validateRecipientKeys(recipientKeys);
  return jweSeal(recipientKeys, plaintext, aad);
}

export class Subscriber {
  readonly #readerJwks: JWK[];

  constructor(privateKeys: Iterable<Uint8Array>) {
    this.#readerJwks = collectBoundedKeys(privateKeys, "private keys").map((privateKey) =>
      okpPrivateJwk(x25519.getPublicKey(privateKey), privateKey),
    );
  }

  async decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    requireBytes(ciphertext, "ciphertext", MAX_CIPHERTEXT_BYTES);
    if (aad !== undefined) requireBytes(aad, "additional authenticated data", MAX_AAD_BYTES);
    const outcome = await jweDecryptManyDetailed(this.#readerJwks, ciphertext, aad);
    if (outcome.status === "opened") return outcome.plaintext;
    if (outcome.status === "malformed") {
      throw new MalformedError("ciphertext is not a supported JWE General JSON value");
    }
    if (outcome.status === "authentication_failed") {
      throw new AuthenticationFailedError("ciphertext or additional data failed authentication");
    }
    throw new NotEntitledError("subscriber keys cannot open ciphertext");
  }
}

export function subscribe(privateKeys: Iterable<Uint8Array>): Subscriber {
  return new Subscriber(privateKeys);
}
