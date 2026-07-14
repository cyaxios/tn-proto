import { BtnPublisher, btnCiphertextPublisherId, btnDecrypt, btnKitPublisherId } from "./raw.js";
import {
  LimitExceededError,
  MalformedError,
  NotEntitledError,
  PrimitiveError,
} from "./primitive_errors.js";

type MalformedSubject =
  | "additional authenticated data"
  | "ciphertext"
  | "plaintext"
  | "producer state"
  | "reader kit"
  | "revocation leaf";

function nativeMessage(error: unknown): string {
  return error instanceof Error ? error.message.toLowerCase() : "";
}

function mapBtnError(error: unknown, subject: MalformedSubject): PrimitiveError {
  if (error instanceof PrimitiveError) return error;
  const message = nativeMessage(error);
  if (message.includes("tree exhausted")) {
    return new LimitExceededError("BTN reader capacity is exhausted");
  }
  if (message.includes("not entitled")) {
    return new NotEntitledError("BTN reader is not entitled to this ciphertext");
  }
  return new MalformedError(`BTN ${subject} is invalid`);
}

function requireBytes(value: Uint8Array, subject: MalformedSubject): void {
  if (!(value instanceof Uint8Array)) {
    throw new MalformedError(`BTN ${subject} must be a Uint8Array`);
  }
}

function validateKit(kit: Uint8Array): Uint8Array {
  requireBytes(kit, "reader kit");
  try {
    btnKitPublisherId(kit);
  } catch (error) {
    throw mapBtnError(error, "reader kit");
  }
  return kit.slice();
}

function collectKits(kits: Iterable<Uint8Array>): Uint8Array[] {
  const collected: Uint8Array[] = [];
  try {
    for (const kit of kits) collected.push(validateKit(kit));
  } catch (error) {
    throw mapBtnError(error, "reader kit");
  }
  if (collected.length === 0) {
    throw new MalformedError("BTN subscription requires at least one reader kit");
  }
  return collected;
}

function validateCiphertext(ciphertext: Uint8Array): void {
  requireBytes(ciphertext, "ciphertext");
  try {
    btnCiphertextPublisherId(ciphertext);
  } catch (error) {
    throw mapBtnError(error, "ciphertext");
  }
}

/** Stateful owner of one BTN publisher tree. Serialized state is secret. */
export class Producer {
  constructor(private readonly publisher: BtnPublisher) {}

  static fromBytes(state: Uint8Array): Producer {
    requireBytes(state, "producer state");
    try {
      return new Producer(BtnPublisher.fromBytes(state));
    } catch (error) {
      throw mapBtnError(error, "producer state");
    }
  }

  toBytes(): Uint8Array {
    return this.publisher.toBytes();
  }

  mint(): Uint8Array {
    try {
      return this.publisher.mint();
    } catch (error) {
      throw mapBtnError(error, "reader kit");
    }
  }

  encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
    requireBytes(plaintext, "plaintext");
    if (aad !== undefined) requireBytes(aad, "additional authenticated data");
    try {
      return aad === undefined
        ? this.publisher.encrypt(plaintext)
        : this.publisher.encryptWithAad(plaintext, aad);
    } catch (error) {
      throw mapBtnError(error, "plaintext");
    }
  }

  decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    requireBytes(ciphertext, "ciphertext");
    if (aad !== undefined) requireBytes(aad, "additional authenticated data");
    try {
      return aad === undefined
        ? this.publisher.decrypt(ciphertext)
        : this.publisher.decryptWithAad(ciphertext, aad);
    } catch (error) {
      throw mapBtnError(error, "ciphertext");
    }
  }

  revoke(kit: Uint8Array): void {
    requireBytes(kit, "reader kit");
    try {
      this.publisher.revokeKit(kit);
    } catch (error) {
      throw mapBtnError(error, "reader kit");
    }
  }

  revokeByLeaf(leaf: bigint): void {
    if (typeof leaf !== "bigint" || leaf < 0n) {
      throw new MalformedError("BTN revocation leaf is invalid");
    }
    try {
      this.publisher.revokeByLeaf(leaf);
    } catch (error) {
      throw mapBtnError(error, "revocation leaf");
    }
  }

  issuedCount(): number {
    return this.publisher.issuedCount();
  }

  revokedCount(): number {
    return this.publisher.revokedCount();
  }

  publisherId(): Uint8Array {
    return this.publisher.publisherId();
  }

  get epoch(): number {
    return this.publisher.epoch;
  }
}

/** Reader-side holder for one or more validated portable BTN kits. */
export class Subscriber {
  private readonly kits: Uint8Array[];

  constructor(kits: Iterable<Uint8Array>) {
    this.kits = collectKits(kits);
  }

  addKey(kit: Uint8Array): void {
    this.kits.push(validateKit(kit));
  }

  decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    validateCiphertext(ciphertext);
    if (aad !== undefined) requireBytes(aad, "additional authenticated data");
    for (const kit of this.kits) {
      try {
        return btnDecrypt(kit, ciphertext, aad);
      } catch (error) {
        const mapped = mapBtnError(error, "ciphertext");
        if (mapped instanceof NotEntitledError) continue;
        throw mapped;
      }
    }
    throw new NotEntitledError("No held BTN reader kit opens this ciphertext");
  }
}

/** Create a fresh stateful BTN producer. */
export function setup(): Producer {
  try {
    return new Producer(new BtnPublisher(null));
  } catch (error) {
    throw mapBtnError(error, "producer state");
  }
}

/** Create a subscriber from one or more portable reader kits. */
export function subscribe(kits: Iterable<Uint8Array>): Subscriber {
  return new Subscriber(kits);
}
