/** Stable categories shared by the byte-oriented cipher facades. */
export type PrimitiveErrorCategory =
  | "NotEntitled"
  | "Malformed"
  | "AuthenticationFailed"
  | "LimitExceeded";

/** Base class for failures surfaced by `btn` and `jwe`. */
export class PrimitiveError extends Error {
  constructor(
    readonly category: PrimitiveErrorCategory,
    message: string,
  ) {
    super(message);
    this.name = `${category}Error`;
  }
}

/** Supplied reader material cannot open the ciphertext. */
export class NotEntitledError extends PrimitiveError {
  constructor(message: string) {
    super("NotEntitled", message);
  }
}

/** State, key material, or ciphertext is structurally invalid. */
export class MalformedError extends PrimitiveError {
  constructor(message: string) {
    super("Malformed", message);
  }
}

/** Ciphertext or additional authenticated data failed authentication. */
export class AuthenticationFailedError extends PrimitiveError {
  constructor(message: string) {
    super("AuthenticationFailed", message);
  }
}

/** A cryptographic input or state limit was exceeded. */
export class LimitExceededError extends PrimitiveError {
  constructor(message: string) {
    super("LimitExceeded", message);
  }
}
