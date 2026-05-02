// Nominal types. TypeScript's structural typing means these do not
// actually enforce anything at runtime, but they document intent and
// prevent accidental cross-assignment when reading code.

export type Did = string & { readonly __brand: "did" };
export type RowHash = string & { readonly __brand: "rowHash" };
export type SignatureB64 = string & { readonly __brand: "signatureB64" };

export function asDid(s: string): Did {
  if (!s.startsWith("did:")) {
    throw new Error(`not a DID: ${s}`);
  }
  return s as Did;
}

export function asRowHash(s: string): RowHash {
  if (!s.startsWith("sha256:") || s.length !== 7 + 64) {
    throw new Error(`not a row_hash: ${s}`);
  }
  return s as RowHash;
}

export function asSignatureB64(s: string): SignatureB64 {
  return s as SignatureB64;
}

export interface GroupHashInput {
  /** Raw ciphertext bytes. */
  ciphertext: Uint8Array;
  /** Sorted field-name to HMAC token mapping. */
  fieldHashes?: Record<string, string>;
}

export interface RowHashInput {
  did: Did;
  timestamp: string;
  eventId: string;
  eventType: string;
  level: string;
  prevHash: RowHash;
  publicFields?: Record<string, unknown>;
  groups?: Record<string, GroupHashInput>;
}

export interface GroupPayload {
  /** Standard base64 (not url-safe) of the ciphertext. */
  ciphertext: string;
  /** snake_case on the wire so TS / Python / Rust ndjson is byte-identical. */
  field_hashes: Record<string, string>;
}

export interface Envelope {
  did: Did;
  timestamp: string;
  eventId: string;
  eventType: string;
  level: string;
  sequence: number;
  prevHash: RowHash;
  rowHash: RowHash;
  signatureB64: SignatureB64;
  publicFields?: Record<string, unknown>;
  groupPayloads?: Record<string, GroupPayload>;
}

// ---------------------------------------------------------------------------
// Read-shape types — moved from core/read_shape.ts in Task 1.8.
// ---------------------------------------------------------------------------

/** What the runtime hands to Layer 1 read-shape projection: a decrypted
 * envelope plus per-group plaintext plus a validity record. */
export interface ReadEntry {
  envelope: Record<string, unknown>;
  plaintext: Record<string, Record<string, unknown>>;
  valid: { signature: boolean; rowHash: boolean; chain: boolean };
}

/** Alias for ReadEntry — used in places where "raw" reads more clearly than "Read". */
export type RawEntry = ReadEntry;

/** The flat dict shape produced by `flattenRawEntry`. The default `tn.read()`
 * yields these. Keys are snake_case throughout — wire-defined envelope keys
 * (`event_type`, `event_id`, ...) and user-supplied payload keys are not the
 * SDK's to rewrite. */
export type Entry = Record<string, unknown>;

/** Log-level threshold value. Matches the constants in client.ts. */
export type LogLevel = "debug" | "info" | "warning" | "error";
