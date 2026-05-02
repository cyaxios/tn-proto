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

// ---------------------------------------------------------------------------
// Admin state — derived state shape produced by the AdminStateReducer in
// core/admin/state.ts. SDK-public types; camelCase per TS convention; the
// wire (manifest) form uses snake_case which is converted at the manifest
// boundary in client.ts.
// ---------------------------------------------------------------------------

export interface RecipientEntry {
  leafIndex: number;
  recipientDid: string | null;
  mintedAt: string | null;
  kitSha256: string | null;
  revoked: boolean;
  revokedAt: string | null;
}

export interface AdminCeremonyState {
  ceremonyId: string;
  cipher: string;
  deviceDid: string;
  createdAt: string | null;
}

export interface AdminGroupState {
  group: string;
  cipher: string;
  publisherDid: string;
  addedAt: string;
}

export interface AdminRecipientState {
  group: string;
  leafIndex: number;
  recipientDid: string | null;
  kitSha256: string;
  mintedAt: string | null;
  activeStatus: "active" | "revoked" | "retired";
  revokedAt: string | null;
  retiredAt: string | null;
}

export interface AdminRotationState {
  group: string;
  cipher: string;
  generation: number;
  previousKitSha256: string;
  rotatedAt: string;
}

export interface AdminCouponState {
  group: string;
  slot: number;
  toDid: string;
  issuedTo: string;
  issuedAt: string | null;
}

export interface AdminEnrolmentState {
  group: string;
  peerDid: string;
  packageSha256: string;
  status: "offered" | "absorbed";
  compiledAt: string | null;
  absorbedAt: string | null;
}

export interface AdminVaultLinkState {
  vaultDid: string;
  projectId: string;
  linkedAt: string;
  unlinkedAt: string | null;
}

export interface AdminState {
  ceremony: AdminCeremonyState | null;
  groups: AdminGroupState[];
  recipients: AdminRecipientState[];
  rotations: AdminRotationState[];
  coupons: AdminCouponState[];
  enrolments: AdminEnrolmentState[];
  vaultLinks: AdminVaultLinkState[];
}
