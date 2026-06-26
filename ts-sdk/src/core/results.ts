// Result types for the Tn class's namespaced verbs. Layer 1 — pure data
// shapes, browser-safe. The Tn class methods produce these; consumers
// import them via `tn-proto` (or via `tn-proto/core` if they only
// need the type).
//
// Field names: camelCase (these are SDK-owned types, not wire envelope
// keys — so the snake-stays rule does not apply). The wire conversion,
// where applicable, is done in Layer 2 before the result lands here.

import type { RowHash } from "./types.js";
import type { AdminState } from "./types.js";
import type { ChainConflict } from "./admin/state.js";

// ---------------------------------------------------------------------------
// Lifted from runtime/node_runtime.ts — canonical definition now lives here.
// ---------------------------------------------------------------------------

export interface EmitReceipt {
  eventId: string;
  rowHash: RowHash;
  sequence: number;
}

// ---------------------------------------------------------------------------
// Lifted from client.ts — canonical definition now lives here.
// ---------------------------------------------------------------------------

export interface AbsorbReceipt {
  kind: string;
  acceptedCount: number;
  dedupedCount: number;
  noop: boolean;
  derivedState: AdminState | null;
  conflicts: ChainConflict[];
  /**
   * Paths in the local keystore whose existing contents were renamed
   * to a `.previous.<UTC_TS>` sidecar to make room for kits from the
   * absorbed package. Empty when nothing was overwritten.
   *
   * Mirrors Python `AbsorbReceipt.replaced_kit_paths` (FINDINGS #6
   * cross-binding parity). Iterate this field after absorb to decide
   * whether to alert / restore / accept the swap rather than relying
   * on a printed warning. Optional: omitted (or empty) when nothing
   * was overwritten.
   */
  replacedKitPaths?: string[];
  /** Set when the package was rejected (signature failure, missing body,
   * unsupported kind). Otherwise undefined. */
  rejectedReason?: string;
}

/**
 * Legacy two-arg `absorb(cfg, source)` return shape.
 *
 * Mirrors Python `tn.absorb.AbsorbResult` (the back-compat shape kept for
 * callers that match on `.status` / `.reason`). The new one-arg
 * `absorb(source)` form returns the richer {@link AbsorbReceipt}; the
 * legacy two-arg form returns this flatter triple so existing call sites
 * keep working unchanged.
 *
 * `status` values mirror Python: `offer_stashed` | `enrolment_applied` |
 * `coupon_applied` | `no_op` | `rejected`.
 */
export interface AbsorbResult {
  status: string;
  reason: string;
  peerDid: string | null;
}

// ---------------------------------------------------------------------------
// Result types for recipient/group admin, bundle, and offer verbs.
// ---------------------------------------------------------------------------

export interface AddRecipientResult {
  group: string;
  cipher: "btn" | "jwe";
  leafIndex: number;
  recipientDid: string | null;
  /** Absolute path to the kit file written to disk by `tn.admin.addRecipient`. */
  kitPath: string;
  /** sha256 hex of the kit file bytes. */
  kitSha256: string;
  /** ISO-8601 timestamp the kit was minted at. */
  mintedAt: string;
}

export interface RevokeRecipientResult {
  group: string;
  cipher: "btn" | "jwe";
  leafIndex: number;
  recipientDid: string | null;
  revokedAt: string;
  /** For jwe rotation: the path to the new kit file written for remaining
   * recipients. null for btn (no rotation needed; revoke flips a leaf
   * out of the subset-difference tree). */
  newKitPath: string | null;
  newKitSha256: string | null;
}

export interface RotateGroupResult {
  group: string;
  cipher: "btn" | "jwe";
  generation: number;
  previousKitSha256: string;
  newKitSha256: string;
  rotatedAt: string;
}

export interface EnsureGroupResult {
  group: string;
  cipher: "btn" | "jwe";
  /** false when the group already existed (idempotent ensure). */
  created: boolean;
  publisherDid: string;
  addedAt: string;
}

export interface BundleResult {
  bundlePath: string;
  bundleSha256: string;
  recipientDid: string;
  /** Group names included in the bundle (sorted alphabetically). */
  groups: string[];
  /** Path to the manifest written alongside the bundle (often inside
   * the .tnpkg archive — record it for callers who need to verify
   * the manifest signature out-of-band). */
  manifestPath: string;
}

export interface OfferReceipt {
  group: string;
  peerDid: string;
  packageSha256: string;
  status: "offered" | "absorbed";
  /** Path to the offer package on disk if a file was written; null when
   * the offer was made in-memory only (e.g., bilateral over a vault). */
  packagePath: string | null;
}
