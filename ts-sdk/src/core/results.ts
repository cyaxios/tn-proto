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
  /** Trusted enrollment offers only: the staged offer's exact digest
   * (`sha256:` over the canonical signed key-binding proof). Hand this to
   * `tn.pkg.approveAndReconcile` / `reconcilePending`. */
  offerDigest?: string;
  /** Publisher DID admitted from a verified enrollment response or a signed,
   * body-indexed kit bundle and installed into the local trust registry. */
  verifiedPublisherDid?: string;
  /** True when the package entered through the explicitly named unsafe
   * legacy-import path (`unsafeLegacySigner`). The import stays unverified. */
  unsafeLegacyImport?: boolean;
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
  cipher: "btn" | "jwe" | "hibe";
  /** btn leaf index; null for hibe (grants carry no leaf — the reader kit
   * is a delegated identity key, mirroring Python's
   * `AddRecipientResult.leaf_index = None`). */
  leafIndex: number | null;
  recipientDid: string | null;
  /** Absolute path to the kit file written to disk by `tn.admin.addRecipient`.
   * null for jwe — a jwe recipient's public key is registered directly, no kit
   * is minted (mirrors Python's jwe add_recipient returning a config update). */
  kitPath: string | null;
  /** sha256 hex of the kit file bytes; null for jwe (no kit). */
  kitSha256: string | null;
  /** ISO-8601 timestamp the kit was minted at. */
  mintedAt: string;
  /** hibe only: the identity path the granted key sits on. */
  idPath?: string;
  /** Whether the registration/grant was backed by a verified key-binding
   * proof (JWE `acceptedOffer` / HIBE `proof`). False marks an explicitly
   * unverified compatibility registration. */
  verified?: boolean;
  /** Digest of the verified key-binding proof, when one backed this call. */
  proofDigest?: string | null;
  /** jwe only: `sha256:` digest of the registered X25519 public key. */
  publicKeySha256?: string | null;
  /** jwe only: canonical digest of the normalized identity/scope/key/evidence binding. */
  bindingDigest?: string | null;
  /** hibe only: whether the kit body was recipient-sealed for delivery. */
  sealed?: boolean;
  /** hibe only: true for an explicit ancestor grant — the key delegates the
   * whole subtree below `idPath` within the remaining depth. */
  subtreeDelegation?: boolean;
}

export interface RevokeRecipientResult {
  group: string;
  cipher: "btn" | "jwe" | "hibe";
  /** btn leaf index; null for hibe (revocation rotates the identity path
   * instead of flipping a leaf). */
  leafIndex: number | null;
  recipientDid: string | null;
  revokedAt: string;
  /** For jwe rotation: the path to the new kit file written for remaining
   * recipients. null for btn (no rotation needed; revoke flips a leaf
   * out of the subset-difference tree). */
  newKitPath: string | null;
  newKitSha256: string | null;
  /** hibe only: the identity path future seals use after the revocation. */
  newPath?: string;
  /** hibe only: re-issued `.tnpkg` kits for the surviving grantees —
   * distribute them and have each survivor absorb theirs. */
  kitPaths?: string[];
}

/** Structured return from `tn.admin.revokeReader` (hibe groups). Mirrors
 * Python's `RevokeReaderResult`. */
export interface RevokeReaderResult {
  revoked: boolean;
  /** Identity path future seals use. */
  newPath: string;
  /** Re-issued kits for the surviving grantees. */
  kitPaths: string[];
  /** DIDs still granted after the revocation. */
  remaining: string[];
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
  cipher: "btn" | "jwe" | "hibe";
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
  /** Trusted enrollment offers only: `sha256:` digest of the canonical
   * signed key-binding proof. The publisher approves/reconciles by this
   * exact digest. */
  offerDigest?: string;
}
