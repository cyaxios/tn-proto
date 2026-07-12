// tn.admin.* namespace — verb surface for ceremony admin operations.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sha256HexBytes } from "../core/chain.js";
import type { NodeRuntime } from "../runtime/node_runtime.js";
import type {
  AddRecipientResult,
  RevokeReaderResult,
  RevokeRecipientResult,
  RotateGroupResult,
  EnsureGroupResult,
} from "../core/results.js";
import {
  TrustError,
  formatTrustTimestamp,
  sha256Digest,
  verifyKeyBindingProof,
  type AcceptedOffer,
  type EnrollmentChallengeV1,
  type KeyBindingProofV1,
} from "../core/trust.js";
import type { AdminState, RecipientEntry } from "../core/types.js";
import type { AdminStateCache } from "./cache.js";
import { resolveRecipient, type RecipientInput } from "./recipient.js";

export interface AddRecipientOptions {
  /**
   * Polymorphic recipient. Accepts a DID string, a 32-byte X25519 public key
   * (jwe), a contacts.yaml row dict, or an AddRecipientResult-like object.
   * Explicit `recipientDid` / `publicKey` fields on this options object
   * override the resolved values.
   */
  recipient?: RecipientInput;
  recipientDid?: string;
  publicKey?: Uint8Array;
  outKitPath?: string;
  cipher?: "btn" | "jwe" | "hibe";
  /**
   * jwe: register the authenticated DID→X25519 binding from one accepted
   * enrollment offer (the normal, verified path). The binding's retained
   * audience/ceremony/group scope is re-checked against this ceremony, and
   * any explicitly supplied `recipientDid`/`publicKey` must match it.
   */
  acceptedOffer?: AcceptedOffer;
  /**
   * jwe: explicit acknowledgment for the raw DID-plus-key registration. Raw
   * registrations are never marked verified, and always emit the common
   * unsafe-operation warning and best-effort audit event.
   */
  unsafeUnverified?: boolean;
}

export interface GrantReaderOptions {
  readerDid?: string;
  idPath?: string;
  outPath?: string;
  /** A verified `hibe-reader` key-binding proof answering this authority's
   * scoped challenge. Grants backed by a proof are recorded as verified. */
  proof?: KeyBindingProofV1;
  /** Required to mint an ANCESTOR of the group's sealing path — the result
   * explicitly records that it delegates the whole subtree below it. */
  allowSubauthority?: boolean;
  /** Explicit plaintext bearer delivery (the only plaintext path). Emits the
   * common unsafe-operation warning/audit and labels the artifact. */
  unsafePlaintext?: boolean;
}

export interface RevokeRecipientOptions {
  /**
   * Polymorphic recipient. Accepts a DID string, an int leafIndex, an
   * AddRecipientResult from the matching addRecipient call, or a
   * contacts.yaml row dict. Explicit `leafIndex` / `recipientDid` fields
   * override the resolved values.
   */
  recipient?: RecipientInput;
  leafIndex?: number;
  recipientDid?: string;
}

export class AdminNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  async addRecipient(group: string, opts: AddRecipientOptions): Promise<AddRecipientResult> {
    // Polymorphic recipient — explicit kwargs win over resolved fields.
    let recipientDid = opts.recipientDid;
    // publicKey is the jwe recipient's raw X25519 public key (consumed by the
    // jwe branch below); for btn the leaf mint doesn't use it.
    if (opts.recipient !== undefined) {
      const resolved = resolveRecipient(opts.recipient);
      if (recipientDid === undefined && resolved.recipientDid !== null) {
        recipientDid = resolved.recipientDid;
      }
    }

    const cipher = (this._rt.config.groups.get(group)?.cipher ?? "btn") as
      | "btn"
      | "jwe"
      | "hibe";

    if (cipher === "hibe") {
      // hibe routes to grantReader (Python: add_recipient -> grant_reader).
      if (opts.publicKey !== undefined) {
        throw new Error(
          `tn.admin.addRecipient: publicKey is JWE-only and was passed to a hibe ` +
            `group ${JSON.stringify(group)}. For hibe, pass outKitPath.`,
        );
      }
      const grantOpts: { readerDid?: string; outPath?: string } = {};
      if (recipientDid !== undefined) grantOpts.readerDid = recipientDid;
      if (opts.outKitPath !== undefined) grantOpts.outPath = opts.outKitPath;
      const granted = this._rt.grantReader(group, grantOpts);
      // Seal the kit to the reader's device key when known — an unsealed kit
      // ships the delegated `.hibe.sk` in cleartext (a bearer token). No-op for
      // a did-less hand-off; the reader unseals via absorbPkgAsync.
      await this._rt.sealKitForRecipient(granted.kitPath, recipientDid);
      const kitSha256 = sha256HexBytes(new Uint8Array(readFileSync(granted.kitPath)));
      return {
        group,
        cipher: "hibe",
        leafIndex: null,
        recipientDid: recipientDid ?? null,
        kitPath: granted.kitPath,
        kitSha256,
        mintedAt: new Date().toISOString(),
        idPath: granted.idPath,
      };
    }

    if (cipher === "jwe") {
      if (opts.acceptedOffer !== undefined) {
        return this._addRecipientJweAccepted(group, opts.acceptedOffer, recipientDid, opts.publicKey);
      }
      // Raw jwe registration: register a DID-plus-key pair directly (no kit
      // minted; mirrors Python `_add_recipient_jwe_impl`). The binding is
      // NOT authenticated, so it persists as `verified: false` and emits the
      // common unsafe-operation warning/audit — pass `unsafeUnverified: true`
      // to acknowledge explicitly.
      if (opts.publicKey === undefined) {
        throw new Error(
          `tn.admin.addRecipient: jwe group ${JSON.stringify(group)} requires publicKey ` +
            `(the recipient's raw 32-byte X25519 public key) or an acceptedOffer.`,
        );
      }
      if (recipientDid === undefined) {
        throw new Error(
          `tn.admin.addRecipient: jwe group ${JSON.stringify(group)} requires recipientDid.`,
        );
      }
      await this._rt.recordUnsafeOperation({
        operation: "jwe_add_recipient",
        relaxations: ["unverified_key_binding"],
        group,
        subject_did: recipientDid,
        artifact_digest: null,
      });
      this._rt.addRecipientJwe(group, recipientDid, opts.publicKey, {
        verified: false,
        proof_digest: null,
        public_key_sha256: sha256Digest(opts.publicKey),
      });
      return {
        group,
        cipher: "jwe",
        leafIndex: null,
        recipientDid,
        kitPath: null,
        kitSha256: null,
        mintedAt: new Date().toISOString(),
        verified: false,
        proofDigest: null,
        publicKeySha256: sha256Digest(opts.publicKey),
      };
    }

    // Default outKitPath: keystore subdir, named <group>.btn.mykit (matches Python).
    const outKitPath =
      opts.outKitPath ?? join(this._rt.config.keystorePath, `${group}.btn.mykit`);

    // Validate suffix (TNClient enforces this too; replicate for the namespace path).
    const basename = outKitPath.split(/[\\/]/).pop() ?? "";
    if (!basename.endsWith(".btn.mykit") || basename === ".btn.mykit") {
      throw new Error(
        `tn.admin.addRecipient: out_path basename must end with '.btn.mykit' ` +
          `(e.g. ${JSON.stringify(group + ".btn.mykit")}), got ${JSON.stringify(basename)}.`,
      );
    }

    // Delegate to NodeRuntime: mint kit, write to disk, emit tn.recipient.added.
    const leafIndex = this._rt.addRecipient(group, outKitPath, recipientDid);

    // Hash the kit file to compute kitSha256 for the result.
    const kitBytes = readFileSync(outKitPath);
    const kitSha256 = sha256HexBytes(new Uint8Array(kitBytes));
    const mintedAt = new Date().toISOString();

    return {
      group,
      cipher,
      leafIndex,
      recipientDid: recipientDid ?? null,
      kitPath: outKitPath,
      kitSha256,
      mintedAt,
    };
  }

  /** Verified jwe registration: consume one AcceptedOffer as a single value. */
  private _addRecipientJweAccepted(
    group: string,
    accepted: AcceptedOffer,
    recipientDid?: string,
    publicKey?: Uint8Array,
  ): AddRecipientResult {
    const binding = accepted.binding;
    const principal = binding.principal;
    if (principal.purpose !== "jwe-reader") {
      throw new TrustError("binding_invalid", "accepted offer is not a jwe-reader binding");
    }
    if (principal.audienceDid !== this._rt.did) {
      throw new TrustError("wrong_recipient", "accepted offer names a different publisher");
    }
    if (principal.ceremonyId !== this._rt.config.ceremonyId || principal.group !== group) {
      throw new TrustError("scope_mismatch", "accepted offer ceremony or group does not match");
    }
    if (recipientDid !== undefined && recipientDid !== principal.did) {
      throw new TrustError(
        "did_signer_mismatch",
        "recipientDid does not match the accepted offer's verified reader",
      );
    }
    if (sha256Digest(binding.publicKey) !== binding.publicKeySha256) {
      throw new TrustError("binding_invalid", "accepted offer key digest does not match its bytes");
    }
    if (publicKey !== undefined) {
      if (
        publicKey.length !== binding.publicKey.length ||
        publicKey.some((byte, index) => byte !== binding.publicKey[index])
      ) {
        throw new TrustError("binding_invalid", "publicKey does not match the accepted offer binding");
      }
    }
    this._rt.addRecipientJwe(group, principal.did, binding.publicKey, {
      verified: true,
      proof_digest: binding.proofDigest,
      public_key_sha256: binding.publicKeySha256,
    });
    return {
      group,
      cipher: "jwe",
      leafIndex: null,
      recipientDid: principal.did,
      kitPath: null,
      kitSha256: null,
      mintedAt: new Date().toISOString(),
      verified: true,
      proofDigest: binding.proofDigest,
      publicKeySha256: binding.publicKeySha256,
    };
  }

  async revokeRecipient(
    group: string,
    opts: RevokeRecipientOptions,
  ): Promise<RevokeRecipientResult> {
    // Polymorphic recipient — explicit kwargs win over resolved fields.
    let leafIndex = opts.leafIndex;
    let recipientDid = opts.recipientDid;
    if (opts.recipient !== undefined) {
      const resolved = resolveRecipient(opts.recipient);
      if (leafIndex === undefined && resolved.leafIndex !== null) {
        leafIndex = resolved.leafIndex;
      }
      if (recipientDid === undefined && resolved.recipientDid !== null) {
        recipientDid = resolved.recipientDid;
      }
    }

    if (leafIndex === undefined && !recipientDid) {
      throw new Error(
        "tn.admin.revokeRecipient: must specify either leafIndex, recipientDid, or recipient",
      );
    }
    const cipher = (this._rt.config.groups.get(group)?.cipher ?? "btn") as
      | "btn"
      | "jwe"
      | "hibe";
    if (cipher === "hibe") {
      // hibe routes to revokeReader (Python: revoke_recipient -> revoke_reader).
      if (!recipientDid) {
        throw new Error("tn.admin.revokeRecipient: recipientDid required for hibe group.");
      }
      if (leafIndex !== undefined) {
        throw new Error(
          "tn.admin.revokeRecipient: leafIndex is btn-only; for hibe use recipientDid.",
        );
      }
      const res = this._rt.revokeReader(group, recipientDid);
      return {
        group,
        cipher: "hibe",
        leafIndex: null,
        recipientDid,
        revokedAt: new Date().toISOString(),
        newKitPath: null,
        newKitSha256: null,
        newPath: res.newPath,
        kitPaths: res.kitPaths,
      };
    }
    if (cipher === "jwe") {
      // jwe revoke_recipient: drop the recipient by DID (keystore + yaml).
      // Mirrors Python `_revoke_recipient_jwe_impl`. O(1), no rotation.
      if (!recipientDid) {
        throw new Error("tn.admin.revokeRecipient: recipientDid required for jwe group.");
      }
      this._rt.revokeRecipientJwe(group, recipientDid);
      return {
        group,
        cipher: "jwe",
        leafIndex: null,
        recipientDid,
        revokedAt: new Date().toISOString(),
        newKitPath: null,
        newKitSha256: null,
      };
    }

    const finalLeafIndex =
      leafIndex !== undefined
        ? leafIndex
        : this._resolveLeafForDid(group, recipientDid!);
    this._rt.revokeRecipient(group, finalLeafIndex, recipientDid);
    return {
      group,
      cipher,
      leafIndex: finalLeafIndex,
      recipientDid: recipientDid ?? null,
      revokedAt: new Date().toISOString(),
      newKitPath: null, // btn: no rotation
      newKitSha256: null,
    };
  }

  private _resolveLeafForDid(group: string, did: string): number {
    const list = this.recipients(group);
    const match = list.find((r) => r.recipient_identity === did);
    if (!match) {
      throw new Error(
        `tn.admin.revokeRecipient: no active recipient with did=${did} in group=${group}`,
      );
    }
    return match.leafIndex;
  }

  /**
   * HIBE's add_recipient: mint a delegated identity key for the group's
   * (or an ancestor) identity path and package it as an absorbable
   * `.tnpkg` kit. Mirrors Python `tn.admin.grant_reader`. Grants are
   * recorded in the authority-side `<group>.hibe.grants` registry, which
   * never rides a kit; the msk never leaves the authority keystore.
   *
   * The normal grant is a verified, recipient-sealed delivery: pass a
   * `hibe-reader` `proof` answering this authority's scoped challenge (or
   * rely on a retained, unexpired verified-reader record for the same
   * scope). A proof-less grant stays available for compatibility but is
   * recorded unverified and emits the common unsafe-operation warning and
   * audit event; `unsafePlaintext: true` is the only plaintext path. An
   * ancestor `idPath` additionally requires `allowSubauthority: true`.
   */
  async grantReader(group: string, opts: GrantReaderOptions = {}): Promise<AddRecipientResult> {
    let verified = false;
    let proofDigest: string | null = null;
    let proofExpiresAt: string | undefined;

    if (opts.proof !== undefined) {
      if (opts.readerDid === undefined) {
        throw new TrustError("untrusted_principal", "a proof-backed grant requires readerDid");
      }
      if (opts.proof.subject_did !== opts.readerDid) {
        throw new TrustError(
          "did_signer_mismatch",
          "proof subject does not match the grant's readerDid",
        );
      }
      const boundDigest = opts.proof.binding["challenge_digest"];
      let challenge: EnrollmentChallengeV1 | undefined;
      if (typeof boundDigest === "string") {
        challenge = this._rt.enrollmentStore().challengeForDigest(boundDigest);
      }
      const principal = verifyKeyBindingProof(opts.proof, {
        purpose: "hibe-reader",
        audienceDid: this._rt.did,
        ceremonyId: this._rt.config.ceremonyId,
        group,
        now: formatTrustTimestamp(Date.now() * 1000),
        ...(challenge === undefined ? {} : { challenge }),
      });
      verified = true;
      proofDigest = principal.proofDigest;
      proofExpiresAt = principal.expiresAt;
    } else if (opts.readerDid !== undefined) {
      // A previously verified reader record may satisfy the requirement for
      // the exact same authority, ceremony, and group scope.
      const retained = this._rt.retainedVerifiedGrant(group, opts.readerDid);
      if (retained !== null) {
        verified = true;
        proofDigest = retained.proofDigest;
      }
    }

    const mintOpts: Parameters<NodeRuntime["grantReader"]>[1] = {
      grantTrust: {
        verified,
        ...(proofDigest === null ? {} : { proofDigest }),
        ...(proofExpiresAt === undefined ? {} : { proofExpiresAt: proofExpiresAt }),
      },
    };
    if (opts.readerDid !== undefined) mintOpts.readerDid = opts.readerDid;
    if (opts.idPath !== undefined) mintOpts.idPath = opts.idPath;
    if (opts.outPath !== undefined) mintOpts.outPath = opts.outPath;
    if (opts.allowSubauthority !== undefined) mintOpts.allowSubauthority = opts.allowSubauthority;
    if (opts.unsafePlaintext === true) mintOpts.unsafePlaintextLabel = true;
    const granted = this._rt.grantReader(group, mintOpts);

    // Delivery: recipient-sealed by default — an unsealed kit ships the
    // delegated `.hibe.sk` in cleartext (a bearer token). The reader unseals
    // via absorbPkgAsync.
    let sealed = false;
    if (opts.unsafePlaintext === true) {
      await this._rt.recordUnsafeOperation({
        operation: "hibe_grant",
        relaxations: verified
          ? ["plaintext_bearer_delivery"]
          : ["plaintext_bearer_delivery", "unverified_key_binding"],
        group,
        subject_did: opts.readerDid ?? null,
        artifact_digest: null,
      });
    } else {
      sealed = await this._rt.sealKitForRecipient(granted.kitPath, opts.readerDid);
      if (verified && !sealed) {
        throw new TrustError(
          "binding_invalid",
          "verified grant delivery requires a resolvable Ed25519 did:key to seal to",
        );
      }
      if (!verified) {
        await this._rt.recordUnsafeOperation({
          operation: "hibe_grant",
          relaxations: sealed
            ? ["unverified_key_binding"]
            : ["plaintext_bearer_delivery", "unverified_key_binding"],
          group,
          subject_did: opts.readerDid ?? null,
          artifact_digest: null,
        });
      }
    }

    const kitSha256 = sha256HexBytes(new Uint8Array(readFileSync(granted.kitPath)));
    return {
      group,
      cipher: "hibe",
      leafIndex: null,
      recipientDid: opts.readerDid ?? null,
      kitPath: granted.kitPath,
      kitSha256,
      mintedAt: new Date().toISOString(),
      idPath: granted.idPath,
      verified,
      proofDigest,
      sealed,
      subtreeDelegation: granted.subtreeDelegation,
    };
  }

  /**
   * Sign this authority's current MPK, encoded maximum depth, sealing path,
   * and path epoch as a `hibe-authority` key-binding assertion, addressed to
   * `opts.audienceDid` (default: self). External writers install it via
   * {@link installHibeAuthorityAssertion} before they may seal.
   */
  async issueHibeAuthorityAssertion(
    group: string,
    ttlMs: number,
    opts: { audienceDid?: string } = {},
  ): Promise<KeyBindingProofV1> {
    return this._rt.issueHibeAuthorityAssertion(group, ttlMs, opts);
  }

  /**
   * Issue a scoped one-time challenge for a prospective HIBE reader. The
   * reader answers with `createHibeReaderProof`, and the resulting proof
   * authorizes a verified {@link grantReader} call.
   */
  async issueHibeReaderChallenge(
    group: string,
    readerDid: string,
    ttlMs: number,
  ): Promise<EnrollmentChallengeV1> {
    return this._rt.enrollmentStore().issueChallenge(readerDid, group, ttlMs);
  }

  /**
   * External-writer accept/pin/update of a HIBE authority assertion: verify
   * the authority DID and signature, the MPK bytes and encoded depth against
   * the binding, the exact scope, and the monotonic path epoch — then pin
   * the record and install the group's public sealing material. A writer
   * cannot seal merely because raw MPK bytes and an id_path are present.
   */
  async installHibeAuthorityAssertion(options: {
    group: string;
    mpk: Uint8Array;
    assertion: KeyBindingProofV1;
    expectedAuthorityDid: string;
  }): Promise<void> {
    this._rt.installHibeAuthorityAssertion(options);
  }

  /**
   * Rotate this authority's identity path and return the new strictly
   * higher-epoch signed assertion in one step.
   */
  async rotateHibePathWithAssertion(
    group: string,
    newPath: string,
  ): Promise<{ group: string; idPath: string; pathEpoch: number; assertion: KeyBindingProofV1 }> {
    return this._rt.rotateHibePathWithAssertion(group, newPath);
  }

  /**
   * Rotate a hibe group's identity path so FUTURE seals use `newPath`
   * (admission rotation, not btn-grade revocation — pre-rotation entries
   * stay open forever for prior grantees). Mirrors Python
   * `tn.admin.rotate_reader_path`. Returns the new path.
   */
  async rotateReaderPath(group: string, newPath: string): Promise<string> {
    return this._rt.rotateReaderPath(group, newPath);
  }

  /**
   * Remove a hibe reader going FORWARD: rotate the group's identity path
   * and re-issue kits to every other granted reader. Mirrors Python
   * `tn.admin.revoke_reader` (see its docstring for the honest semantics:
   * the revoked reader keeps everything sealed before the revocation).
   */
  async revokeReader(
    group: string,
    readerDid: string,
    opts: { newPath?: string; outDir?: string } = {},
  ): Promise<RevokeReaderResult> {
    return this._rt.revokeReader(group, readerDid, opts);
  }

  async rotate(group: string): Promise<RotateGroupResult> {
    const groupSpec = this._rt.config.groups.get(group);
    if (!groupSpec) {
      throw new Error(`tn.admin.rotate: unknown group ${JSON.stringify(group)}`);
    }
    const cipher = (groupSpec.cipher ?? "btn") as "btn" | "jwe" | "hibe";
    if (cipher === "hibe") {
      throw new Error(
        `tn.admin.rotate: group ${JSON.stringify(group)} uses cipher 'hibe'; this ` +
          `rotation is btn/jwe-only. hibe groups rotate their identity path via ` +
          `tn.admin.rotateReaderPath (or revokeReader).`,
      );
    }

    if (cipher === "btn") {
      // 0.4.0a3+: TS BTN rotation now mirrors Python end-to-end.
      // NodeRuntime.rotateGroup mints a fresh BtnPublisher, swaps the
      // on-disk state + self-kit, bumps groups.<g>.index_epoch in the
      // yaml, and emits tn.rotation.completed. Surviving recipients
      // appear unchanged in `recipients(group)` — the publisher (or the
      // `tn-js admin rotate` CLI) re-mints kits for them via
      // addRecipient and ships per-recipient .tnpkg artifacts.
      const result = this._rt.rotateGroup(group);
      return {
        group,
        cipher: "btn",
        generation: result.generation,
        previousKitSha256: result.previousKitSha256,
        newKitSha256: result.newKitSha256,
        rotatedAt: result.rotatedAt,
      };
    }
    if (cipher === "jwe") {
      // jwe rotate: archive + regenerate keys, bump the epoch, and emit
      // tn.rotation.completed. Prior recipients must re-enroll. Mirrors Python.
      return this._rt.rotateGroupJwe(group);
    }
    // Unreachable but keeps TS happy.
    throw new Error(`tn.admin.rotate: unknown cipher=${cipher}`);
  }

  async ensureGroup(
    group: string,
    opts?: { cipher?: "btn" | "jwe" | "hibe"; fields?: string[] },
  ): Promise<EnsureGroupResult> {
    const cipher = opts?.cipher ?? "btn";
    const state = this.state();
    const existing = state.groups.find((g) => g.group === group);
    if (existing) {
      // Idempotent re-ensure: the group is already attested, but still honor
      // `fields` routing (matches Python's ensure_group on an existing group).
      if (opts?.fields && opts.fields.length > 0) {
        this._rt.adminRouteFields(group, opts.fields);
      }
      return {
        group,
        cipher: existing.cipher as "btn" | "jwe" | "hibe",
        created: false,
        publisherDid: existing.publisherDid,
        addedAt: existing.addedAt,
      };
    }
    // Group not yet attested in the log — emit tn.group.added.
    const receipt = this._rt.adminEnsureGroup(group, cipher, opts?.fields);
    const addedAt = new Date().toISOString();
    return {
      group,
      cipher,
      created: true,
      publisherDid: this._rt.did,
      addedAt: receipt.eventId ? addedAt : addedAt,
    };
  }

  recipients(group: string, opts?: { includeRevoked?: boolean }): RecipientEntry[] {
    return this._rt.recipients(group, opts);
  }

  state(group?: string): AdminState {
    return this._rt.adminState(group);
  }

  cache(): AdminStateCache {
    return this._rt.adminCache();
  }

  revokedCount(group: string): number {
    return this._rt.revokedCount(group);
  }
}
