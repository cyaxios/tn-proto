// tn.pkg.* namespace - verb surface for tnpkg / package operations.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";
import { Buffer } from "node:buffer";
import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { CeremonyConfig } from "../runtime/config.js";
import { sha256HexBytes } from "../core/chain.js";
import { compileKitBundleToFile } from "../compile.js";
import { mintAndSealBundle, recipientKeyIsResolvable } from "../seal_bundle_producer.js";
import type { AcceptedOffer, EnrollmentChallengeV1 } from "../core/trust.js";
import {
  buildEnrollmentResponseArtifact,
  buildJweOfferArtifact,
} from "../runtime/enrollment.js";
import type {
  AbsorbReceipt,
  AbsorbResult,
  BundleResult,
  OfferReceipt,
} from "../core/results.js";

export interface ExportOptions {
  /** Mint a per-recipient kit and write it to outPath. */
  kit?: { recipientDid: string; outPath: string };
  /** Build a recipient-specific tnpkg bundle (kit + admin-log snapshot + chosen groups). */
  bundle?: { recipientDid: string; outPath: string; groups?: string[]; includeAdminLog?: boolean };
  /** Snapshot the admin log only (no per-recipient state). */
  adminLogSnapshot?: { outPath: string };
  /** Self-kit export (the publisher's own decryption key bundle, for restoring on a new device). */
  selfKit?: { outPath: string; passphrase?: string };
}

export interface BundleForRecipientOptions {
  recipientDid: string;
  outPath: string;
  groups?: string[];
  includeAdminLog?: boolean;
  /**
   * Seal the bundle body under a per-export key wrapped to `recipientDid`,
   * so only the holder of that DID's private seed can decrypt the kits.
   *
   * Mirrors Python `tn.pkg.bundle_for_recipient(..., seal_for_recipient=True)`.
   * Requires a real `did:key:z...` recipient with an embedded Ed25519
   * public key to wrap under; a synthetic / keyless DID is rejected
   * up front (same validation as Python and the `tn bundle
   * --seal-for-recipient` CLI verb). Defaults to `false` (plaintext
   * kit_bundle, the existing behaviour).
   */
  sealForRecipient?: boolean;
}

export interface OfferOptions {
  group: string;
  peerDid: string;
  outPath: string;
  /**
   * A publisher-signed enrollment challenge. When present, the offer becomes
   * a trusted JWE enrollment offer: the challenge is verified against
   * `peerDid` first, this reader's static X25519 key is created (or reused)
   * for the group, and a signed `KeyBindingProofV1` bound to the exact
   * challenge digest is packaged for the publisher to absorb.
   */
  challenge?: EnrollmentChallengeV1;
}

export interface CompileEnrolmentOptions {
  group: string;
  recipientDid: string;
  outPath: string;
}

/** Trusted-enrollment response compilation consumes one AcceptedOffer. */
export interface CompileEnrolmentResponseOptions extends CompileEnrolmentOptions {
  acceptedOffer: AcceptedOffer;
  ttlMs: number;
}

export interface CompiledPackage {
  outPath: string;
  manifestSha256: string;
}

/**
 * Translate a new-style {@link AbsorbReceipt} into the legacy flat
 * {@link AbsorbResult} shape returned by the two-arg `absorb(cfg, source)`
 * form.
 *
 * Mirrors Python `tn.absorb.absorb`'s legacy branch:
 *   - A rejection (`rejectedReason` set) maps to `status="rejected"`.
 *   - `admin_log_snapshot` maps to `no_op` (when nothing was applied) or
 *     `enrolment_applied`.
 *   - Other applied kinds (kit_bundle, full_keystore, group_keys,
 *     identity_seed, project_seed, offer, enrolment, contact_update) map
 *     to `no_op` when the absorb was a no-op (idempotent / clock-dominated)
 *     and `enrolment_applied` when work landed.
 *   - An unknown / unsupported kind with no rejection reason maps to
 *     `status="rejected", reason="unknown kind"` (Python's default tail).
 *
 * The TS `AbsorbReceipt` does not carry Python's `peer_did`, so `peerDid`
 * is always `null` here (Python likewise leaves it `None` for the snapshot
 * / seed kinds that flow through this path).
 */
function _toLegacyAbsorbResult(receipt: AbsorbReceipt): AbsorbResult {
  if (receipt.rejectedReason) {
    return { status: "rejected", reason: receipt.rejectedReason, peerDid: null };
  }
  const applied = receipt.acceptedCount > 0;
  if (receipt.noop || (!applied && receipt.dedupedCount > 0)) {
    return { status: "no_op", reason: "", peerDid: null };
  }
  if (applied) {
    return { status: "enrolment_applied", reason: "", peerDid: null };
  }
  // No rejection reason, nothing applied, nothing deduped: treat as a
  // no-op for known kinds, and as rejected (Python's default tail) for an
  // unrecognised kind.
  if (receipt.kind === "unknown" || receipt.kind === "") {
    return { status: "rejected", reason: "unknown kind", peerDid: null };
  }
  return { status: "no_op", reason: "", peerDid: null };
}

export class PkgNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  /**
   * Pack a `.tnpkg` from local ceremony state and write it to `outPath`.
   * Delegates to `NodeRuntime.exportPkg` which handles all manifest kind
   * variants (admin_log_snapshot, kit_bundle, full_keystore, offer, enrolment).
   * Returns the absolute path to the written file.
   */
  async export(opts: ExportOptions, outPath: string): Promise<string> {
    if (opts.adminLogSnapshot) {
      return this._rt.exportPkg({ kind: "admin_log_snapshot" }, outPath);
    }
    if (opts.selfKit) {
      return this._rt.exportPkg(
        { kind: "full_keystore", confirmIncludesSecrets: true },
        outPath,
      );
    }
    if (opts.bundle) {
      const b = opts.bundle;
      const exportOpts: Parameters<typeof this._rt.exportPkg>[0] = {
        kind: "kit_bundle",
        toDid: b.recipientDid,
      };
      if (b.groups !== undefined) exportOpts.groups = b.groups;
      return this._rt.exportPkg(exportOpts, outPath);
    }
    if (opts.kit) {
      const k = opts.kit;
      return this._rt.exportPkg({ kind: "kit_bundle", toDid: k.recipientDid }, outPath);
    }
    throw new Error(
      "tn.pkg.export: must supply one of opts.kit, opts.bundle, opts.adminLogSnapshot, or opts.selfKit",
    );
  }

  /**
   * Apply a `.tnpkg` file or raw bytes to local state. Idempotent.
   * Delegates to `NodeRuntime.absorbPkg`.
   *
   * Two call shapes, mirroring Python `tn.pkg.absorb`:
   *
   *   tn.pkg.absorb(source)        // new — returns AbsorbReceipt
   *   tn.pkg.absorb(cfg, source)   // legacy two-arg — returns AbsorbResult
   *
   * The legacy two-arg form returns the flatter {@link AbsorbResult}
   * (`{ status, reason, peerDid }`) for back-compat with callers that
   * match on `.status` / `.reason`. The `cfg` argument is accepted for
   * signature parity with the Python reference (which threads a
   * `LoadedConfig` through); the TS runtime is already bound to its own
   * config, so the absorb uses the bound runtime either way. The new
   * one-arg form is the canonical surface and is unchanged.
   */
  async absorb(
    source: string | Uint8Array,
    opts?: { unsafeLegacySigner?: boolean },
  ): Promise<AbsorbReceipt>;
  async absorb(cfg: CeremonyConfig, source: string | Uint8Array): Promise<AbsorbResult>;
  async absorb(
    a: CeremonyConfig | string | Uint8Array,
    b?: string | Uint8Array | { unsafeLegacySigner?: boolean },
  ): Promise<AbsorbReceipt | AbsorbResult> {
    if (typeof a === "string" || a instanceof Uint8Array) {
      // New form: a is the source, b (when present) is the options object.
      const opts = b !== undefined && !(b instanceof Uint8Array) && typeof b !== "string" ? b : {};
      return this._rt.absorbPkg(a, opts);
    }
    // Legacy two-arg form: a is the cfg (accepted for parity), b is the
    // source. Run the absorb and translate to the flat AbsorbResult shape.
    const receipt = this._rt.absorbPkg(b as string | Uint8Array);
    return _toLegacyAbsorbResult(receipt);
  }

  /**
   * Mint fresh kits for `opts.recipientDid` across the specified groups
   * (or all non-internal groups if omitted), bundle them into a `.tnpkg`,
   * and return a `BundleResult` with path + sha256 + group list.
   *
   * Delegates to `NodeRuntime.bundleForRecipient` which avoids FINDINGS #5
   * (accidentally shipping the publisher's own self-kit).
   */
  async bundleForRecipient(opts: BundleForRecipientOptions): Promise<BundleResult> {
    const bundleOpts: { groups?: string[] } = {};
    if (opts.groups !== undefined) bundleOpts.groups = opts.groups;

    let bundlePath: string;
    if (opts.sealForRecipient) {
      // Seal the body under a fresh per-export BEK wrapped to the
      // recipient DID (parity with Python's seal_for_recipient=True).
      // Reject a keyless / synthetic DID up front — there is nothing to
      // wrap the BEK under (matches Python validation + the CLI verb).
      if (!recipientKeyIsResolvable(opts.recipientDid)) {
        throw new Error(
          "tn.pkg.bundleForRecipient: sealForRecipient requires a recipient " +
            "did:key:z... with an embedded Ed25519 public key to wrap the body " +
            `key under; ${JSON.stringify(opts.recipientDid)} has none. Pass the ` +
            "recipient's real did:key, or drop sealForRecipient to ship an " +
            "unsealed kit bundle.",
        );
      }
      // Mint an unsealed kit_bundle to a temp path, then seal it under a
      // fresh BEK wrapped to the recipient. Composes the existing seal
      // primitives (encryptBodyBlob + buildRecipientWraps); no plaintext
      // body ever reaches opts.outPath. Mirrors the CLI `tn bundle
      // --seal-for-recipient` composition.
      const sealed = await mintAndSealBundle({
        recipientDid: opts.recipientDid,
        publisherKey: this._rt.keystore.device,
        outPath: opts.outPath,
        mintUnsealed: (tmpUnsealedPath: string) =>
          this._rt.bundleForRecipient(opts.recipientDid, tmpUnsealedPath, bundleOpts),
      });
      bundlePath = sealed.outPath;
    } else {
      bundlePath = this._rt.bundleForRecipient(
        opts.recipientDid,
        opts.outPath,
        bundleOpts,
      );
    }
    const bundleBytes = readFileSync(bundlePath);
    const bundleSha256 = sha256HexBytes(new Uint8Array(bundleBytes));
    const resolvedGroups = opts.groups?.slice().sort() ?? [];
    return {
      bundlePath,
      bundleSha256,
      recipientDid: opts.recipientDid,
      groups: resolvedGroups,
      manifestPath: bundlePath,
    };
  }

  /**
   * Compile a kit bundle for a single recipient/group into a `.tnpkg` file.
   * Uses the standalone `compileKitBundleToFile` helper from `compile.ts`,
   * which reads kits from the keystore directory directly (no minting).
   *
   * Returns `CompiledPackage` with the resolved output path and manifest sha256.
   */
  async compileEnrolment(opts: CompileEnrolmentOptions): Promise<CompiledPackage>;
  async compileEnrolment(opts: CompileEnrolmentResponseOptions): Promise<CompiledPackage>;
  async compileEnrolment(
    opts: CompileEnrolmentOptions & { acceptedOffer?: AcceptedOffer; ttlMs?: number },
  ): Promise<CompiledPackage> {
    if (opts.acceptedOffer !== undefined) {
      return this._compileEnrolmentResponse(opts as CompileEnrolmentResponseOptions);
    }
    const result = compileKitBundleToFile({
      keystoreDir: this._rt.config.keystorePath,
      groups: [opts.group],
      outPath: opts.outPath,
    });
    // Hash the manifest JSON bytes for the receipt.
    const manifestBytes = new Uint8Array(
      Buffer.from(JSON.stringify(result.manifest, null, 2) + "\n"),
    );
    const manifestSha256 = sha256HexBytes(manifestBytes);
    return {
      outPath: result.outPath,
      manifestSha256,
    };
  }

  /**
   * Compile the publisher's signed `EnrollmentResponseV1` package for an
   * accepted JWE offer. Consumes exactly one {@link AcceptedOffer} — the
   * response embeds ITS offer and X25519 key digests, so a valid binding can
   * never be paired with another offer's digest. The reader absorbs the
   * resulting `.tnpkg` to install this publisher as a verified writer.
   */
  private async _compileEnrolmentResponse(
    opts: CompileEnrolmentResponseOptions,
  ): Promise<CompiledPackage> {
    const principal = opts.acceptedOffer.binding.principal;
    if (opts.recipientDid !== principal.did) {
      throw new Error(
        `tn.pkg.compileEnrolment: did_signer_mismatch: recipientDid ` +
          `${JSON.stringify(opts.recipientDid)} does not match the accepted offer's reader ` +
          `${JSON.stringify(principal.did)}`,
      );
    }
    const groupEpoch = this._rt.config.groups.get(opts.group)?.indexEpoch ?? 0;
    const { artifact } = buildEnrollmentResponseArtifact({
      publisherKey: this._rt.keystore.device,
      ceremonyId: this._rt.config.ceremonyId,
      group: opts.group,
      groupEpoch,
      accepted: opts.acceptedOffer,
      ttlMs: opts.ttlMs,
    });
    const outPath = pathResolve(opts.outPath);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, Buffer.from(artifact));
    return { outPath, manifestSha256: sha256HexBytes(artifact) };
  }

  /**
   * Publisher pre-authorization: record `readerDid` as the expected reader
   * for `group` and issue a signed one-time enrollment challenge with a
   * `ttlMs` acceptance window. The reader answers via `offer({ challenge })`.
   */
  async issueEnrollmentChallenge(
    readerDid: string,
    group: string,
    ttlMs: number,
  ): Promise<EnrollmentChallengeV1> {
    return this._rt.issueEnrollmentChallenge(readerDid, group, ttlMs);
  }

  /**
   * Reverify one retained pending offer and promote it when authorized —
   * a challenged offer from a preauthorized reader, or an offer whose exact
   * digest was already approved. Unsolicited offers stay pending until
   * {@link approveAndReconcile}.
   */
  async reconcilePending(digest: string): Promise<AcceptedOffer> {
    const store = this._rt.enrollmentStore();
    return store.reconcile(store.pendingOffer(digest));
  }

  /**
   * Approve the exact retained offer digest, then reverify, consume the
   * challenge, promote, and register the acceptance atomically under the
   * enrollment lock. Idempotent for the exact same bytes.
   */
  async approveAndReconcile(digest: string): Promise<AcceptedOffer> {
    return this._rt.enrollmentStore().approveAndReconcile(digest);
  }

  /**
   * NEW verb — port of Python's `tn.offer`.
   *
   * Produces a `.tnpkg` containing a kit_bundle for `opts.peerDid`,
   * intended to be sent to that peer so they can absorb it and begin
   * reading encrypted log entries.
   *
   * Semantics:
   *   1. Compile a kit_bundle for the peer via `compileEnrolment`.
   *   2. Hash the resulting package for the receipt.
   *   3. Emit a `tn.offer.compiled` attested event so the local log
   *      records the offer (mirrors Python `offer.py`'s emit_to_outbox).
   *   4. Return `OfferReceipt` with status="offered".
   *
   * Note: Python's `offer.py` emits a Package with package_kind="offer"
   * to an outbox file via emit_to_outbox. The TS equivalent emits
   * a `tn.offer.compiled` info event to the ceremony log instead
   * (the outbox pattern is not yet implemented in the TS SDK).
   */
  async offer(opts: OfferOptions): Promise<OfferReceipt> {
    // Trusted JWE enrollment offer: answer the publisher's signed challenge
    // with a signed key-binding proof over this reader's static X25519 key.
    if (opts.challenge !== undefined) {
      return this._offerTrustedEnrollment(opts, opts.challenge);
    }

    // Step 1: compile a kit_bundle for the peer.
    const compiled = await this.compileEnrolment({
      group: opts.group,
      recipientDid: opts.peerDid,
      outPath: opts.outPath,
    });

    // Step 2: hash the written package file.
    const pkgBytes = readFileSync(compiled.outPath);
    const packageSha256 = sha256HexBytes(new Uint8Array(pkgBytes));

    // Step 3: emit a tn.offer.compiled event for local log attestation.
    // Python's offer.py uses package_kind="offer" and emits to outbox;
    // here we attest to the ceremony log which is the TS equivalent.
    this._rt.emit("info", "tn.offer.compiled", {
      group: opts.group,
      peer_identity: opts.peerDid,
      package_sha256: `sha256:${packageSha256}`,
      package_path: compiled.outPath,
    });

    // Step 4: return the receipt.
    return {
      group: opts.group,
      peerDid: opts.peerDid,
      packageSha256,
      status: "offered",
      packagePath: compiled.outPath,
    };
  }

  /** Build, retain, and write the challenged trusted enrollment offer. */
  private async _offerTrustedEnrollment(
    opts: OfferOptions,
    challenge: EnrollmentChallengeV1,
  ): Promise<OfferReceipt> {
    const built = buildJweOfferArtifact({
      readerKey: this._rt.keystore.device,
      readerKeystoreDir: this._rt.config.keystorePath,
      publisherDid: opts.peerDid,
      ceremonyId: challenge.ceremony_id,
      group: opts.group,
      challenge,
    });
    const outPath = pathResolve(opts.outPath);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, Buffer.from(built.artifact));
    const packageSha256 = sha256HexBytes(built.artifact);
    this._rt.emit("info", "tn.offer.compiled", {
      group: opts.group,
      peer_identity: opts.peerDid,
      package_sha256: `sha256:${packageSha256}`,
      package_path: outPath,
      offer_digest: built.offerDigest,
    });
    return {
      group: opts.group,
      peerDid: opts.peerDid,
      packageSha256,
      status: "offered",
      packagePath: outPath,
      offerDigest: built.offerDigest,
    };
  }
}
