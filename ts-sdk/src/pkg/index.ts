// tn.pkg.* namespace — Phase 2 verb surface for tnpkg / package operations.
// Methods are populated in Task 2.7.

import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import type { NodeRuntime } from "../runtime/node_runtime.js";
import { sha256HexBytes } from "../core/chain.js";
import { compileKitBundleToFile } from "../compile.js";
import type {
  AbsorbReceipt,
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
}

export interface OfferOptions {
  group: string;
  peerDid: string;
  outPath: string;
}

export interface CompileEnrolmentOptions {
  group: string;
  recipientDid: string;
  outPath: string;
}

export interface CompiledPackage {
  outPath: string;
  manifestSha256: string;
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
   */
  async absorb(source: string | Uint8Array): Promise<AbsorbReceipt> {
    return this._rt.absorbPkg(source);
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
    const bundlePath = this._rt.bundleForRecipient(
      opts.recipientDid,
      opts.outPath,
      bundleOpts,
    );
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
  async compileEnrolment(opts: CompileEnrolmentOptions): Promise<CompiledPackage> {
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
      peer_did: opts.peerDid,
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
}
