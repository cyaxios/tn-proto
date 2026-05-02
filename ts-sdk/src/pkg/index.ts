// tn.pkg.* namespace — Phase 2 verb surface for tnpkg / package operations.
// Methods are populated in Task 2.7.

import type { NodeRuntime } from "../runtime/node_runtime.js";
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

  async export(_opts: ExportOptions, _outPath: string): Promise<string> {
    throw new Error("tn.pkg.export: not implemented (Task 2.7)");
  }
  async absorb(_source: string | Uint8Array): Promise<AbsorbReceipt> {
    throw new Error("tn.pkg.absorb: not implemented (Task 2.7)");
  }
  async bundleForRecipient(_opts: BundleForRecipientOptions): Promise<BundleResult> {
    throw new Error("tn.pkg.bundleForRecipient: not implemented (Task 2.7)");
  }
  async compileEnrolment(_opts: CompileEnrolmentOptions): Promise<CompiledPackage> {
    throw new Error("tn.pkg.compileEnrolment: not implemented (Task 2.7)");
  }
  async offer(_opts: OfferOptions): Promise<OfferReceipt> {
    throw new Error("tn.pkg.offer: not implemented (Task 2.7)");
  }
}
