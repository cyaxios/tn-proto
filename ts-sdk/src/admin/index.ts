// tn.admin.* namespace — Phase 2 verb surface for ceremony admin operations.
// Methods are populated in Task 2.6.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sha256HexBytes } from "../core/chain.js";
import type { NodeRuntime } from "../runtime/node_runtime.js";
import type {
  AddRecipientResult,
  RevokeRecipientResult,
  RotateGroupResult,
  EnsureGroupResult,
} from "../core/results.js";
import type { AdminState, RecipientEntry } from "../core/types.js";
import type { AdminStateCache } from "./cache.js";

export interface AddRecipientOptions {
  recipientDid?: string;
  outKitPath?: string;
  cipher?: "btn" | "jwe";
}

export interface RevokeRecipientOptions {
  leafIndex?: number;
  recipientDid?: string;
}

export class AdminNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  async addRecipient(group: string, opts: AddRecipientOptions): Promise<AddRecipientResult> {
    // Default outKitPath: keystore subdir, named <group>.btn.mykit (matches Python).
    const outKitPath =
      opts.outKitPath ?? join(this._rt.config.keystorePath, `${group}.btn.mykit`);
    const cipher = (this._rt.config.groups.get(group)?.cipher ?? "btn") as "btn" | "jwe";

    // Validate suffix (TNClient enforces this too; replicate for the namespace path).
    const basename = outKitPath.split(/[\\/]/).pop() ?? "";
    if (!basename.endsWith(".btn.mykit") || basename === ".btn.mykit") {
      throw new Error(
        `tn.admin.addRecipient: out_path basename must end with '.btn.mykit' ` +
          `(e.g. ${JSON.stringify(group + ".btn.mykit")}), got ${JSON.stringify(basename)}.`,
      );
    }

    // Delegate to NodeRuntime: mint kit, write to disk, emit tn.recipient.added.
    const leafIndex = this._rt.addRecipient(group, outKitPath, opts.recipientDid);

    // Hash the kit file to compute kitSha256 for the result.
    const kitBytes = readFileSync(outKitPath);
    const kitSha256 = sha256HexBytes(new Uint8Array(kitBytes));
    const mintedAt = new Date().toISOString();

    return {
      group,
      cipher,
      leafIndex,
      recipientDid: opts.recipientDid ?? null,
      kitPath: outKitPath,
      kitSha256,
      mintedAt,
    };
  }

  async revokeRecipient(
    group: string,
    opts: RevokeRecipientOptions,
  ): Promise<RevokeRecipientResult> {
    if (opts.leafIndex === undefined && !opts.recipientDid) {
      throw new Error(
        "tn.admin.revokeRecipient: must specify either leafIndex or recipientDid",
      );
    }
    const cipher = (this._rt.config.groups.get(group)?.cipher ?? "btn") as "btn" | "jwe";
    const leafIndex =
      opts.leafIndex !== undefined
        ? opts.leafIndex
        : this._resolveLeafForDid(group, opts.recipientDid!);
    this._rt.revokeRecipient(group, leafIndex, opts.recipientDid);
    return {
      group,
      cipher,
      leafIndex,
      recipientDid: opts.recipientDid ?? null,
      revokedAt: new Date().toISOString(),
      newKitPath: null, // btn: no rotation
      newKitSha256: null,
    };
  }

  private _resolveLeafForDid(group: string, did: string): number {
    const list = this.recipients(group);
    const match = list.find((r) => r.recipientDid === did);
    if (!match) {
      throw new Error(
        `tn.admin.revokeRecipient: no active recipient with did=${did} in group=${group}`,
      );
    }
    return match.leafIndex;
  }

  async rotate(_group: string): Promise<RotateGroupResult> {
    const cipher = (this._rt.config.groups.get(_group)?.cipher ?? "btn") as "btn" | "jwe";
    if (cipher === "btn") {
      throw new Error(
        "tn.admin.rotate: btn cipher does not support in-band rotation. " +
          "Use tn.admin.revokeRecipient + tn.admin.addRecipient instead.",
      );
    }
    if (cipher === "jwe") {
      throw new Error("tn.admin.rotate: jwe cipher rotation not yet implemented in TS SDK.");
    }
    // Unreachable but keeps TS happy.
    throw new Error(`tn.admin.rotate: unknown cipher=${cipher}`);
  }

  async ensureGroup(
    group: string,
    opts?: { cipher?: "btn" | "jwe" },
  ): Promise<EnsureGroupResult> {
    const cipher = opts?.cipher ?? "btn";
    const state = this.state();
    const existing = state.groups.find((g) => g.group === group);
    if (existing) {
      return {
        group,
        cipher: existing.cipher as "btn" | "jwe",
        created: false,
        publisherDid: existing.publisherDid,
        addedAt: existing.addedAt,
      };
    }
    // Group not yet attested in the log — emit tn.group.added.
    const receipt = this._rt.adminEnsureGroup(group, cipher);
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
