// tn.admin.* namespace — verb surface for ceremony admin operations.

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
  cipher?: "btn" | "jwe";
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
    // publicKey is captured for future jwe support (TS jwe-add lands later);
    // for btn the leaf mint doesn't consume it.
    if (opts.recipient !== undefined) {
      const resolved = resolveRecipient(opts.recipient);
      if (recipientDid === undefined && resolved.recipientDid !== null) {
        recipientDid = resolved.recipientDid;
      }
    }

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
    const cipher = (this._rt.config.groups.get(group)?.cipher ?? "btn") as "btn" | "jwe";
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

  async rotate(group: string): Promise<RotateGroupResult> {
    const groupSpec = this._rt.config.groups.get(group);
    if (!groupSpec) {
      throw new Error(`tn.admin.rotate: unknown group ${JSON.stringify(group)}`);
    }
    const cipher = (groupSpec.cipher ?? "btn") as "btn" | "jwe";

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
      throw new Error("tn.admin.rotate: jwe cipher rotation not yet implemented in TS SDK.");
    }
    // Unreachable but keeps TS happy.
    throw new Error(`tn.admin.rotate: unknown cipher=${cipher}`);
  }

  async ensureGroup(
    group: string,
    opts?: { cipher?: "btn" | "jwe"; fields?: string[] },
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
        cipher: existing.cipher as "btn" | "jwe",
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
