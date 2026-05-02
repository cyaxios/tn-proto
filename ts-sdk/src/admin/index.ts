// tn.admin.* namespace — Phase 2 verb surface for ceremony admin operations.
// Methods are populated in Task 2.6.

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

  async addRecipient(_group: string, _opts: AddRecipientOptions): Promise<AddRecipientResult> {
    throw new Error("tn.admin.addRecipient: not implemented (Task 2.6)");
  }
  async revokeRecipient(_group: string, _opts: RevokeRecipientOptions): Promise<RevokeRecipientResult> {
    throw new Error("tn.admin.revokeRecipient: not implemented (Task 2.6)");
  }
  async rotate(_group: string): Promise<RotateGroupResult> {
    throw new Error("tn.admin.rotate: not implemented (Task 2.6)");
  }
  async ensureGroup(_group: string, _opts?: { cipher?: "btn" | "jwe" }): Promise<EnsureGroupResult> {
    throw new Error("tn.admin.ensureGroup: not implemented (Task 2.6)");
  }
  recipients(_group: string, _opts?: { includeRevoked?: boolean }): RecipientEntry[] {
    throw new Error("tn.admin.recipients: not implemented (Task 2.6)");
  }
  state(_group?: string): AdminState {
    throw new Error("tn.admin.state: not implemented (Task 2.6)");
  }
  cache(): AdminStateCache {
    throw new Error("tn.admin.cache: not implemented (Task 2.6)");
  }
  revokedCount(_group: string): number {
    throw new Error("tn.admin.revokedCount: not implemented (Task 2.6)");
  }
}
