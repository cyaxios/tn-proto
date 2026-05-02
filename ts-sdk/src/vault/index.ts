// tn.vault.* namespace — Phase 2 verb surface for vault link/unlink.
// Methods are populated in Task 2.8.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { EmitReceipt } from "../core/results.js";

export class VaultNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  async link(_vaultDid: string, _projectId: string): Promise<EmitReceipt> {
    throw new Error("tn.vault.link: not implemented (Task 2.8)");
  }
  async unlink(_vaultDid: string, _projectId: string, _reason?: string): Promise<EmitReceipt> {
    throw new Error("tn.vault.unlink: not implemented (Task 2.8)");
  }
  async setLinkState(_state: "linked" | "unlinked"): Promise<EmitReceipt> {
    throw new Error("tn.vault.setLinkState: not implemented (Task 2.8)");
  }
}
