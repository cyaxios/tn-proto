// tn.vault.* namespace — Phase 2 verb surface for vault link/unlink.
// Methods are populated in Task 2.8.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { EmitReceipt } from "../core/results.js";

export class VaultNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  async link(vaultDid: string, projectId: string): Promise<EmitReceipt> {
    return this._rt.vaultLink(vaultDid, projectId);
  }

  async unlink(vaultDid: string, projectId: string, reason?: string): Promise<EmitReceipt> {
    return this._rt.vaultUnlink(vaultDid, projectId, reason);
  }

  /**
   * Not ported. Python's `tn.admin.set_link_state` mutates the ceremony
   * yaml file (flipping ceremony.mode between "local" and "linked") — it is
   * a config-mutation operation, not a log-event verb. The TS SDK does not
   * yet expose yaml mutation; use `tn.vault.link(...)` or
   * `tn.vault.unlink(...)` to emit the corresponding log events instead.
   */
  async setLinkState(state: "linked" | "unlinked"): Promise<EmitReceipt> {
    throw new Error(
      `tn.vault.setLinkState: not yet ported from Python. ` +
        `Python's set_link_state mutates the ceremony yaml (ceremony.mode), ` +
        `not the event log. Use tn.vault.link(...) or tn.vault.unlink(...) ` +
        `to emit the corresponding log events instead (state=${state}).`,
    );
  }
}
