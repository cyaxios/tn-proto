// tn.vault.* namespace — Phase 2 verb surface for vault link/unlink.
// Methods are populated in Task 2.8.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { EmitReceipt } from "../core/results.js";

export class VaultNamespace {
  private readonly _merge: (f: Record<string, unknown>) => Record<string, unknown>;

  constructor(
    private readonly _rt: NodeRuntime,
    merge?: (f: Record<string, unknown>) => Record<string, unknown>,
  ) {
    // Default identity merge so that VaultNamespace can be constructed
    // standalone (e.g. from NodeRuntime directly) without a Tn wrapper.
    this._merge = merge ?? ((f) => f);
  }

  async link(vaultDid: string, projectId: string): Promise<EmitReceipt> {
    return this._rt.emit("info", "tn.vault.linked", this._merge({
      vault_did: vaultDid,
      project_id: projectId,
      linked_at: new Date().toISOString(),
    }));
  }

  async unlink(vaultDid: string, projectId: string, reason?: string): Promise<EmitReceipt> {
    const fields: Record<string, unknown> = {
      vault_did: vaultDid,
      project_id: projectId,
      unlinked_at: new Date().toISOString(),
    };
    if (reason !== undefined) fields["reason"] = reason;
    return this._rt.emit("info", "tn.vault.unlinked", this._merge(fields));
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
