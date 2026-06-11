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
    if (typeof this._rt.vaultLink === "function") {
      return this._rt.vaultLink(vaultDid, projectId);
    }
    return this._rt.emit("info", "tn.vault.linked", this._merge({
      vault_identity: vaultDid,
      project_id: projectId,
      linked_at: new Date().toISOString(),
    }));
  }

  async unlink(vaultDid: string, projectId: string, reason?: string): Promise<EmitReceipt> {
    if (typeof this._rt.vaultUnlink === "function") {
      return this._rt.vaultUnlink(vaultDid, projectId, reason);
    }
    const fields: Record<string, unknown> = {
      vault_identity: vaultDid,
      project_id: projectId,
      // Match Python's _vault_unlink_impl: `reason` is always written,
      // null when the caller omits it (not absent). Keeps the on-log
      // event byte-equivalent across the two SDKs.
      reason: reason ?? null,
      unlinked_at: new Date().toISOString(),
    };
    return this._rt.emit("info", "tn.vault.unlinked", this._merge(fields));
  }

  /**
   * Flip the ceremony's link state by writing `ceremony.mode` into the
   * AUTHORITATIVE yaml. Port of the persistent half of Python's
   * `tn.admin.set_link_state` (`python/tn/admin/__init__.py::set_link_state`)
   * — a config-mutation operation, NOT a log-event verb (hence it does
   * not return an `EmitReceipt`).
   *
   * The verb's `"linked" | "unlinked"` maps onto the yaml's
   * `ceremony.mode` of `"linked" | "local"` (Python uses `"local"` for
   * the unlinked state). The write lands at the head of the `extends:`
   * chain (Python resolves the authoritative yaml with key="vault"), so
   * unlinking a named stream flips the project, not a discarded
   * stream-local override.
   *
   * To emit the corresponding `tn.vault.linked` / `tn.vault.unlinked`
   * audit events, call `tn.vault.link(...)` / `tn.vault.unlink(...)`
   * separately — those are the log-event verbs; this is the on-disk
   * mode flip.
   *
   * `opts.linkedVault` is REQUIRED when `state === "linked"`: Python's
   * config loader rejects a `mode: linked` yaml with no `linked_vault`,
   * and Python's `set_link_state(mode="linked")` itself raises without
   * one. The `unlinked` direction needs no vault argument.
   */
  async setLinkState(
    state: "linked" | "unlinked",
    opts: { linkedVault?: string; linkedProjectId?: string } = {},
  ): Promise<void> {
    const mode = state === "linked" ? "linked" : "local";
    const mutateOpts: { linkedVault?: string; linkedProjectId?: string } = {};
    if (opts.linkedVault !== undefined) mutateOpts.linkedVault = opts.linkedVault;
    if (opts.linkedProjectId !== undefined) mutateOpts.linkedProjectId = opts.linkedProjectId;
    this._rt.setCeremonyMode(mode, mutateOpts);
  }
}
