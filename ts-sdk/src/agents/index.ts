// tn.agents.* namespace — verb surface for agent runtimes + policy.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { PolicyDocument } from "../core/agents_policy.js";

export interface AddRuntimeOptions {
  runtimeDid: string;
  groups: string[];
  outPath: string;
  label?: string;
}

export class AgentsNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  async addRuntime(opts: AddRuntimeOptions): Promise<string> {
    return this._rt.adminAddAgentRuntime(opts);
  }

  policy(): PolicyDocument | null {
    return this._rt.getAgentPolicy();
  }

  async reloadPolicy(): Promise<PolicyDocument | null> {
    return this._rt.reloadAgentPolicy();
  }
}
