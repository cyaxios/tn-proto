// tn.agents.* namespace — Phase 2 verb surface for agent runtimes + policy.
// Methods are populated in Task 2.9.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { PolicyDocument } from "../core/agents_policy.js";

export interface AddRuntimeOptions {
  runtimeDid: string;
  groups: string[];
  outPath: string;
}

export class AgentsNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  async addRuntime(_opts: AddRuntimeOptions): Promise<string> {
    throw new Error("tn.agents.addRuntime: not implemented (Task 2.9)");
  }
  policy(): PolicyDocument | null {
    throw new Error("tn.agents.policy: not implemented (Task 2.9)");
  }
  async reloadPolicy(): Promise<PolicyDocument | null> {
    throw new Error("tn.agents.reloadPolicy: not implemented (Task 2.9)");
  }
}
