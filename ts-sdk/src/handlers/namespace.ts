// tn.handlers.* namespace — Phase 2 verb surface for handler add/list/flush.
// Methods are populated in Task 2.10.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { TNHandler } from "./index.js";

export class HandlersNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  add(_handler: TNHandler): void {
    throw new Error("tn.handlers.add: not implemented (Task 2.10)");
  }
  list(): TNHandler[] {
    throw new Error("tn.handlers.list: not implemented (Task 2.10)");
  }
  async flush(): Promise<void> {
    throw new Error("tn.handlers.flush: not implemented (Task 2.10)");
  }
}
