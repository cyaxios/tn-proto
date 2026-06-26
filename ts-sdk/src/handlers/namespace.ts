// tn.handlers.* namespace — verb surface for handler add/list/flush.

import type { NodeRuntime } from "../runtime/node_runtime.js";
import type { TNHandler } from "./index.js";

export class HandlersNamespace {
  constructor(private readonly _rt: NodeRuntime) {}

  add(handler: TNHandler): void {
    this._rt.addHandler(handler);
  }

  list(): TNHandler[] {
    return this._rt.listHandlers();
  }

  async flush(): Promise<void> {
    await this._rt.flushHandlers();
  }
}
