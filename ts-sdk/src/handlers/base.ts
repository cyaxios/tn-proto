// Handler fan-out interface for TN log output.
// Mirrors the Python tn.handlers.base design: sync on the caller thread.
// Async/network handlers can wrap this and manage their own queue.

export interface FilterSpec {
  eventType?: string;
  eventTypePrefix?: string;
  notEventTypePrefix?: string;
  eventTypeIn?: readonly string[];
  level?: string;
  levelIn?: readonly string[];
  /**
   * Bool match on the envelope's `sync` field. `undefined` means "do not
   * filter on sync". When the envelope has no `sync` field the runtime
   * treats it as `true` (mirrors python/tn/handlers/filter.py).
   */
  sync?: boolean;
}

export interface TNHandler {
  readonly name: string;
  accepts(envelope: Record<string, unknown>): boolean;
  emit(envelope: Record<string, unknown>, rawLine: string): void;
  close(): void;
  /**
   * Return a string identifying this handler's sink — file path,
   * stdout sentinel, network endpoint URL, etc. Used for runtime
   * de-duplication: when two handlers in a single emit's effective
   * fan-out resolve to the same address, the second write is
   * suppressed (per the no-side-effect-dupes rule).
   *
   * Returning ``null`` opts the handler out of dedup — the runtime
   * treats it as having a unique address every time. Subclasses with
   * a meaningful sink (file, stdout, etc.) should override.
   *
   * Mirrors python/tn/handlers/base.py:resolved_address.
   */
  resolved_address?(): string | null;
}

export function compileFilter(
  spec: FilterSpec | undefined,
): (env: Record<string, unknown>) => boolean {
  if (!spec) return () => true;

  const {
    eventType,
    eventTypePrefix,
    notEventTypePrefix,
    eventTypeIn,
    level: levelExact,
    levelIn,
    sync: syncWant,
  } = spec;

  const etSet = eventTypeIn ? new Set(eventTypeIn) : undefined;
  const lvSet = levelIn ? new Set(levelIn) : undefined;

  return (env) => {
    const et = String(env["event_type"] ?? "");
    const lv = String(env["level"] ?? "");
    if (eventType !== undefined && et !== eventType) return false;
    if (eventTypePrefix !== undefined && !et.startsWith(eventTypePrefix)) return false;
    if (notEventTypePrefix !== undefined && et.startsWith(notEventTypePrefix)) return false;
    if (etSet !== undefined && !etSet.has(et)) return false;
    if (levelExact !== undefined && lv !== levelExact) return false;
    if (lvSet !== undefined && !lvSet.has(lv)) return false;
    if (syncWant !== undefined) {
      // Missing `sync` field is treated as true (matches Python).
      const envSync = env["sync"];
      const effective = envSync === undefined ? true : Boolean(envSync);
      if (effective !== syncWant) return false;
    }
    return true;
  };
}

export abstract class BaseTNHandler implements TNHandler {
  readonly name: string;
  private readonly _filter: (env: Record<string, unknown>) => boolean;

  constructor(name: string, filter?: FilterSpec) {
    this.name = name;
    this._filter = compileFilter(filter);
  }

  accepts(envelope: Record<string, unknown>): boolean {
    return this._filter(envelope);
  }

  abstract emit(envelope: Record<string, unknown>, rawLine: string): void;

  close(): void {
    // no-op by default; stateful handlers override
  }

  /** Default opt-out: subclasses with a meaningful sink override. */
  resolved_address(): string | null {
    return null;
  }
}

/**
 * Base for network handlers that need at-least-once delivery. Mirrors
 * python/tn/handlers/base.py:AsyncHandler — `emit` enqueues to a durable
 * outbox; a background worker drains it, calling the subclass's `publish`
 * with exponential-backoff retries. A crash mid-send leaves the item on
 * disk so it's redelivered on next start.
 *
 * Subclasses implement `publish(envelope, raw)` (throw/reject on failure ->
 * retry) and may override `finalFlush()` (emit a last partial batch on
 * close).
 */
export abstract class AsyncTNHandler extends BaseTNHandler {
  private _outbox: import("./outbox.js").DurableOutbox | null = null;
  private _worker: import("./outbox.js").OutboxWorker | null = null;
  private readonly _ready: Promise<void>;

  constructor(
    name: string,
    opts: {
      outboxDir: string;
      filter?: FilterSpec;
      maxRetries?: number;
      backoffInitialMs?: number;
      backoffMaxMs?: number;
    },
  ) {
    super(name, opts.filter);
    // Lazy-load the outbox module so base.ts stays free of fs/queue deps
    // until an async handler is actually constructed.
    this._ready = (async () => {
      const { DurableOutbox, OutboxWorker } = await import("./outbox.js");
      this._outbox = new DurableOutbox(opts.outboxDir);
      const workerOpts: import("./outbox.js").OutboxWorkerOptions = { name };
      if (opts.maxRetries !== undefined) workerOpts.maxRetries = opts.maxRetries;
      if (opts.backoffInitialMs !== undefined) workerOpts.backoffInitialMs = opts.backoffInitialMs;
      if (opts.backoffMaxMs !== undefined) workerOpts.backoffMaxMs = opts.backoffMaxMs;
      this._worker = new OutboxWorker(this._outbox, (e, r) => this.publish(e, r), workerOpts);
      this._worker.start();
    })();
  }

  /** Resolves once the outbox + worker are initialized. */
  whenReady(): Promise<void> {
    return this._ready;
  }

  override emit(envelope: Record<string, unknown>, rawLine: string): void {
    // Enqueue durably; the worker delivers with retry. If the async init is
    // still pending, buffer the put behind the ready promise so nothing is
    // dropped.
    if (this._outbox) {
      this._outbox.put({ envelope, raw: rawLine });
    } else {
      void this._ready.then(() => this._outbox?.put({ envelope, raw: rawLine }));
    }
  }

  /** Actually send to the network. Throw/reject on failure -> retry. */
  protected abstract publish(envelope: Record<string, unknown>, raw: string): Promise<void> | void;

  /** Hook after the worker drains, before close. Buffering subclasses override. */
  protected finalFlush(): void {
    /* no-op */
  }

  override close(): void {
    // Best-effort synchronous close; for a clean drain await closeAsync().
    void this.closeAsync();
  }

  /** Drain the outbox (up to timeoutMs), then stop the worker + flush. */
  async closeAsync(opts: { timeoutMs?: number } = {}): Promise<void> {
    await this._ready;
    if (this._worker) await this._worker.stop(opts);
    try {
      this.finalFlush();
    } catch {
      /* best-effort */
    }
  }
}
