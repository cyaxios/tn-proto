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
