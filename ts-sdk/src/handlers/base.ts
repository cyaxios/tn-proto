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
}

export interface TNHandler {
  readonly name: string;
  accepts(envelope: Record<string, unknown>): boolean;
  emit(envelope: Record<string, unknown>, rawLine: string): void;
  close(): void;
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
}
