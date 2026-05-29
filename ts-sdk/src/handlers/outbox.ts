// Durable outbox + background worker for async (network) handlers.
// Port of python/tn/handlers/outbox.py.
//
// Python uses persist-queue's SQLiteAckQueue. To keep the TS SDK
// dependency-light (no native sqlite binding), this uses an equivalent
// FILE-DIRECTORY queue with the same guarantees:
//
//   * Crash-safe: each item is its own file; `put` writes a temp file then
//     atomically renames it in. An item is `ack`ed only AFTER a successful
//     publish (by deleting its file). A crash mid-publish leaves the file on
//     disk so it's reprocessed on next start.
//   * FIFO: items are claimed oldest-first by filename (monotonic prefix).
//   * Single-process: one worker drains one item at a time on the event
//     loop; claims use an atomic rename so a half-processed item is
//     recoverable. (Multi-process draining of one dir is not a goal —
//     matches the Python single-worker model.)

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

/** One queued item: the envelope + its raw ndjson line, as enqueued by emit. */
export interface OutboxItem {
  envelope: Record<string, unknown>;
  raw: string;
}

interface ClaimedItem {
  /** The `.processing` filename (the claim handle). */
  claim: string;
  item: OutboxItem;
}

const ITEM_SUFFIX = ".item.json";
const PROC_SUFFIX = ".processing.json";

/**
 * File-directory durable queue. Mirrors python DurableOutbox's contract:
 * `put` / `claimNext` / `ack` / `nack` / `size`, ack-after-publish, and
 * crash recovery of in-flight (`.processing`) items on construction.
 */
export class DurableOutbox {
  private readonly _dir: string;
  private _seq = 0;

  constructor(dir: string) {
    this._dir = dir;
    mkdirSync(dir, { recursive: true });
    // Crash recovery: any item left `.processing` from a previous run (the
    // process died mid-publish) is reset to pending so it's retried.
    for (const name of readdirSync(dir)) {
      if (name.endsWith(PROC_SUFFIX)) {
        const pending = name.slice(0, -PROC_SUFFIX.length) + ITEM_SUFFIX;
        try {
          renameSync(join(dir, name), join(dir, pending));
        } catch {
          /* best-effort recovery */
        }
      }
    }
  }

  /** Enqueue an item. Atomic: write temp, rename into place. */
  put(item: OutboxItem): void {
    // Monotonic-ish, sortable prefix: time + per-instance counter + random.
    const seq = (this._seq++).toString().padStart(9, "0");
    const stamp = `${Date.now().toString().padStart(15, "0")}_${seq}_${randomBytes(4).toString("hex")}`;
    const finalPath = join(this._dir, stamp + ITEM_SUFFIX);
    const tmpPath = finalPath + ".tmp";
    writeFileSync(tmpPath, JSON.stringify(item), "utf8");
    renameSync(tmpPath, finalPath);
  }

  /** Claim the oldest pending item (atomic rename to `.processing`), or
   *  null if the queue is empty. */
  claimNext(): ClaimedItem | null {
    const pending = readdirSync(this._dir)
      .filter((n) => n.endsWith(ITEM_SUFFIX))
      .sort();
    for (const name of pending) {
      const claim = name.slice(0, -ITEM_SUFFIX.length) + PROC_SUFFIX;
      try {
        renameSync(join(this._dir, name), join(this._dir, claim));
      } catch {
        // Lost the race / file vanished — try the next one.
        continue;
      }
      try {
        const item = JSON.parse(readFileSync(join(this._dir, claim), "utf8")) as OutboxItem;
        return { claim, item };
      } catch {
        // Corrupt item — drop it so it doesn't wedge the queue.
        try {
          rmSync(join(this._dir, claim));
        } catch {
          /* best-effort */
        }
        continue;
      }
    }
    return null;
  }

  /** Acknowledge (delete) a claimed item after a successful publish. */
  ack(claim: string): void {
    try {
      rmSync(join(this._dir, claim));
    } catch {
      /* already gone */
    }
  }

  /** Return a claimed item to the pending pool for retry. */
  nack(claim: string): void {
    const pending = claim.slice(0, -PROC_SUFFIX.length) + ITEM_SUFFIX;
    try {
      renameSync(join(this._dir, claim), join(this._dir, pending));
    } catch {
      /* best-effort */
    }
  }

  /** Count of pending + in-flight items. */
  size(): number {
    if (!existsSync(this._dir)) return 0;
    return readdirSync(this._dir).filter(
      (n) => n.endsWith(ITEM_SUFFIX) || n.endsWith(PROC_SUFFIX),
    ).length;
  }
}

export type PublishFn = (envelope: Record<string, unknown>, raw: string) => Promise<void> | void;

export interface OutboxWorkerOptions {
  name: string;
  maxRetries?: number;
  backoffInitialMs?: number;
  backoffMaxMs?: number;
  /** Idle poll interval when the queue is empty. */
  pollMs?: number;
  /** Deterministic jitter for tests (default: crypto-random in ±20%). */
  jitter?: () => number;
}

/**
 * Background drainer. Mirrors python OutboxWorker: claims items oldest-first,
 * retries `publish` with exponential backoff + jitter, acks on success and
 * nacks (gives up, leaving the item to retry next iteration) after
 * `maxRetries`. Runs on the event loop (no threads).
 */
export class OutboxWorker {
  private readonly _outbox: DurableOutbox;
  private readonly _publish: PublishFn;
  private readonly _name: string;
  private readonly _maxRetries: number;
  private readonly _backoffInit: number;
  private readonly _backoffMax: number;
  private readonly _pollMs: number;
  private readonly _jitter: () => number;
  private _stopped = false;
  private _runPromise: Promise<void> | null = null;

  constructor(outbox: DurableOutbox, publish: PublishFn, opts: OutboxWorkerOptions) {
    this._outbox = outbox;
    this._publish = publish;
    this._name = opts.name;
    this._maxRetries = opts.maxRetries ?? 10;
    this._backoffInit = opts.backoffInitialMs ?? 1000;
    this._backoffMax = opts.backoffMaxMs ?? 60_000;
    this._pollMs = opts.pollMs ?? 250;
    // ±20% jitter to avoid thundering-herd on a shared-broker hiccup.
    this._jitter = opts.jitter ?? (() => 1.0 + ((randomBytes(2).readUInt16BE(0) / 65535) * 0.4 - 0.2));
  }

  start(): void {
    if (this._runPromise) return;
    this._runPromise = this._run();
  }

  private async _run(): Promise<void> {
    while (!this._stopped) {
      const claimed = this._outbox.claimNext();
      if (!claimed) {
        await _sleep(this._pollMs);
        continue;
      }
      await this._deliver(claimed);
    }
  }

  private async _deliver(claimed: ClaimedItem): Promise<void> {
    let attempt = 0;
    while (!this._stopped) {
      try {
        await this._publish(claimed.item.envelope, claimed.item.raw);
        this._outbox.ack(claimed.claim);
        return;
      } catch {
        attempt += 1;
        if (attempt >= this._maxRetries) {
          // Give up on this pass; nack so it returns to pending (a future
          // dead-letter queue is a tracked improvement, matching Python).
          this._outbox.nack(claimed.claim);
          return;
        }
        let delay = Math.min(this._backoffMax, this._backoffInit * 2 ** (attempt - 1));
        delay *= this._jitter();
        const interrupted = await _sleepUntilStop(delay, () => this._stopped);
        if (interrupted) {
          this._outbox.nack(claimed.claim);
          return;
        }
      }
    }
    // Stopped mid-retry: return the item to pending.
    this._outbox.nack(claimed.claim);
  }

  /** Drain (best-effort, up to timeoutMs), then stop the run loop. */
  async stop(opts: { timeoutMs?: number } = {}): Promise<void> {
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline && this._outbox.size() > 0) {
      await _sleep(100);
    }
    this._stopped = true;
    if (this._runPromise) {
      await Promise.race([this._runPromise, _sleep(Math.max(500, deadline - Date.now()))]);
    }
  }
}

function _sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Sleep that resolves early (returns true) if stop is requested. */
async function _sleepUntilStop(ms: number, stopped: () => boolean): Promise<boolean> {
  const step = 100;
  let waited = 0;
  while (waited < ms) {
    if (stopped()) return true;
    await _sleep(Math.min(step, ms - waited));
    waited += step;
  }
  return stopped();
}
