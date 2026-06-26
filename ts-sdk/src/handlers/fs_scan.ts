// `fs.scan` handler — pick up `.tnpkg` files from a watched directory.
//
// Mirrors `python/tn/handlers/fs_scan.py`. Polls a directory for `.tnpkg`
// files, calls a host-supplied `absorb` adapter for each, then archives
// or deletes. Bad-signature / rejected files always go to `.rejected/`.
//
// The host wires `absorb` via [`makePackageAbsorber`] (or a mock in tests).

import {
  existsSync,
  mkdirSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { extname, join } from "node:path";

import { BaseTNHandler, type FilterSpec } from "./base.js";

/** What to do with a successfully absorbed file. */
export type FsScanOnProcessed = "archive" | "delete";

/** Minimal receipt shape — mirrors the fields fs.scan inspects. */
export interface FsScanAbsorbReceipt {
  /** Empty / null when accepted; non-empty when the absorber rejected the package. */
  rejectedReason?: string | null;
}

/** Adapter the host plugs in (typically `client.absorb`). */
export interface FsScanAbsorber {
  absorb(path: string): FsScanAbsorbReceipt;
}

export interface FsScanHandlerOptions {
  inDir: string;
  absorber: FsScanAbsorber;
  pollIntervalMs?: number;
  onProcessed?: FsScanOnProcessed;
  archiveDir?: string;
  rejectedDir?: string;
  filter?: FilterSpec;
  /** Start the scheduler immediately. Tests pass false. */
  autostart?: boolean;
}

/** Poll a directory for `.tnpkg` files and absorb them. */
export class FsScanHandler extends BaseTNHandler {
  private readonly inDir: string;
  private readonly absorber: FsScanAbsorber;
  private readonly pollIntervalMs: number;
  private readonly onProcessed: FsScanOnProcessed;
  private readonly archiveDir: string;
  private readonly rejectedDir: string;
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private closed = false;

  constructor(name: string, opts: FsScanHandlerOptions) {
    super(name, opts.filter);
    this.inDir = opts.inDir;
    this.absorber = opts.absorber;
    this.pollIntervalMs = opts.pollIntervalMs ?? 30_000;
    this.onProcessed = opts.onProcessed ?? "archive";
    this.archiveDir = opts.archiveDir ?? join(opts.inDir, ".processed");
    this.rejectedDir = opts.rejectedDir ?? join(opts.inDir, ".rejected");
    if (opts.autostart !== false) this.start();
  }

  override accepts(_envelope: Record<string, unknown>): boolean {
    // Scan handlers don't react to local emits.
    return false;
  }

  emit(_envelope: Record<string, unknown>, _rawLine: string): void {
    // No-op: all work happens on the scheduler tick.
  }

  override close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Start the scheduler if not running. Idempotent. */
  start(): void {
    if (this.timer !== null || this.closed) return;
    // Initial tick.
    void this.maybeTick();
    this.timer = setInterval(() => void this.maybeTick(), this.pollIntervalMs);
    // Don't keep the event loop alive solely for this poll.
    if (typeof this.timer.unref === "function") this.timer.unref();
  }

  private async maybeTick(): Promise<void> {
    if (this.inFlight || this.closed) return;
    this.inFlight = true;
    try {
      this.tickOnce();
    } catch (e) {
      console.warn(`[${this.name}] fs.scan tick failed:`, e);
    } finally {
      this.inFlight = false;
    }
  }

  /** One scan cycle. Returns the count of newly absorbed files. */
  tickOnce(): number {
    if (!existsSync(this.inDir)) return 0;
    const entries = readdirSync(this.inDir)
      .map((n) => join(this.inDir, n))
      .filter((p) => {
        try {
          return statSync(p).isFile() && extname(p) === ".tnpkg";
        } catch {
          return false;
        }
      })
      .sort();
    let absorbed = 0;
    for (const path of entries) {
      let receipt: FsScanAbsorbReceipt;
      try {
        receipt = this.absorber.absorb(path);
      } catch (e) {
        console.warn(`[${this.name}] fs.scan: absorb crashed for ${path}:`, e);
        this.moveTo(path, this.rejectedDir);
        continue;
      }
      if (receipt.rejectedReason && receipt.rejectedReason.length > 0) {
        console.warn(`[${this.name}] fs.scan: rejecting ${path}: ${receipt.rejectedReason}`);
        this.moveTo(path, this.rejectedDir);
        continue;
      }
      absorbed += 1;
      this.dispose(path);
    }
    return absorbed;
  }

  private dispose(path: string): void {
    if (this.onProcessed === "delete") {
      try {
        unlinkSync(path);
      } catch (e) {
        console.warn(`[${this.name}] fs.scan: failed to delete ${path}:`, e);
      }
      return;
    }
    this.moveTo(path, this.archiveDir);
  }

  private moveTo(path: string, destDir: string): void {
    if (!existsSync(destDir)) mkdirSync(destDir, { recursive: true });
    const base = path.split(/[\\/]/).pop() ?? "file.tnpkg";
    let target = join(destDir, base);
    if (existsSync(target)) {
      const suffix = nowStampSeconds();
      const dot = base.lastIndexOf(".");
      const stem = dot >= 0 ? base.slice(0, dot) : base;
      const ext = dot >= 0 ? base.slice(dot) : "";
      target = join(destDir, `${stem}__${suffix}${ext}`);
    }
    try {
      renameSync(path, target);
    } catch (e) {
      console.warn(`[${this.name}] fs.scan: failed to move ${path} -> ${target}:`, e);
    }
  }
}

/** Adapter that maps a TNClient-shaped absorb to the receipt this handler reads. */
export function makePackageAbsorber(client: {
  absorb: (source: string) => { rejectedReason?: string | null };
}): FsScanAbsorber {
  return {
    absorb(path: string): FsScanAbsorbReceipt {
      const r = client.absorb(path);
      return { rejectedReason: r.rejectedReason ?? null };
    },
  };
}

function nowStampSeconds(): string {
  const d = new Date();
  const pad = (n: number, w: number) => String(n).padStart(w, "0");
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1, 2)}${pad(d.getUTCDate(), 2)}` +
    `T${pad(d.getUTCHours(), 2)}${pad(d.getUTCMinutes(), 2)}${pad(d.getUTCSeconds(), 2)}Z`
  );
}

/** Yaml spec shape. */
export interface FsScanSpec {
  kind: "fs.scan";
  name?: string;
  in_dir: string;
  poll_interval?: string | number;
  on_processed?: FsScanOnProcessed;
  archive_dir?: string;
  rejected_dir?: string;
  filter?: FilterSpec;
}
