// Size-based rotating file handler. Mirrors Python FileRotatingHandler.
// Rotation renames tn.ndjson -> tn.ndjson.1 -> ... -> tn.ndjson.N (oldest dropped).

import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import { BaseTNHandler, type FilterSpec } from "./base.js";

export interface FileHandlerOptions {
  /** Rotate when file exceeds this many bytes. Default: 5 MB. */
  maxBytes?: number;
  /** Number of backup files to keep (oldest discarded). Default: 5. */
  backupCount?: number;
  filter?: FilterSpec;
}

export class FileHandler extends BaseTNHandler {
  private readonly _path: string;
  private readonly _maxBytes: number;
  private readonly _backupCount: number;

  constructor(name: string, path: string, options: FileHandlerOptions = {}) {
    super(name, options.filter);
    this._path = path;
    this._maxBytes = options.maxBytes ?? 5 * 1024 * 1024;
    this._backupCount = options.backupCount ?? 5;

    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  emit(_envelope: Record<string, unknown>, rawLine: string): void {
    this._maybeRotate();
    appendFileSync(this._path, rawLine, "utf8");
  }

  private _maybeRotate(): void {
    if (!existsSync(this._path)) return;
    if (statSync(this._path).size < this._maxBytes) return;
    this._rotate();
  }

  private _rotate(): void {
    const dir = dirname(this._path);
    const base = basename(this._path);
    // Shift existing backups: .N dropped, .N-1 -> .N, ..., .1 -> .2
    for (let i = this._backupCount - 1; i >= 1; i--) {
      const src = join(dir, `${base}.${i}`);
      const dst = join(dir, `${base}.${i + 1}`);
      if (existsSync(src)) renameSync(src, dst);
    }
    renameSync(this._path, join(dir, `${base}.1`));
  }
}
