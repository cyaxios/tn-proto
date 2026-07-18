import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

const LOCK_RETRY_MS = 10;
const LOCK_TIMEOUT_MS = 20_000;
const LOCK_STALE_MS = 60_000;

function sleepSync(ms: number): void {
  const shared = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(shared), 0, 0, ms);
}

function fsyncDirectory(path: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
    fsyncSync(fd);
  } catch {
    // Directory fsync is not supported on every Windows filesystem. The file
    // itself is still fsynced before rename, and POSIX gets the full barrier.
  } finally {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // best effort
      }
    }
  }
}

/** Owner-only, same-directory, crash-durable atomic replacement. */
export function durableAtomicWrite(path: string, data: Uint8Array | string): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true });
  const token = randomBytes(8).toString("hex");
  const tmp = join(parent, `.${path.split(/[\\/]/).pop()}.tmp.${process.pid}.${token}`);
  let fd: number | null = null;
  let closed = false;
  try {
    fd = openSync(tmp, "wx", 0o600);
    const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    writeSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    closed = true;
    renameSync(tmp, path);
    fsyncDirectory(parent);
  } catch (err) {
    if (fd !== null && !closed) {
      try {
        closeSync(fd);
      } catch {
        // best effort
      }
    }
    try {
      if (existsSync(tmp)) unlinkSync(tmp);
    } catch {
      // best effort
    }
    throw err;
  }
}

/** Durable removal of a transaction marker after all promoted files exist. */
export function durableUnlink(path: string): void {
  if (!existsSync(path)) return;
  unlinkSync(path);
  fsyncDirectory(dirname(path));
}

function processIsAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function staleLockCanBeRemoved(path: string): boolean {
  let age: number;
  try {
    age = Date.now() - statSync(path).mtimeMs;
  } catch {
    return false;
  }
  if (age <= LOCK_STALE_MS) return false;
  try {
    const record = JSON.parse(readFileSync(path, "utf8")) as { pid?: unknown };
    if (typeof record.pid === "number" && processIsAlive(record.pid)) return false;
  } catch {
    // An old malformed lock has no live owner evidence.
  }
  return true;
}

/** Short cross-process critical section using an owner-aware lock file. */
export function withDurableFileLock<T>(lockPath: string, fn: () => T): T {
  mkdirSync(dirname(lockPath), { recursive: true });
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  let fd: number;
  for (;;) {
    try {
      fd = openSync(lockPath, "wx", 0o600);
      break;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw err;
      if (staleLockCanBeRemoved(lockPath)) {
        try {
          unlinkSync(lockPath);
          fsyncDirectory(dirname(lockPath));
          continue;
        } catch {
          // Another waiter or the owner raced us; retry normally.
        }
      }
      if (Date.now() >= deadline) {
        throw new Error(`state lock timeout: ${lockPath} is still held`);
      }
      sleepSync(LOCK_RETRY_MS);
    }
  }
  try {
    const record = Buffer.from(JSON.stringify({ pid: process.pid }) + "\n", "utf8");
    writeSync(fd, record);
    fsyncSync(fd);
    return fn();
  } finally {
    try {
      closeSync(fd);
    } finally {
      try {
        durableUnlink(lockPath);
      } catch {
        // The owner is done; a leftover lock will be reclaimed after staleness.
      }
    }
  }
}
