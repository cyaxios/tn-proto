// tn.watch — tail-aware async-iterable over a TN ndjson log.
//
// Tracks byte offset so we never re-read prior bytes on append. Survives
// rotation (inode change) by reopening at offset 0 of the new file. On
// unexpected truncation (file shorter than tracked offset, no inode
// change), we resume from the new end and emit a tamper-class admin event.
//
// See docs/superpowers/specs/2026-05-01-ts-sdk-refresh-design.md §3.2 and
// the implementation plan §3.2 for the rotation / truncation / since
// semantics this verb supports.

import { open as fsOpen } from "node:fs/promises";
import { statSync } from "node:fs";
import { resolve as pathResolve } from "node:path";
import chokidar from "chokidar";

import type { NodeRuntime } from "./runtime/node_runtime.js";
import type { Entry } from "./core/types.js";
import { flattenRawEntry } from "./core/read_shape.js";

export type WatchSince = "start" | "now" | number | string;

export interface WatchOptions {
  /** Starting point: "start" replays from byte 0, "now" (default) yields
   * only new appends, a sequence number resumes at the first envelope
   * with sequence >= N, an ISO-8601 string resumes at the first envelope
   * with timestamp >= S. */
  since?: WatchSince;
  /** Pass entries through secureRead-style validation. Default: false. */
  verify?: boolean;
  /** Polling fallback interval for filesystems where native fs.watch
   * doesn't deliver events. Default: 300ms. */
  pollIntervalMs?: number;
  /** Override the log path (defaults to runtime.config.logPath). */
  logPath?: string;
}

interface WatchState {
  offset: number;
  inode: number | null;
}

const DECODER = new TextDecoder();

export async function* watch(
  rt: NodeRuntime,
  opts: WatchOptions = {},
): AsyncIterable<Entry> {
  const logPath = pathResolve(opts.logPath ?? rt.config.logPath);
  const verify = opts.verify ?? false;
  const pollMs = opts.pollIntervalMs ?? 300;
  const since = opts.since ?? "now";

  // 1. Establish initial offset.
  const state: WatchState = await initialState(logPath, since);

  // 2. Drain anything already past offset (initial replay or "now" no-op).
  // 3. Watch for changes, drain incremental bytes per change event.

  const queue: Entry[] = [];
  let resolveWaiter: (() => void) | null = null;
  const closed = false;
  // Serialize concurrent drain calls (e.g. chokidar "add" fires at the same
  // time as the explicit initial drain call below).
  let drainPromise: Promise<void> = Promise.resolve();

  const drainOnce = async (): Promise<void> => {
    let st;
    try {
      st = statSync(logPath);
    } catch {
      return;
    }
    if (state.inode !== null && st.ino !== state.inode) {
      // Rotation: file replaced. Reset to offset 0 of the new file.
      state.offset = 0;
      state.inode = st.ino;
    }
    if (st.size < state.offset) {
      // Unexpected truncation: file shorter than tracked offset, same inode.
      // Resume from new end; emit a tamper-class admin event so monitoring
      // catches the case. Best-effort — never let an emit failure break
      // the watcher.
      try {
        rt.emit("warning", "tn.watch.truncation_observed", {
          log_path: logPath,
          prior_offset: state.offset,
          new_size: st.size,
        });
      } catch {
        /* swallow — keep watching */
      }
      state.offset = st.size;
      return;
    }
    if (st.size === state.offset) return;

    // Read the new tail bytes and parse line-by-line.
    const fh = await fsOpen(logPath, "r");
    try {
      const buf = new Uint8Array(st.size - state.offset);
      await fh.read(buf, 0, buf.byteLength, state.offset);
      const text = DECODER.decode(buf);
      let lineStart = 0;
      let lastNewlineEnd = state.offset;
      for (let i = 0; i < text.length; i++) {
        if (text.charCodeAt(i) !== 0x0a) continue;
        const line = text.slice(lineStart, i);
        lineStart = i + 1;
        lastNewlineEnd = state.offset + i + 1;
        if (line.length === 0) continue;
        const raw = rt.parseEnvelopeLine(line, { verify });
        if (raw === null) continue;
        const entry = flattenRawEntry(raw, { includeValid: verify });
        queue.push(entry);
      }
      state.offset = lastNewlineEnd;
    } finally {
      await fh.close();
    }

    if (resolveWaiter) {
      resolveWaiter();
      resolveWaiter = null;
    }
  };

  // Serialize concurrent drain calls: each invocation chains onto the
  // previous promise so that concurrent "add"/"change" events from
  // chokidar and the explicit initial drain never race on state.offset.
  const drainSinceOffset = (): Promise<void> => {
    drainPromise = drainPromise.then(() => drainOnce());
    return drainPromise;
  };

  const watcher = chokidar.watch(logPath, {
    persistent: true,
    awaitWriteFinish: false,
    interval: pollMs,
  });
  watcher.on("add", drainSinceOffset);
  watcher.on("change", drainSinceOffset);

  // Initial drain — picks up whatever's already past the start offset.
  await drainSinceOffset();

  try {
    while (!closed) {
      while (queue.length > 0) {
        yield queue.shift()!;
      }
      await new Promise<void>((r) => {
        resolveWaiter = r;
        setTimeout(r, pollMs);
      });
    }
  } finally {
    await watcher.close();
  }
}

async function initialState(logPath: string, since: WatchSince): Promise<WatchState> {
  let st;
  try {
    st = statSync(logPath);
  } catch {
    return { offset: 0, inode: null };
  }

  if (since === "start") {
    return { offset: 0, inode: st.ino };
  }
  if (since === "now") {
    return { offset: st.size, inode: st.ino };
  }
  // Either a sequence number or an ISO timestamp — fast-forward by scanning
  // from byte 0 for the first envelope that meets the threshold.
  const offset = await findOffsetForSince(logPath, since);
  return { offset, inode: st.ino };
}

async function findOffsetForSince(logPath: string, since: number | string): Promise<number> {
  const fh = await fsOpen(logPath, "r");
  try {
    const st = await fh.stat();
    const buf = new Uint8Array(st.size);
    await fh.read(buf, 0, st.size, 0);
    const text = DECODER.decode(buf);
    let lineStart = 0;
    let off = 0;
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) !== 0x0a) continue;
      const line = text.slice(lineStart, i);
      const linePos = lineStart;
      lineStart = i + 1;
      off = lineStart;
      if (!line.trim()) continue;
      try {
        const env = JSON.parse(line);
        const matches =
          typeof since === "number"
            ? typeof env.sequence === "number" && env.sequence >= since
            : typeof env.timestamp === "string" && env.timestamp >= since;
        if (matches) return linePos;
      } catch {
        /* skip malformed line */
      }
    }
    return off;
  } finally {
    await fh.close();
  }
}
