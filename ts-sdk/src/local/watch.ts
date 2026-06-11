import type { Entry } from "../Entry.js";
import { parseNdjson } from "./ndjson.js";
import { processEnvelope } from "./envelope.js";
import type { TnFileHandle } from "./file_handle.js";
import type { KeystoreHandle } from "./keystore.js";

export interface WatchOpts {
  keystore?: KeystoreHandle;
  since?: "now" | "start";
  pollMs?: number;
  where?: (e: Entry) => boolean;
  signal?: AbortSignal;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const id = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(id);
      reject(new DOMException("Aborted", "AbortError"));
    }, { once: true });
  });
}

export async function* localWatch(
  handle: TnFileHandle,
  opts: WatchOpts = {},
): AsyncIterable<Entry> {
  const pollMs = opts.pollMs ?? 1000;
  let offset: number;

  if (opts.since === "start") {
    for (const envelope of parseNdjson(await handle.text())) {
      const entry = processEnvelope(envelope, opts.keystore);
      if (!opts.where || opts.where(entry)) yield entry;
    }
    offset = await handle.size();
  } else {
    offset = await handle.size();
  }

  while (true) {
    if (opts.signal?.aborted) break;
    try { await sleep(pollMs, opts.signal); } catch { break; }
    if (opts.signal?.aborted) break;

    const newSize = await handle.size();
    if (newSize <= offset) continue;
    const chunk = await handle.slice(offset, newSize);
    offset = newSize;
    for (const envelope of parseNdjson(chunk)) {
      const entry = processEnvelope(envelope, opts.keystore);
      if (!opts.where || opts.where(entry)) yield entry;
    }
  }
}
