import type { Entry } from "../Entry.js";
import { parseNdjson } from "./ndjson.js";
import { processEnvelope } from "./envelope.js";
import type { TnFileHandle } from "./file_handle.js";
import type { KeystoreHandle } from "./keystore.js";

export interface ReadOpts {
  keystore?: KeystoreHandle;
  where?: (e: Entry) => boolean;
}

export async function* localRead(
  handle: TnFileHandle,
  opts: ReadOpts = {},
): AsyncIterable<Entry> {
  for (const envelope of parseNdjson(await handle.text())) {
    const entry = processEnvelope(envelope, opts.keystore);
    if (opts.where && !opts.where(entry)) continue;
    yield entry;
  }
}
