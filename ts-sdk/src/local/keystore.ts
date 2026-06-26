import { fromBase64, bytesToHex } from "./_utils.js";
import { btnKitPublisherId } from "../raw.js";

export interface KeystoreHandle {
  kitsForPublisher(publisherIdHex: string): Uint8Array[];
}

interface RawEntry {
  publisher_id: string;
  kits: string[];
}

export function parseKeystore(json: string): KeystoreHandle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("invalid keystore: not valid JSON");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    !("keystores" in (parsed as Record<string, unknown>))
  ) {
    throw new Error("invalid keystore: missing 'keystores' field");
  }
  const raw = parsed as { keystores: RawEntry[] };
  if (!Array.isArray(raw.keystores)) {
    throw new Error("invalid keystore: 'keystores' must be an array");
  }

  const byPublisher = new Map<string, Uint8Array[]>();
  for (const entry of raw.keystores) {
    if (!entry.publisher_id || !Array.isArray(entry.kits)) continue;
    const kits = entry.kits.map(fromBase64);
    const existing = byPublisher.get(entry.publisher_id);
    if (existing) existing.push(...kits);
    else byPublisher.set(entry.publisher_id, kits);
  }

  return {
    kitsForPublisher(id) { return byPublisher.get(id) ?? []; },
  };
}

/** Build a KeystoreHandle from a project body files Map as returned by
 * `loadProject()` in tn-proto-web. Scans for `*.btn.mykit` entries and
 * indexes them by publisher ID so they can decrypt incoming TN entries. */
export function keystoreFromBodyFiles(files: Map<string, Uint8Array>): KeystoreHandle {
  const byPublisher = new Map<string, Uint8Array[]>();
  for (const [path, bytes] of files) {
    if (!path.endsWith(".btn.mykit")) continue;
    try {
      const pubId = bytesToHex(btnKitPublisherId(bytes));
      const existing = byPublisher.get(pubId);
      if (existing) existing.push(bytes);
      else byPublisher.set(pubId, [bytes]);
    } catch {
      // skip corrupt kit
    }
  }
  return {
    kitsForPublisher(id) { return byPublisher.get(id) ?? []; },
  };
}
