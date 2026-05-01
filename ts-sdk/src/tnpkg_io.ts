// Layer 2 `.tnpkg` file I/O — Node-only.
//
// Thin wrappers around the browser-safe Layer 1 functions in
// `./core/tnpkg_archive.js` and manifest helpers in `./core/tnpkg.js`.
// All filesystem access is isolated here so the core layer stays
// browser-safe.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import {
  type BodyContents,
  type Manifest,
  fromWireDict,
  toWireDict,
} from "./core/tnpkg.js";
import { packTnpkg, parseTnpkg, type ZipEntry } from "./core/tnpkg_archive.js";

export type { ZipEntry } from "./core/tnpkg_archive.js";
export type { ParsedZipEntry } from "./core/tnpkg_archive.js";
export { packTnpkg, parseTnpkg } from "./core/tnpkg_archive.js";

/** Sort-keys replacer for JSON.stringify so the manifest JSON in the
 * archive matches Python's `json.dumps(..., sort_keys=True, indent=2)`. */
function sortedReplacer(_root: unknown): (this: unknown, key: string, value: unknown) => unknown {
  return function replacer(_key, value) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  };
}

/** Write a `.tnpkg` zip to `outPath`. The manifest must already be
 * signed (see `signManifest`). `body` keys are logical paths inside the
 * zip — typically `body/...` per the format. */
export function writeTnpkg(outPath: string, manifest: Manifest, body: BodyContents): string {
  if (!manifest.manifestSignatureB64) {
    throw new Error(
      "writeTnpkg: manifest is unsigned. Call signManifest(...) before writing — " +
        "the wire format requires manifest_signature_b64 to be present.",
    );
  }
  const resolved = pathResolve(outPath);
  const dir = dirname(resolved);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const wireDoc = toWireDict(manifest, true);
  const manifestJson = JSON.stringify(wireDoc, sortedReplacer(wireDoc), 2) + "\n";
  const entries: ZipEntry[] = [
    { name: "manifest.json", data: new TextEncoder().encode(manifestJson) },
  ];
  // Stable order: keys sorted lexicographically. Matches Python's
  // `zf.writestr` ordering driven by dict insertion, which is
  // unspecified — the receiver doesn't care, but a stable order keeps
  // diffs / fixtures readable.
  for (const name of Object.keys(body).sort()) {
    entries.push({ name, data: body[name]! });
  }
  writeFileSync(resolved, packTnpkg(entries));
  return resolved;
}

/** Open a `.tnpkg` from a file path or in-memory bytes. Returns the
 * parsed manifest plus a body map (every non-manifest entry). Does NOT
 * verify the signature — call `verifyManifest` separately. */
export function readTnpkg(source: string | Uint8Array): {
  manifest: Manifest;
  body: Map<string, Uint8Array>;
} {
  let bytes: Uint8Array;
  if (typeof source === "string") {
    if (!existsSync(source)) {
      throw new Error(`readTnpkg: source path does not exist: ${source}`);
    }
    bytes = new Uint8Array(readFileSync(source));
  } else {
    bytes = source;
  }
  let entries: ReturnType<typeof parseTnpkg>;
  try {
    entries = parseTnpkg(bytes);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`readTnpkg: input is not a valid \`.tnpkg\` zip: ${msg}`, { cause: e });
  }
  const manifestEntry = entries.find((e) => e.name === "manifest.json");
  if (!manifestEntry) {
    throw new Error(
      "readTnpkg: zip is missing `manifest.json`. The `.tnpkg` format requires a " +
        "top-level signed manifest; this archive does not have one.",
    );
  }
  const manifestDoc = JSON.parse(new TextDecoder("utf-8").decode(manifestEntry.data));
  const manifest = fromWireDict(manifestDoc);
  const body = new Map<string, Uint8Array>();
  for (const e of entries) {
    if (e.name === "manifest.json") continue;
    body.set(e.name, e.data);
  }
  return { manifest, body };
}
