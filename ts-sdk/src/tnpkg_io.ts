// Layer 2 `.tnpkg` file I/O — Node-only.
//
// Thin wrappers around the browser-safe Layer 1 functions in
// `./core/tnpkg_archive.js` and manifest helpers in `./core/tnpkg.js`.
// All filesystem access is isolated here so the core layer stays
// browser-safe.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import { tnpkgReadBytes, tnpkgWriteBytes } from "./raw.js";
import { type BodyContents, type Manifest, fromWireDict, toWireDict } from "./core/tnpkg.js";

export type { ZipEntry } from "./core/tnpkg_archive.js";
export type { ParsedZipEntry } from "./core/tnpkg_archive.js";
export { packTnpkg, parseTnpkg } from "./core/tnpkg_archive.js";

/** Serialize a signed `.tnpkg` to zip bytes in memory. The manifest must
 * already be signed (see `signManifest`). `body` keys are logical paths
 * inside the zip (typically `body/...` per the format). Shared by
 * `writeTnpkg` and in-memory callers such as `compileKitBundle`. The zip
 * layout itself is produced by the Rust core via `tnpkgWriteBytes`. */
export function packTnpkgBytes(manifest: Manifest, body: BodyContents): Uint8Array {
  if (!manifest.manifestSignatureB64) {
    throw new Error(
      "packTnpkgBytes: manifest is unsigned. Call signManifest(...) first; " +
        "the wire format requires manifest_signature_b64 to be present.",
    );
  }
  const wireDoc = toWireDict(manifest, true);
  const entries = Object.keys(body)
    .sort()
    .map((name) => ({ name, data: body[name]! }));
  return new Uint8Array(tnpkgWriteBytes(wireDoc, entries));
}

/** Write a `.tnpkg` zip to `outPath`. The manifest must already be
 * signed (see `signManifest`). `body` keys are logical paths inside the
 * zip (typically `body/...` per the format). */
export function writeTnpkg(outPath: string, manifest: Manifest, body: BodyContents): string {
  const bytes = packTnpkgBytes(manifest, body);
  const resolved = pathResolve(outPath);
  const dir = dirname(resolved);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(resolved, Buffer.from(bytes));
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
  let parsed: { manifest: unknown; body: Array<{ name: string; data: Uint8Array }> };
  try {
    parsed = tnpkgReadBytes(bytes) as {
      manifest: unknown;
      body: Array<{ name: string; data: Uint8Array }>;
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`readTnpkg: input is not a valid \`.tnpkg\` zip: ${msg}`, { cause: e });
  }
  const manifest = fromWireDict(parsed.manifest);
  const body = new Map<string, Uint8Array>();
  for (const e of parsed.body) {
    body.set(e.name, e.data);
  }
  return { manifest, body };
}
