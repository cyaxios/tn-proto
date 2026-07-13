// Layer 2 `.tnpkg` file I/O — Node-only.
//
// `readTnpkg` is the explicitly unverified legacy inspection boundary.
// Security-sensitive consumers use `readTnpkgVerified`, which performs a
// metadata-only resource preflight, reads and verifies only the bounded
// manifest, and loads body members only after that signature succeeds.

import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve as pathResolve } from "node:path";

import { type UnzipFileInfo, unzipSync } from "fflate";

import { canonicalize } from "./core/canonical.js";
import {
  type BodyContents,
  type Manifest,
  fromWireDict,
  toWireDict,
  validateTnpkgBodyName,
  verifyManifest,
  verifyManifestBodyIndex,
} from "./core/tnpkg.js";
import { packTnpkg, parseTnpkg } from "./core/tnpkg_archive.js";

export type { ZipEntry, ParsedZipEntry } from "./core/tnpkg_archive.js";
export { packTnpkg, parseTnpkg };

export const MAX_PKG_ENTRY_COUNT = 2_000;
export const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
export const MAX_PKG_ENTRY_BYTES = 128 * 1024 * 1024;
export const MAX_PKG_TOTAL_BYTES = 512 * 1024 * 1024;
export const MAX_PKG_COMPRESSION_RATIO = 200;
// Bounds `readFileSync` itself. The allowance above the uncompressed cap
// covers ZIP headers, central-directory records, and the archive comment.
export const MAX_PKG_INPUT_BYTES = MAX_PKG_TOTAL_BYTES + 64 * 1024 * 1024;

interface ZipMetadata {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  compression: number;
}

function packageError(operation: string, detail: string, cause?: unknown): Error {
  return cause === undefined
    ? new Error(`${operation}: ${detail}`)
    : new Error(`${operation}: ${detail}`, { cause });
}

function readBoundedSource(source: string | Uint8Array, operation: string): Uint8Array {
  if (typeof source !== "string") {
    if (source.byteLength > MAX_PKG_INPUT_BYTES) {
      throw packageError(
        operation,
        `input is ${source.byteLength} bytes, exceeding the archive input limit of ${MAX_PKG_INPUT_BYTES} bytes`,
      );
    }
    return source;
  }
  if (!existsSync(source)) {
    throw packageError(operation, `source path does not exist: ${source}`);
  }
  const stat = statSync(source);
  if (!stat.isFile()) {
    throw packageError(operation, `source path is not a regular file: ${source}`);
  }
  if (stat.size > MAX_PKG_INPUT_BYTES) {
    throw packageError(
      operation,
      `input file is ${stat.size} bytes, exceeding the archive input limit of ${MAX_PKG_INPUT_BYTES} bytes`,
    );
  }
  const bytes = new Uint8Array(readFileSync(source));
  // Defend against a file growing between stat and read.
  if (bytes.byteLength > MAX_PKG_INPUT_BYTES) {
    throw packageError(
      operation,
      `input file grew beyond the archive input limit of ${MAX_PKG_INPUT_BYTES} bytes`,
    );
  }
  return bytes;
}

function inspectZip(bytes: Uint8Array, operation: string): ZipMetadata[] {
  const metadata: ZipMetadata[] = [];
  const names = new Set<string>();
  let manifestCount = 0;
  let total = 0;
  try {
    // A false filter makes fflate traverse central-directory metadata without
    // inflating or copying any archive member.
    unzipSync(bytes, {
      filter(info: UnzipFileInfo): boolean {
        if (metadata.length >= MAX_PKG_ENTRY_COUNT) {
          throw packageError(operation, `package has more than ${MAX_PKG_ENTRY_COUNT} entries`);
        }
        const entry: ZipMetadata = {
          name: info.name,
          compressedSize: info.size,
          uncompressedSize: info.originalSize,
          compression: info.compression,
        };
        if (entry.name === "manifest.json") {
          manifestCount += 1;
          if (manifestCount > 1) {
            throw packageError(
              operation,
              `a package must carry exactly one manifest.json (found at least ${manifestCount})`,
            );
          }
        } else {
          validateTnpkgBodyName(entry.name);
        }
        if (names.has(entry.name)) {
          throw packageError(operation, `duplicate package member ${JSON.stringify(entry.name)}`);
        }
        names.add(entry.name);
        if (
          !Number.isSafeInteger(entry.compressedSize) ||
          !Number.isSafeInteger(entry.uncompressedSize) ||
          entry.compressedSize < 0 ||
          entry.uncompressedSize < 0
        ) {
          throw packageError(
            operation,
            `package member ${JSON.stringify(entry.name)} has invalid sizes`,
          );
        }
        if (entry.compression !== 0 && entry.compression !== 8) {
          throw packageError(
            operation,
            `package member ${JSON.stringify(entry.name)} uses unsupported compression method ${entry.compression}`,
          );
        }
        if (entry.uncompressedSize > MAX_PKG_ENTRY_BYTES) {
          throw packageError(
            operation,
            `package member ${JSON.stringify(entry.name)} declares ${entry.uncompressedSize} uncompressed bytes, exceeding the per-entry limit of ${MAX_PKG_ENTRY_BYTES}`,
          );
        }
        if (entry.name === "manifest.json" && entry.uncompressedSize > MAX_MANIFEST_BYTES) {
          throw packageError(
            operation,
            `manifest.json declares ${entry.uncompressedSize} uncompressed bytes, exceeding the manifest limit of ${MAX_MANIFEST_BYTES}`,
          );
        }
        const ratio = entry.uncompressedSize / Math.max(entry.compressedSize, 1);
        if (ratio > MAX_PKG_COMPRESSION_RATIO) {
          throw packageError(
            operation,
            `package member ${JSON.stringify(entry.name)} has compression ratio ${ratio.toFixed(1)}x, exceeding the limit of ${MAX_PKG_COMPRESSION_RATIO}x`,
          );
        }
        total += entry.uncompressedSize;
        if (total > MAX_PKG_TOTAL_BYTES) {
          throw packageError(
            operation,
            `total uncompressed size exceeds the limit of ${MAX_PKG_TOTAL_BYTES} bytes`,
          );
        }
        metadata.push(entry);
        return false;
      },
    });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(`${operation}:`)) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw packageError(operation, `input is not a valid \`.tnpkg\` zip: ${message}`, error);
  }

  if (manifestCount !== 1) {
    throw packageError(
      operation,
      `a package must carry exactly one manifest.json (found ${manifestCount})`,
    );
  }
  return metadata;
}

function extractManifest(
  bytes: Uint8Array,
  operation: string,
): { manifest: Manifest; manifestBytes: Uint8Array } {
  let extracted: Record<string, Uint8Array>;
  try {
    extracted = unzipSync(bytes, { filter: (info) => info.name === "manifest.json" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw packageError(operation, `could not read bounded manifest.json: ${message}`, error);
  }
  const manifestBytes = extracted["manifest.json"];
  if (manifestBytes === undefined || manifestBytes.byteLength > MAX_MANIFEST_BYTES) {
    throw packageError(operation, "manifest.json exceeded the bounded read limit");
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes);
    return { manifest: fromWireDict(JSON.parse(text) as unknown), manifestBytes };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw packageError(operation, `manifest.json is invalid: ${message}`, error);
  }
}

function extractBody(
  bytes: Uint8Array,
  metadata: readonly ZipMetadata[],
  operation: string,
): Map<string, Uint8Array> {
  let extracted: Record<string, Uint8Array>;
  try {
    extracted = unzipSync(bytes, { filter: (info) => info.name !== "manifest.json" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw packageError(operation, `could not read package body: ${message}`, error);
  }
  const body = new Map<string, Uint8Array>();
  for (const entry of metadata) {
    if (entry.name === "manifest.json") continue;
    const data = extracted[entry.name];
    if (data === undefined || data.byteLength !== entry.uncompressedSize) {
      throw packageError(operation, `body member ${JSON.stringify(entry.name)} was truncated`);
    }
    body.set(entry.name, data);
  }
  return body;
}

function bodyMapToContents(body: ReadonlyMap<string, Uint8Array>): BodyContents {
  return Object.fromEntries(body);
}

/** Serialize a signed `.tnpkg` to ZIP bytes in memory. */
export function packTnpkgBytes(manifest: Manifest, body: BodyContents): Uint8Array {
  for (const name of Object.keys(body)) validateTnpkgBodyName(name);
  if (!manifest.manifestSignatureB64) {
    throw new Error(
      "packTnpkgBytes: manifest is unsigned. Call signManifestWithBody(...) first; " +
        "the wire format requires manifest_signature_b64 to be present.",
    );
  }
  verifyManifestBodyIndex(manifest, body, true);

  // Serialize the complete TS wire document directly. In particular, do not
  // route through an older manifest-specific WASM normalizer that can discard
  // additive fields such as body_sha256.
  const wireDoc = toWireDict(manifest, true);
  const manifestBytes = canonicalize(wireDoc);
  const entries = [
    { name: "manifest.json", data: manifestBytes },
    ...Object.keys(body)
      .sort()
      .map((name) => ({ name, data: body[name]! })),
  ];
  return packTnpkg(entries);
}

/** Write a signed, body-indexed `.tnpkg` to `outPath`. */
export function writeTnpkg(outPath: string, manifest: Manifest, body: BodyContents): string {
  const bytes = packTnpkgBytes(manifest, body);
  const resolved = pathResolve(outPath);
  const dir = dirname(resolved);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(resolved, Buffer.from(bytes));
  return resolved;
}

/**
 * Open a `.tnpkg` for explicitly unverified legacy inspection.
 *
 * This validates ZIP structure and resource bounds but intentionally does not
 * verify the manifest signature or body index. Security-sensitive consumers
 * must use {@link readTnpkgVerified}.
 */
export function readTnpkg(source: string | Uint8Array): {
  manifest: Manifest;
  body: Map<string, Uint8Array>;
} {
  const operation = "readTnpkg";
  const bytes = readBoundedSource(source, operation);
  const metadata = inspectZip(bytes, operation);
  const { manifest } = extractManifest(bytes, operation);
  const body = extractBody(bytes, metadata, operation);
  return { manifest, body };
}

/**
 * Open a `.tnpkg` through the fail-closed trust boundary.
 *
 * The full input and central-directory declarations are bounded first. Only
 * manifest.json is then inflated and its signature verified. Body members are
 * loaded only after that succeeds, and exact member/digest equality is checked
 * before any body bytes are returned to the caller.
 */
export function readTnpkgVerified(source: string | Uint8Array): {
  manifest: Manifest;
  body: Map<string, Uint8Array>;
} {
  const operation = "readTnpkgVerified";
  const bytes = readBoundedSource(source, operation);
  const metadata = inspectZip(bytes, operation);
  const { manifest } = extractManifest(bytes, operation);
  verifyManifest(manifest);
  const body = extractBody(bytes, metadata, operation);
  verifyManifestBodyIndex(manifest, bodyMapToContents(body), true);
  return { manifest, body };
}
