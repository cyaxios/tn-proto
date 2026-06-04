// Public API for @tnproto/sdk/local — browser-local TN log reader.
//
// openLogFile / openKeystore require File System Access API (Chromium 86+, Edge 86+).
// Firefox / Safari: read the file via <input type="file">, pass contents to
// keystoreFromJson() and wrap with fromText() or logFileFromHandle().

export type { TnFileHandle } from "./file_handle.js";
export { fromFileSystemHandle, fromText } from "./file_handle.js";
export type { KeystoreHandle } from "./keystore.js";
export { parseKeystore } from "./keystore.js";
export type { ReadOpts } from "./read.js";
export { localRead } from "./read.js";
export type { WatchOpts } from "./watch.js";
export { localWatch } from "./watch.js";

import { fromFileSystemHandle, type TnFileHandle } from "./file_handle.js";
import { parseKeystore, type KeystoreHandle } from "./keystore.js";
import { localRead, type ReadOpts } from "./read.js";
import { localWatch, type WatchOpts } from "./watch.js";
import type { Entry } from "../Entry.js";

export interface LocalLogHandle {
  readonly name: string;
  read(opts?: ReadOpts): AsyncIterable<Entry>;
  watch(opts?: WatchOpts): AsyncIterable<Entry>;
}

/** Minimal FSA handle surface this module needs. Structurally compatible with
 * FileSystemFileHandle from the browser File System Access API. */
interface FsaHandle {
  readonly name: string;
  getFile(): Promise<{
    readonly size: number;
    text(): Promise<string>;
    slice(start?: number, end?: number): { text(): Promise<string> };
  }>;
}

type FsaPicker = (opts?: Record<string, unknown>) => Promise<FsaHandle[]>;

function requireFsa(api: string): FsaPicker {
  const g = globalThis as Record<string, unknown>;
  if (typeof g["showOpenFilePicker"] !== "function") {
    throw new Error(
      `${api} requires the File System Access API (Chromium 86+ / Edge 86+). ` +
        `Use fromText() with <input type="file"> for Firefox/Safari.`,
    );
  }
  return g["showOpenFilePicker"] as FsaPicker;
}

function makeHandle(fh: TnFileHandle): LocalLogHandle {
  return {
    get name() { return fh.name; },
    read(opts) { return localRead(fh, opts); },
    watch(opts) { return localWatch(fh, opts); },
  };
}

export async function openLogFile(): Promise<LocalLogHandle> {
  const picker = requireFsa("openLogFile");
  const handles = await picker({
    types: [{ description: "TN Log", accept: { "application/x-ndjson": [".log", ".ndjson"] } }],
    multiple: false,
  });
  const h = handles[0];
  if (!h) throw new Error("openLogFile: no file selected");
  return makeHandle(fromFileSystemHandle(h));
}

export function logFileFromHandle(handle: FsaHandle): LocalLogHandle {
  return makeHandle(fromFileSystemHandle(handle));
}

export async function openKeystore(): Promise<KeystoreHandle> {
  const picker = requireFsa("openKeystore");
  const handles = await picker({
    types: [{ description: "TN Keystore", accept: { "application/json": [".json"] } }],
    multiple: false,
  });
  const h = handles[0];
  if (!h) throw new Error("openKeystore: no file selected");
  return parseKeystore(await (await h.getFile()).text());
}

export function keystoreFromJson(json: string): KeystoreHandle {
  return parseKeystore(json);
}
