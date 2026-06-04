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

function makeHandle(fh: TnFileHandle): LocalLogHandle {
  return {
    get name() { return fh.name; },
    read(opts) { return localRead(fh, opts); },
    watch(opts) { return localWatch(fh, opts); },
  };
}

type FsaPicker = (opts?: Record<string, unknown>) => Promise<FileSystemFileHandle[]>;

function requireFsa(api: string): FsaPicker {
  if (typeof window === "undefined" || !("showOpenFilePicker" in window)) {
    throw new Error(
      `${api} requires the File System Access API (Chromium 86+ / Edge 86+). ` +
        `Use fromText() with <input type="file"> for Firefox/Safari.`,
    );
  }
  return (window as typeof window & { showOpenFilePicker: FsaPicker }).showOpenFilePicker;
}

export async function openLogFile(): Promise<LocalLogHandle> {
  const picker = requireFsa("openLogFile");
  const [h] = await picker({
    types: [{ description: "TN Log", accept: { "application/x-ndjson": [".log", ".ndjson"] } }],
    multiple: false,
  });
  return makeHandle(fromFileSystemHandle(h));
}

export function logFileFromHandle(handle: FileSystemFileHandle): LocalLogHandle {
  return makeHandle(fromFileSystemHandle(handle));
}

export async function openKeystore(): Promise<KeystoreHandle> {
  const picker = requireFsa("openKeystore");
  const [h] = await picker({
    types: [{ description: "TN Keystore", accept: { "application/json": [".json"] } }],
    multiple: false,
  });
  return parseKeystore(await (await h.getFile()).text());
}

export function keystoreFromJson(json: string): KeystoreHandle {
  return parseKeystore(json);
}
