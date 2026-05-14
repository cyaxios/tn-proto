// Browser-safe in-memory `Storage` adapter for `WasmRuntime`.
//
// Satisfies `JsStorageCallbacks` (see `storage_node.ts` for the contract
// shape) using only a `Map<string, Uint8Array>` under the hood — no
// `node:fs`, no `node:path`, no native I/O at all. Importing this file
// is safe in any JS context: browser tab, service worker, CF Workers,
// Deno, Bun, Node, anywhere.
//
// **Use case**: in-browser minting / emit / read flows. The app is
// responsible for persistence — load the keystore + yaml into memory
// before calling `WasmRuntime.init(...)`, run the runtime in-process,
// then read the resulting bytes back out and persist however the host
// stores things (IndexedDB, fetch-to-server, IPC, drag-drop, etc.).
//
// **Path semantics**: paths are opaque string keys. Use `/` separators
// (wasm32's `std::path` is Unix-only and `WasmRuntime.init` normalizes
// `\` → `/` before handing the yaml path to Rust, so all paths the
// Rust side then constructs internally are `/`-separated). Callers
// who preload from disk should normalize separators themselves.
//
// **Persistence handoff**: call `snapshot()` after a runtime close to
// pull every byte back out as `Record<string, Uint8Array>`. Pass into
// `memoryStorageAdapter(snapshot)` on next mount to round-trip.

import type { JsStorageCallbacks } from "./storage_node.js";

export interface MemoryStorageAdapter extends JsStorageCallbacks {
  /** Pull every (path, bytes) entry out as a plain object for persistence. */
  snapshot(): Record<string, Uint8Array>;
  /** Insert or replace a single entry. Useful for incremental preloads. */
  put(path: string, data: Uint8Array): void;
  /** Number of entries currently held. */
  size(): number;
}

/**
 * Build an in-memory storage adapter pre-loaded with `preload` entries.
 *
 * The returned object IS both the `JsStorageCallbacks` shape that
 * `WasmRuntime.init(yamlPath, storage)` expects AND the
 * `MemoryStorageAdapter` interface with `snapshot()`/`put()`/`size()`
 * helpers for persistence handoff.
 *
 * Example browser minting flow:
 * ```ts
 * const stateBytes = await fetchPublisherStateFromServer();
 * const storage = memoryStorageAdapter({
 *   "/v/tn.yaml":                   new TextEncoder().encode(yamlText),
 *   "/v/.tn/keys/local.private":    stateBytes.priv,
 *   "/v/.tn/keys/local.public":     stateBytes.pub,
 *   "/v/.tn/keys/index_master.key": stateBytes.indexMaster,
 *   "/v/.tn/keys/default.btn.state":stateBytes.btnState,
 *   "/v/.tn/keys/default.btn.mykit":stateBytes.btnKit,
 * });
 * const rt = WasmRuntime.initWith("/v/tn.yaml", storage, {
 *   skipCeremonyInitEmit: true,
 *   skipPolicyPublishedEmit: true,
 * });
 * rt.adminAddRecipient("default", "/v/.tn/keys/bob.btn.mykit", "did:key:zBob...");
 * const finalState = storage.snapshot();
 * await persistToIndexedDb(finalState);
 * ```
 */
export function memoryStorageAdapter(
  preload?: Record<string, Uint8Array>,
): MemoryStorageAdapter {
  const files = new Map<string, Uint8Array>();
  // Normalize preload keys so callers can use idiomatic relative-style
  // paths without worrying about whether Rust emits `/./` or not.
  if (preload) {
    for (const [k, v] of Object.entries(preload)) {
      files.set(_normalizePath(k), v);
    }
  }

  /**
   * Normalize a path: drop empty + `.` segments, resolve `..` segments,
   * preserve a leading `/` if the input was absolute. The Rust side
   * passes paths like `"/v/./.tn/keys/local.private"` after joining a
   * relative `keystore.path` (`"./.tn/keys"`) onto the yaml's parent
   * dir — `nodeStorageAdapter` gets away without normalization because
   * Node's `fs` resolves `./` segments natively. The in-memory map
   * compares keys by exact string, so we have to normalize ourselves.
   */
  function _normalizePath(p: string): string {
    const isAbsolute = p.startsWith("/");
    const parts = p
      .split("/")
      .filter((part) => part.length > 0 && part !== ".");
    const out: string[] = [];
    for (const part of parts) {
      if (part === "..") {
        out.pop();
      } else {
        out.push(part);
      }
    }
    return (isAbsolute ? "/" : "") + out.join("/");
  }

  function _enoent(path: string): Error {
    return new Error(`ENOENT: no entry at ${JSON.stringify(path)} (memoryStorageAdapter)`);
  }

  function _bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  return {
    read(path) {
      const key = _normalizePath(path);
      const v = files.get(key);
      if (!v) throw _enoent(path);
      // Return a copy so callers (Rust-side) can't mutate our internal map.
      return new Uint8Array(v);
    },
    write(path, data) {
      // Copy so post-write mutation by the caller doesn't bleed back in.
      files.set(_normalizePath(path), new Uint8Array(data));
    },
    append(path, data) {
      const key = _normalizePath(path);
      const existing = files.get(key);
      if (!existing) {
        files.set(key, new Uint8Array(data));
        return;
      }
      const merged = new Uint8Array(existing.length + data.length);
      merged.set(existing, 0);
      merged.set(data, existing.length);
      files.set(key, merged);
    },
    exists(path) {
      return files.has(_normalizePath(path));
    },
    list(dir) {
      const normDir = _normalizePath(dir);
      const prefix = normDir.endsWith("/") ? normDir : normDir + "/";
      const out: string[] = [];
      for (const k of files.keys()) {
        if (!k.startsWith(prefix)) continue;
        const rest = k.slice(prefix.length);
        // Direct children only — no further `/` in the remainder.
        if (rest.length === 0 || rest.includes("/")) continue;
        out.push(k);
      }
      return out;
    },
    rename(from, to) {
      const fromKey = _normalizePath(from);
      const v = files.get(fromKey);
      if (!v) throw _enoent(from);
      files.delete(fromKey);
      files.set(_normalizePath(to), v);
    },
    remove(path) {
      const key = _normalizePath(path);
      if (!files.has(key)) throw _enoent(path);
      files.delete(key);
    },
    createDirAll(_dir) {
      // No-op: paths are flat keys; directories are implicit.
    },
    casWrite(path, prior, newData) {
      const key = _normalizePath(path);
      const current = files.get(key) ?? null;
      if (prior === null) {
        if (current !== null && current.length > 0) {
          throw new Error(
            `cas-mismatch: ${path} already exists (expected no prior, found ${current.length} bytes)`,
          );
        }
      } else {
        if (current === null) {
          throw new Error(
            `cas-mismatch: ${path} does not exist (expected ${prior.length} bytes of prior)`,
          );
        }
        if (!_bytesEqual(current, prior)) {
          throw new Error(
            `cas-mismatch: ${path} on-disk bytes differ from caller-supplied prior`,
          );
        }
      }
      files.set(key, new Uint8Array(newData));
    },
    snapshot() {
      const out: Record<string, Uint8Array> = {};
      for (const [k, v] of files) out[k] = new Uint8Array(v);
      return out;
    },
    put(path, data) {
      files.set(_normalizePath(path), new Uint8Array(data));
    },
    size() {
      return files.size;
    },
  };
}
