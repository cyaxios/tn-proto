// Node-side `Storage` adapter for `WasmRuntime`.
//
// `tn-wasm`'s `WasmRuntime.init(yamlPath, storage)` expects a plain JS
// object whose properties are nine synchronous callbacks — see
// `crypto/tn-wasm/src/storage.rs::JsStorageAdapter::from_js` for the
// authoritative contract. This module returns exactly that object,
// wrapping `node:fs` *Sync calls.
//
// Phase 7 of the wasm-widen plan (see
// `docs/superpowers/plans/2026-05-13-wasm-widen-and-fallback-deprecate.md`
// §2.3). Browser-side `IndexedDbStorageAdapter` is Phase 7b and only
// stubbed here.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

/**
 * The shape of the JS object `JsStorageAdapter::from_js` looks up by
 * property name. Every callback is **synchronous** — `JsStorageAdapter`
 * calls them through `js_sys::Function::call*`, which has no notion of
 * awaiting a promise on the Rust side. Throwing a JS `Error` from a
 * callback maps to an `io::Error{kind: Other}` on the Rust side, with
 * the message coming from `err.message`.
 *
 * Paths arrive as strings; byte payloads as `Uint8Array`.
 */
export interface JsStorageCallbacks {
  /** Read the full contents of `path`. Throws on missing. */
  read(path: string): Uint8Array;
  /** Overwrite `path` with `data`, creating parent dirs as needed. */
  write(path: string, data: Uint8Array): void;
  /** Append `data` to `path`, creating the file + parents if absent. */
  append(path: string, data: Uint8Array): void;
  /** Whether `path` exists. */
  exists(path: string): boolean;
  /** List entries under `dir`. Returned strings are full paths. */
  list(dir: string): string[];
  /** Atomic rename. */
  rename(from: string, to: string): void;
  /** Remove a file. */
  remove(path: string): void;
  /** Recursively create `dir`. */
  createDirAll(dir: string): void;
  /**
   * Compare-and-swap write.
   *
   * - `prior === null` means "no prior expected; this should be a fresh
   *   write." If the file already exists with non-empty bytes, throws
   *   `cas-mismatch: ...`.
   * - `prior` non-null: read current bytes; if they differ from `prior`
   *   byte-for-byte, throws `cas-mismatch: ...`.
   * - Otherwise: tmp + rename, mirroring `FsStorage::cas_write`.
   *
   * The `cas-mismatch:` prefix is the convention from the Rust side so
   * callers can pattern-match on the error message.
   */
  casWrite(path: string, prior: Uint8Array | null, newData: Uint8Array): void;
}

/** Process-local monotonic counter to disambiguate concurrent tmpfiles. */
let _tmpCounter = 0;

/** Build a fresh tmpfile path next to `target`. */
function _tmpPathFor(target: string): string {
  _tmpCounter += 1;
  // Match the Rust `atomic_write_via_tmp` shape: `.<name>.tmp.<pid>.<counter>`.
  return join(dirname(target), `.${basename(target)}.tmp.${process.pid}.${_tmpCounter}`);
}

/**
 * Byte-for-byte equality between two `Uint8Array`s. Cheap fast-paths
 * for length mismatch and identical references.
 */
function _bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a === b) return true;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Construct a [`JsStorageCallbacks`] object suitable for handing to
 * `WasmRuntime.init(yamlPath, storage)`.
 *
 * Stateless: the returned object captures no module-level state beyond
 * the tmp-counter used for `casWrite` tmpfile naming. Safe to call
 * once per `WasmRuntime` instance or once per process, your choice.
 */
export function nodeStorageAdapter(): JsStorageCallbacks {
  return {
    read(path) {
      return new Uint8Array(readFileSync(path));
    },

    write(path, data) {
      // Parent-dir creation matches `FsStorage::write_bytes`. The Rust
      // side relies on this — `Runtime::init_with_storage` writes into
      // `<keystore>/...` without first calling `createDirAll` when the
      // parent already exists from an earlier mint step.
      const parent = dirname(path);
      if (parent && parent !== path) {
        mkdirSync(parent, { recursive: true });
      }
      writeFileSync(path, data);
    },

    append(path, data) {
      const parent = dirname(path);
      if (parent && parent !== path) {
        mkdirSync(parent, { recursive: true });
      }
      appendFileSync(path, data);
    },

    exists(path) {
      return existsSync(path);
    },

    list(dir) {
      // Return full paths to match `FsStorage::list`, which yields
      // `entry.path()` (i.e. `dir.join(child_name)`).
      return readdirSync(dir).map((name) => join(dir, name));
    },

    rename(from, to) {
      renameSync(from, to);
    },

    remove(path) {
      unlinkSync(path);
    },

    createDirAll(dir) {
      mkdirSync(dir, { recursive: true });
    },

    casWrite(path, prior, newData) {
      // Mirror of `FsStorage::cas_write` (crypto/tn-core/src/storage.rs).
      // We don't have an advisory lock here — Node-side TN is
      // single-process by convention, and the wasm runtime is itself
      // single-threaded. CAS for us is: re-read, compare to `prior`,
      // atomic-write via tmp+rename. Concurrent multi-process writers
      // would need `proper-lockfile` or similar; out of scope here.

      const parent = dirname(path);
      if (parent && parent !== path) {
        mkdirSync(parent, { recursive: true });
      }

      const exists = existsSync(path);
      let current: Uint8Array | null = null;
      if (exists) {
        // statSync to detect dir-vs-file before we try to read.
        const st = statSync(path);
        if (st.isFile()) {
          current = new Uint8Array(readFileSync(path));
        }
      }

      if (prior === null) {
        // "Fresh write expected." If the file already exists with
        // non-empty bytes, that's a CAS miss — somebody beat us.
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

      // Atomic publish: write to a sibling tmpfile with the `wx` flag
      // (fail-if-exists) so a stray concurrent writer in the same
      // process collides loudly rather than silently overwriting; then
      // renameSync over the target.
      const tmp = _tmpPathFor(path);
      try {
        writeFileSync(tmp, newData, { flag: "wx" });
        renameSync(tmp, path);
      } catch (err) {
        // Best-effort cleanup of the tmpfile on any failure during
        // write/rename. We don't surface the cleanup error.
        try {
          unlinkSync(tmp);
        } catch {
          /* tmpfile may not exist; ignore */
        }
        throw err;
      }
    },
  };
}

/**
 * Browser-side `IndexedDbStorageAdapter` placeholder.
 *
 * **Not implemented.** IndexedDB is async and the `JsStorageCallbacks`
 * contract is synchronous; bridging that needs either a preload-into-
 * memory-cache step or `SharedArrayBuffer + Atomics.wait`, both of
 * which are Phase 7b. See
 * `docs/superpowers/plans/2026-05-13-wasm-widen-and-fallback-deprecate.md`.
 */
export function indexedDbStorageAdapter(): JsStorageCallbacks {
  throw new Error(
    "indexedDbStorageAdapter: not yet implemented (Phase 7b). " +
      "Browser-side wasm storage needs a sync shim over async IndexedDB.",
  );
}
