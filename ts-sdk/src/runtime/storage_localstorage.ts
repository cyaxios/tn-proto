// Browser-side `localStorage` adapter for `WasmRuntime`.
//
// Satisfies `JsStorageCallbacks` (see `storage_node.ts` for the contract
// shape) by mapping each "path" onto a key in `window.localStorage`.
// All nine callbacks are synchronous, matching the Rust-side contract
// — `localStorage` itself is sync, so no buffering or sync-shim trickery
// is needed.
//
// Why localStorage over IndexedDB / OPFS:
//   * Sync. Keeps Tn's verb surface (tn.info / tn.log / tn.read / etc.)
//     sync just like Node, so browser code reads the same as Node code.
//   * Available in every browser back to ~2009. No feature-detection.
//   * Simple key/value semantics line up trivially with the flat "path"
//     keys WasmRuntime emits — no schema, no transactions, no openDB.
// Tradeoff: ~5 MB per-origin quota. Adequate for any "log a few thousand
// events per session" use case; not adequate for a primary high-volume
// telemetry sink. Quota-exceeded surfaces as a recognisable error.
//
// Binary <-> string: localStorage stores strings only. Bytes are
// base64-encoded on write and decoded on read. ~33% overhead vs raw,
// trivial CPU cost. Pure-JS implementations (no Buffer / atob/btoa
// quirks with non-Latin-1) so the same code runs in workers, MV3
// extensions, anywhere localStorage exists.
//
// Path semantics match storage_memory.ts: paths are opaque string keys,
// `/`-separated, normalized by dropping empty + `.` segments and
// resolving `..`. Directories are implicit (`createDirAll` is a no-op).

import type { JsStorageCallbacks } from "./storage_node.js";

/**
 * Optional knobs for the localStorage adapter.
 */
export interface LocalStorageAdapterOptions {
  /**
   * Prefix prepended to every key written into `localStorage`. Lets
   * multiple ceremonies (or multiple TN apps) coexist on the same
   * origin without collision. Default: `"tn/"`.
   *
   * Example: with `keyPrefix: "myapp/"`, a path of `/v/tn.yaml` ends
   * up at `localStorage["myapp//v/tn.yaml"]`. (The leading `/` is
   * preserved verbatim after normalization.)
   */
  keyPrefix?: string;

  /**
   * Override the storage backend. Defaults to `window.localStorage`.
   * Passed explicitly mainly for tests — you can hand in a Map-backed
   * shim that exposes the same `getItem` / `setItem` / `removeItem` /
   * `key` / `length` surface.
   */
  storage?: Storage;
}

export interface LocalStorageAdapter extends JsStorageCallbacks {
  /** Pull every (path, bytes) entry out as a plain object. */
  snapshot(): Record<string, Uint8Array>;
  /** Insert or replace a single entry (used by tests + migrations). */
  put(path: string, data: Uint8Array): void;
  /** Number of entries currently held under this prefix. */
  size(): number;
  /** Drop every entry under this prefix. */
  clearAll(): void;
}

/**
 * Standard error type thrown when a write would exceed the
 * per-origin localStorage quota. Caller code can `instanceof` route
 * on this to surface a "switch storage" UX without parsing message
 * strings.
 */
export class LocalStorageQuotaError extends Error {
  readonly path: string;
  readonly bytesAttempted: number;
  constructor(path: string, bytesAttempted: number, cause?: unknown) {
    super(
      `localStorage quota exceeded while writing ${path} ` +
        `(${bytesAttempted} bytes). The per-origin quota is typically ~5 MB.`,
    );
    this.name = "LocalStorageQuotaError";
    this.path = path;
    this.bytesAttempted = bytesAttempted;
    if (cause !== undefined) (this as Error & { cause?: unknown }).cause = cause;
  }
}

const DEFAULT_KEY_PREFIX = "tn/";

/**
 * Build a localStorage-backed storage adapter.
 *
 * The returned object IS both the `JsStorageCallbacks` shape that
 * `WasmRuntime.init(yamlPath, storage)` expects AND the
 * `LocalStorageAdapter` interface with helpers for testing and
 * migration.
 */
export function localStorageStorageAdapter(
  opts?: LocalStorageAdapterOptions,
): LocalStorageAdapter {
  const keyPrefix = opts?.keyPrefix ?? DEFAULT_KEY_PREFIX;
  const backend: Storage = opts?.storage ?? _defaultStorage();

  /**
   * Normalize a path the same way storage_memory.ts does: drop empty +
   * `.` segments, resolve `..` segments, preserve leading `/`. Rust
   * emits paths like `/v/./.tn/keys/local.private`; storage_node gets
   * away without normalization because node:fs handles `./` natively.
   * We compare by string key, so we have to normalize ourselves.
   */
  function _normalizePath(p: string): string {
    const isAbsolute = p.startsWith("/");
    const parts = p
      .split("/")
      .filter((part) => part.length > 0 && part !== ".");
    const out: string[] = [];
    for (const part of parts) {
      if (part === "..") out.pop();
      else out.push(part);
    }
    return (isAbsolute ? "/" : "") + out.join("/");
  }

  function _storageKey(path: string): string {
    return keyPrefix + _normalizePath(path);
  }

  function _enoent(path: string): Error {
    return new Error(`ENOENT: no entry at ${JSON.stringify(path)} (localStorageAdapter)`);
  }

  function _bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  function _isQuotaError(err: unknown): boolean {
    if (!err) return false;
    // Spec: DOMException with code 22 (QUOTA_EXCEEDED_ERR) or name
    // "QuotaExceededError" / "NS_ERROR_DOM_QUOTA_REACHED" (Firefox).
    if (typeof DOMException !== "undefined" && err instanceof DOMException) {
      if (err.code === 22) return true;
      if (err.name === "QuotaExceededError") return true;
      if (err.name === "NS_ERROR_DOM_QUOTA_REACHED") return true;
    }
    const name = (err as { name?: string })?.name;
    return name === "QuotaExceededError" || name === "NS_ERROR_DOM_QUOTA_REACHED";
  }

  function _setItem(path: string, key: string, value: string): void {
    try {
      backend.setItem(key, value);
    } catch (err) {
      if (_isQuotaError(err)) {
        throw new LocalStorageQuotaError(path, value.length, err);
      }
      throw err;
    }
  }

  // ── Helpers for prefix iteration ───────────────────────────────────

  /** Yield every (storage-key, path-key) pair under this prefix. */
  function* _entries(): Generator<[string, string]> {
    for (let i = 0; i < backend.length; i++) {
      const k = backend.key(i);
      if (k === null) continue;
      if (!k.startsWith(keyPrefix)) continue;
      yield [k, k.slice(keyPrefix.length)];
    }
  }

  // ── JsStorageCallbacks impl ────────────────────────────────────────

  return {
    read(path) {
      const v = backend.getItem(_storageKey(path));
      if (v === null) throw _enoent(path);
      return _b64Decode(v);
    },

    write(path, data) {
      _setItem(path, _storageKey(path), _b64Encode(data));
    },

    append(path, data) {
      const key = _storageKey(path);
      const existing = backend.getItem(key);
      if (existing === null) {
        _setItem(path, key, _b64Encode(data));
        return;
      }
      const before = _b64Decode(existing);
      const merged = new Uint8Array(before.length + data.length);
      merged.set(before, 0);
      merged.set(data, before.length);
      _setItem(path, key, _b64Encode(merged));
    },

    exists(path) {
      return backend.getItem(_storageKey(path)) !== null;
    },

    list(dir) {
      const normDir = _normalizePath(dir);
      const prefix = normDir.endsWith("/") ? normDir : normDir + "/";
      const out: string[] = [];
      for (const [, pathKey] of _entries()) {
        if (!pathKey.startsWith(prefix)) continue;
        const rest = pathKey.slice(prefix.length);
        // Direct children only — no further `/` in the remainder.
        if (rest.length === 0 || rest.includes("/")) continue;
        out.push(pathKey);
      }
      return out;
    },

    rename(from, to) {
      const fromKey = _storageKey(from);
      const v = backend.getItem(fromKey);
      if (v === null) throw _enoent(from);
      _setItem(to, _storageKey(to), v);
      backend.removeItem(fromKey);
    },

    remove(path) {
      const key = _storageKey(path);
      if (backend.getItem(key) === null) throw _enoent(path);
      backend.removeItem(key);
    },

    createDirAll(_dir) {
      // No-op: paths are flat keys; directories are implicit.
    },

    casWrite(path, prior, newData) {
      const key = _storageKey(path);
      const currentStr = backend.getItem(key);
      const current = currentStr === null ? null : _b64Decode(currentStr);

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

      // localStorage has no atomic rename; setItem itself is atomic
      // for a single key (no torn writes within one tab), which is
      // what callers actually need. The Node implementation's
      // tmp-file-then-rename dance is for crash-resilience against
      // process kill mid-write, which doesn't apply here.
      _setItem(path, key, _b64Encode(newData));
    },

    // ── Adapter-only helpers (not part of JsStorageCallbacks) ─────

    snapshot() {
      const out: Record<string, Uint8Array> = {};
      for (const [storageKey, pathKey] of _entries()) {
        const v = backend.getItem(storageKey);
        if (v === null) continue;
        out[pathKey] = _b64Decode(v);
      }
      return out;
    },

    put(path, data) {
      _setItem(path, _storageKey(path), _b64Encode(data));
    },

    size() {
      let n = 0;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for (const _ of _entries()) n += 1;
      return n;
    },

    clearAll() {
      // Collect first, delete after — iterating `backend` while mutating
      // is unspecified.
      const toRemove: string[] = [];
      for (const [storageKey] of _entries()) toRemove.push(storageKey);
      for (const k of toRemove) backend.removeItem(k);
    },
  };
}

// ── Default-backend resolution ───────────────────────────────────────

function _defaultStorage(): Storage {
  if (typeof localStorage !== "undefined") return localStorage;
  if (typeof globalThis !== "undefined") {
    const g = globalThis as { localStorage?: Storage };
    if (g.localStorage) return g.localStorage;
  }
  throw new Error(
    "localStorageStorageAdapter: window.localStorage is not available in this " +
      "JS context. Pass an explicit `storage` shim in the options if you're " +
      "using a non-browser host.",
  );
}

// ── Base64 helpers ───────────────────────────────────────────────────
//
// Browser-safe, pure-JS, no Buffer / TextEncoder dependency. We don't
// use `btoa(String.fromCharCode(...))` because that path breaks on
// strings longer than the engine's argument-count limit; the byte-wise
// loop here is unconditional.

const _B64_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function _b64Encode(bytes: Uint8Array): string {
  // Local-binding aliases keep TS's noUncheckedIndexedAccess happy
  // without `!`-littering every line. The loop bounds guarantee every
  // index is in range, so the `?? 0` fallback never fires at runtime.
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    out += _B64_CHARS.charAt(a >> 2);
    out += _B64_CHARS.charAt(((a & 0x03) << 4) | (b >> 4));
    out += _B64_CHARS.charAt(((b & 0x0f) << 2) | (c >> 6));
    out += _B64_CHARS.charAt(c & 0x3f);
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const a = bytes[i] ?? 0;
    out += _B64_CHARS.charAt(a >> 2);
    out += _B64_CHARS.charAt((a & 0x03) << 4);
    out += "==";
  } else if (rem === 2) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1] ?? 0;
    out += _B64_CHARS.charAt(a >> 2);
    out += _B64_CHARS.charAt(((a & 0x03) << 4) | (b >> 4));
    out += _B64_CHARS.charAt((b & 0x0f) << 2);
    out += "=";
  }
  return out;
}

const _B64_LOOKUP: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < _B64_CHARS.length; i++) t[_B64_CHARS.charCodeAt(i)] = i;
  return t;
})();

function _b64Decode(s: string): Uint8Array {
  // Strip a single trailing newline if present (some serializers add
  // one; localStorage round-trips are exact so this is paranoia).
  let end = s.length;
  while (end > 0 && (s.charCodeAt(end - 1) === 10 || s.charCodeAt(end - 1) === 13)) end -= 1;
  // Padding count
  let pad = 0;
  if (end > 0 && s.charCodeAt(end - 1) === 61) pad += 1;
  if (end > 1 && s.charCodeAt(end - 2) === 61) pad += 1;
  const usable = end - pad;
  // 4 b64 chars -> 3 bytes; minus padding.
  const groups = Math.floor(usable / 4);
  const tail = usable - groups * 4;
  const byteLen =
    groups * 3 + (tail === 0 ? 0 : tail === 2 ? 1 : tail === 3 ? 2 : 0);
  const out = new Uint8Array(byteLen);
  let oi = 0;
  let i = 0;
  // _B64_LOOKUP is a 128-slot Int16Array (.charCodeAt for printable ASCII
  // stays in range); reads always return `number`. The `?? 0` fallbacks
  // exist purely to satisfy noUncheckedIndexedAccess and never fire at
  // runtime — input is already trimmed to base64 chars by the caller.
  for (; i + 4 <= usable; i += 4) {
    const a = _B64_LOOKUP[s.charCodeAt(i)] ?? 0;
    const b = _B64_LOOKUP[s.charCodeAt(i + 1)] ?? 0;
    const c = _B64_LOOKUP[s.charCodeAt(i + 2)] ?? 0;
    const d = _B64_LOOKUP[s.charCodeAt(i + 3)] ?? 0;
    out[oi++] = (a << 2) | (b >> 4);
    out[oi++] = ((b & 0x0f) << 4) | (c >> 2);
    out[oi++] = ((c & 0x03) << 6) | d;
  }
  if (tail === 2) {
    const a = _B64_LOOKUP[s.charCodeAt(i)] ?? 0;
    const b = _B64_LOOKUP[s.charCodeAt(i + 1)] ?? 0;
    out[oi++] = (a << 2) | (b >> 4);
  } else if (tail === 3) {
    const a = _B64_LOOKUP[s.charCodeAt(i)] ?? 0;
    const b = _B64_LOOKUP[s.charCodeAt(i + 1)] ?? 0;
    const c = _B64_LOOKUP[s.charCodeAt(i + 2)] ?? 0;
    out[oi++] = (a << 2) | (b >> 4);
    out[oi++] = ((b & 0x0f) << 4) | (c >> 2);
  }
  return out;
}
