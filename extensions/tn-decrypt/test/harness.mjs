// Shared test harness: drive the REAL service worker (background.js) in
// Node under a chrome stub, with the extension's OWN web-target wasm
// bundle pre-initialized.
//
// Why this exists: the older tests (extension_logic.mjs, file_import.mjs)
// re-implement background.js logic inline. That works but it's a second
// copy that can silently drift from the shipped service worker. This
// harness imports the actual background.js so the message dispatch,
// storage helpers, origin gate, classify path, and EMK unlock flow under
// test are the exact code that ships.
//
// Mechanics:
//   1. Pre-init wasm/tn_wasm.js (the same module wasm_loader.js statically
//      imports). ESM caches by resolved URL, so when background.js's lazy
//      ensureWasm() runs, wasm-bindgen sees it already initialized and the
//      loader's idempotent path returns the ready namespace.
//   2. Install a globalThis.chrome stub (storage.local + runtime listeners
//      + getURL/id) and globalThis.crypto (Node webcrypto) so the AES/
//      PBKDF2/EMK paths run unmodified.
//   3. Import background.js with a unique query string per call so each
//      loadBackground() gets a FRESH module instance (fresh in-memory
//      `unlocked` map + `emk`), giving tests isolation. The shared chrome
//      storage is reset on each call too.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const extRoot = resolve(here, "..");

let _wasm = null;
let _loadCounter = 0;
// The chrome stub's backing store is process-global (one chrome object).
// loadBackground() swaps a fresh object into this ref each call.
let _store = {};
let _onMessage = null;
let _onMessageExternal = null;

async function ensureWasmPreinit() {
  if (_wasm) return _wasm;
  const wasmJsPath = resolve(extRoot, "wasm/tn_wasm.js");
  const wasmBgPath = resolve(extRoot, "wasm/tn_wasm_bg.wasm");
  const mod = await import(pathToFileURL(wasmJsPath).href);
  const compiled = await WebAssembly.compile(readFileSync(wasmBgPath));
  await mod.default({ module_or_path: compiled });
  _wasm = mod;
  return mod;
}

function installChromeStub() {
  if (!globalThis.crypto) globalThis.crypto = webcrypto;
  globalThis.chrome = {
    runtime: {
      id: "abcdefghijklmnopabcdefghijklmnop",
      getURL: (p) => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${p}`,
      onMessage: { addListener: (fn) => { _onMessage = fn; } },
      onMessageExternal: { addListener: (fn) => { _onMessageExternal = fn; } },
    },
    storage: {
      local: {
        get: async (keys) => {
          const out = {};
          const list = keys == null
            ? Object.keys(_store)
            : (Array.isArray(keys) ? keys : [keys]);
          for (const k of list) if (k in _store) out[k] = _store[k];
          return out;
        },
        set: async (kv) => { Object.assign(_store, kv); },
        remove: async (key) => {
          for (const k of (Array.isArray(key) ? key : [key])) delete _store[k];
        },
      },
    },
  };
}

/**
 * Load a fresh service worker. Returns helpers bound to that instance.
 *
 * @param {object} [opts]
 * @param {object} [opts.seedStore] initial chrome.storage.local contents
 * @returns {Promise<{ send, sendExternal, getStore, wasm }>}
 */
export async function loadBackground(opts = {}) {
  const wasm = await ensureWasmPreinit();
  installChromeStub();
  _store = { ...(opts.seedStore || {}) };
  _onMessage = null;
  _onMessageExternal = null;

  _loadCounter += 1;
  const url = pathToFileURL(resolve(extRoot, "background.js")).href + `?h=${_loadCounter}`;
  await import(url);
  if (typeof _onMessage !== "function") {
    throw new Error("background.js did not register an onMessage listener");
  }

  // Promisified mirror of chrome.runtime.sendMessage: the SW handler
  // returns `true` to signal it will call sendResponse asynchronously.
  const send = (msg) => new Promise((res) => {
    const ret = _onMessage(msg, {}, res);
    if (ret !== true) res(undefined);
  });

  // Mirror of chrome.runtime.onMessageExternal: sender carries a url the
  // origin gate inspects.
  const sendExternal = (msg, senderUrl) => new Promise((res) => {
    const ret = _onMessageExternal
      ? _onMessageExternal(msg, { url: senderUrl }, res)
      : res({ ok: false, reason: "no external listener" });
    if (ret !== true) res(undefined);
  });

  // Flush the fire-and-forget boot IIFE (auto-load local-file keystores)
  // so callers see a settled state.
  await send({ type: "status" });

  return { send, sendExternal, getStore: () => _store, wasm };
}

// ── tiny assertion + crypto fixture helpers ────────────────────────────

export function makeAsserter() {
  let passed = 0, failed = 0;
  const ok = (m) => { console.log(`[ok]   ${m}`); passed += 1; };
  const fail = (m, why) => { console.log(`[fail] ${m}: ${why}`); failed += 1; };
  const eq = (m, got, want) => {
    if (got === want) ok(m);
    else fail(m, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
  };
  const truthy = (m, v) => { if (v) ok(m); else fail(m, `value was ${JSON.stringify(v)}`); };
  const done = () => {
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
  };
  return { ok, fail, eq, truthy, done, counts: () => ({ passed, failed }) };
}

export function bytesToB64(bytes) {
  const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of a) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex(bytes) {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Mint a btn publisher + self-kit, and a one-line ciphertext, using the
 * extension's own wasm bundle. Returns { kit, kitB64, pubIdHex, encrypt }.
 */
export function makePublisher(wasm, seedByte) {
  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (seedByte + i * 3 + 7) & 0xff;
  const pub = new wasm.BtnPublisher(btnSeed);
  const kit = pub.mint();
  const pubIdHex = hex(wasm.btnKitPublisherId(kit));
  const encrypt = (obj) => wasm.btnDecrypt
    ? pub.encrypt(wasm.canonicalBytes(obj))
    : null;
  return {
    pub, kit, kitB64: bytesToB64(kit), pubIdHex,
    encryptB64: (obj) => bytesToB64(pub.encrypt(wasm.canonicalBytes(obj))),
    free: () => pub.free(),
  };
}

/**
 * Build a passphrase-encrypted vault blob the way the vault/website does,
 * matching background.js::decryptKeystoreBlob (PBKDF2-SHA256 + AES-GCM).
 */
export async function makeVaultBlob(bundleObj, passphrase, iterations = 260000) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const pk = await webcrypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), { name: "PBKDF2" }, false, ["deriveKey"],
  );
  const key = await webcrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    pk, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const ct = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(JSON.stringify(bundleObj)),
  ));
  return {
    salt_b64: bytesToB64(salt),
    nonce_b64: bytesToB64(nonce),
    ciphertext_b64: bytesToB64(ct),
    kdf_params: { iterations },
  };
}

/**
 * Derive the 32-byte EMK material the popup ships to setupExtensionUnlock/
 * unlockExtension from a passphrase (PBKDF2-SHA256 deriveBits(256)).
 * Mirrors popup.js::deriveEmkRawFromPassphrase.
 */
export async function deriveEmkRaw(passphrase, saltBytes, iterations) {
  const pk = await webcrypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), { name: "PBKDF2" }, false, ["deriveBits"],
  );
  const bits = await webcrypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" }, pk, 256,
  );
  return new Uint8Array(bits);
}
