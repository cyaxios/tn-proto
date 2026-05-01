// Single-flight loader for the tn-wasm bundle inside the extension
// service worker (and any other extension page that wants to call wasm
// directly).
//
// Mirrors the dashboard's loader at
// `tnproto-org/static/dashboard/wasm_loader.js` — same single-flight
// promise cache, same idempotent init, same wasm-bindgen `__wbg_init`
// invocation. The only thing that's different here is the URL we hand
// to `import()` and the URL we hand to `__wbg_init`: both go through
// `chrome.runtime.getURL(...)` so they resolve to `chrome-extension://`
// regardless of whether we're running in the SW, popup, or options
// page. The MV3 service-worker fetch sandbox accepts those URLs; a raw
// `/wasm/...` path would not resolve.
//
// Refs:
//   - dashboard wasm_loader (canonical pattern, commit be3e4701)
//   - manifest.json `web_accessible_resources` exposes both files
//   - D-13 (browser calls tn-wasm primitives directly, not through
//     TNClient — TNClient depends on node:fs)
//   - D-28 (typed errors + structured logging — informs the [ext]
//     breadcrumb style emitted here)

const WASM_BG_PATH = "wasm/tn_wasm_bg.wasm";

// Static top-level import. MV3 service workers REJECT dynamic
// ``import(url)`` at runtime ("import() is disallowed on
// ServiceWorkerGlobalScope by the HTML specification" — w3c/
// ServiceWorker#1356). The previous version of this loader used a
// dynamic import to mirror the dashboard pattern, which works in a
// regular page but blows up the moment the SW handler tries to load
// wasm. The fix: import statically up here, where the SW evaluates
// the module graph at startup. The manifest declares the SW as
// ``"type": "module"`` so this is legal; ``web_accessible_resources``
// exposes the wasm file so ``chrome.runtime.getURL`` still resolves.
import * as _tnWasmMod from "./wasm/tn_wasm.js";

let _initPromise = null;

/**
 * Load (or return cached) tn-wasm module. Returns the module namespace
 * object directly so callers can reach for `mod.btnDecrypt`,
 * `mod.btnCiphertextPublisherId`, etc.
 *
 * Idempotent — first call drives init, subsequent calls resolve to the
 * cached promise. Safe to call from any extension context that has
 * ``chrome.runtime`` available (SW, popup, options, content script).
 */
export async function loadTnWasm() {
  if (_initPromise === null) {
    const t0 = Date.now();
    _initPromise = (async () => {
      const bgUrl = chrome.runtime.getURL(WASM_BG_PATH);
      console.log(`[ext:wasm] init wasm-bindgen with ${bgUrl}`);
      if (typeof _tnWasmMod.default === "function") {
        try {
          // Object form is the new wasm-bindgen API; the bare URL
          // form triggers a deprecation warning.
          await _tnWasmMod.default({ module_or_path: bgUrl });
        } catch (e) {
          // wasm-bindgen ``__wbg_init`` is idempotent — repeat calls
          // throw "already initialized". Swallow that and log
          // everything else.
          const msg = e && e.message ? e.message : String(e);
          if (!/already/i.test(msg)) {
            console.error(`[ext:wasm] init error: ${e?.name || "Error"} ${msg}`);
            throw e;
          }
        }
      }
      console.log(`[ext:wasm] ready in ${Date.now() - t0}ms`);
      return _tnWasmMod;
    })();
  }
  return _initPromise;
}

/** Reset the cached module (test helper only). */
export function _resetForTests() {
  _modPromise = null;
}
