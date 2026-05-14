# C9 — Chrome extension inline decryption

**Status: scaffolded, no tests yet. Implemented in the C9 PR.**

## What this silo proves

The Chrome extension at `extensions/tn-decrypt/` decrypts TN-encrypted
entries in-place while the user views a vendor dashboard (Datadog,
Splunk, Kibana, …):

1. Load extension into a fresh Chromium via Playwright.
2. Import a plaintext keystore fixture into the extension.
3. Lock the extension with a passphrase.
4. Navigate to a fixture page that contains TN-encrypted ciphertext
   in DOM JSON blobs.
5. The extension's content script scans the DOM, decrypts inline,
   rewrites the page.
6. Assert the plaintext renders correctly + the passphrase actually
   gates access (locked extension does not decrypt).

## Why it's load-bearing

The extension is a meaningful piece of the user-facing product — it's
how developers actually consume encrypted logs in tools they already
use. If the extension breaks, "encrypted logs in vendor tools" stops
working in production.

It's also the most-external dependency (Chrome + Playwright + the
extension's manifest v3 service worker) so it's the most likely to
silently break on upstream tooling changes.

## Code paths exercised

- `extensions/tn-decrypt/manifest.json` — extension manifest
- `extensions/tn-decrypt/src/content_script.ts` — DOM scanner + rewriter
- `extensions/tn-decrypt/src/service_worker.ts` — decrypt orchestration
- `extensions/tn-decrypt/src/wasm_loader.ts` — wasm init in extension context
- `crypto/tn-wasm/pkg-web/` — browser-targeted wasm consumed by ext

## Tests to add (in the C9 PR)

- `test_extension_loads.py` — Chromium starts, extension manifest accepted, no console errors
- `test_import_keystore.py` — extension UI accepts a plaintext keystore + locks with passphrase
- `test_inline_decrypt.py` — fixture page with encrypted JSON → plaintext rendered after scan
- `test_locked_extension_no_decrypt.py` — locked state → ciphertext stays ciphertext
- `test_wasm_init.py` — extension service worker initializes the wasm bundle without error

## How to run only this silo

```bash
make -C regression c9
```

This silo needs:
- Playwright with Chromium installed (`playwright install chromium`)
- The extension built (`cd extensions/tn-decrypt && npm run build`)
- A pre-generated keystore fixture + a pre-generated fixture page
  containing encrypted blobs (silo-local fixtures)

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| Chromium fails to start with extension | `manifest.json` — check manifest-v3 service-worker entry |
| Extension UI shows blank panel | `src/popup/*.ts` build output; check `npm run build` succeeded |
| Inline decrypt produces empty strings | `content_script.ts` DOM-scanner pattern + service-worker message routing |
| Wasm load fails in service worker | `wasm_loader.ts` — fetch path for `tn_wasm_bg.wasm`; manifest-v3 wasm CSP |
| Locked extension still decrypts | `service_worker.ts` — passphrase gate enforcement order |
