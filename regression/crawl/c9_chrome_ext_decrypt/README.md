# C9 — Chrome extension inline decryption

## What this silo proves

The Chrome extension at `extensions/tn-decrypt/` ships its OWN copy of
the wasm bundle (`extensions/tn-decrypt/wasm/tn_wasm.{js,bg.wasm}`).
That copy must decrypt TN-encrypted entries identical-byte to what
Python's `tn_btn` produces — if they drift, every browser user gets a
silent decrypt failure while Python users see plaintext.

The load-bearing crypto guarantee:

1. Python `tn_btn.PublisherState` mints a kit + ciphertext.
2. Load the **extension's** wasm bundle (not the SDK's `pkg-web/`).
3. Call `btnDecrypt(kit, ciphertext)` via the extension's exported
   wasm-bindgen function.
4. The plaintext byte-for-byte equals what Python wrote.

This catches "the extension was rebuilt against a stale wasm" and
"the extension was bumped without re-bundling the wasm" before either
ships to a real user.

## Why it's load-bearing

The DOM-rewrite layer (content script scans page, calls service
worker, replaces text) is mechanical — its bug is "decrypt isn't
being called" or "result isn't being injected." The CRYPTO layer is
where silent breakage lives. If the extension's wasm bundle can
decrypt, the rest is a wiring problem the smoke test surfaces; if it
can't, nothing else matters.

## Tests in this silo

- `test_ext_wasm_decrypts_python.test.ts` — load the extension's
  wasm bundle in Node, mint Python fixture, decrypt, assert byte
  identical. Same shape as `extensions/tn-decrypt/test/python_interop.mjs`
  but with named regression assertions.
- `test_ext_dom_rewrite.test.ts` — placeholder for the full
  Playwright DOM-rewrite test. **Skipped** with a documented reason
  — that's walk-tier. The crypto-level proof above gates the
  load-bearing guarantee for now.

## Code paths exercised

- `extensions/tn-decrypt/wasm/tn_wasm.js` — wasm-bindgen loader
- `extensions/tn-decrypt/wasm/tn_wasm_bg.wasm` — Rust-compiled wasm
- `extensions/tn-decrypt/wasm/btnDecrypt` (export) — the SW's
  decrypt path
- `crypto/tn-btn/src/lib.rs` — BTN cipher (Python parity)

## How to run only this silo

```bash
make c9
# or
node --import tsx --test regression/crawl/c9_chrome_ext_decrypt/*.test.ts
```

Requirements:
- Python `tn_btn` installed (the regression venv has it).
- The extension's wasm bundle is on disk
  (`extensions/tn-decrypt/wasm/*`). It's checked in.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `btnDecrypt is not a function` | extension's wasm bundle out of sync; re-vendor from `crypto/tn-wasm/pkg-web/` |
| publisher_id mismatch (kit vs ciphertext) | BTN serialization drifted between Python and the bundled wasm; check `crypto/tn-btn/src/lib.rs` versioning |
| Decrypt succeeds but plaintext is gibberish | wire format drift — check `tn_btn.PublisherState.encrypt` Python vs wasm `btnDecrypt` |
| Python tn_btn not importable | regression venv missing the wheel; `pip install tn-btn>=0.2.0a1` |
