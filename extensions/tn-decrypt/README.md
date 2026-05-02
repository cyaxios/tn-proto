# TN Decrypt (Chrome extension)

Decrypts TN envelopes in the page you're looking at. Your dashboard vendor
(Datadog, Splunk, Kibana, webmail, any random HTML rendering of an ndjson
log) stores the ciphertext as opaque text. This extension scans the DOM,
finds the envelopes, asks its service worker to decrypt each group payload
using a kit you've imported, and rewrites the page in place. Keys stay on
this machine; only the active browser session holds them in memory.

## Why this exists

Vendor tools do not have per-field decryption. They ingest bytes and index
what they see. Running a TN reader kit inside the browser makes the same
page legible only for people who hold the kit, and stays opaque for
everyone else looking over the same shoulder.

## How it maps to the Rust core

Uses the exact same `tn-wasm` build (web target) that the Python SDK and
Node CLI wrap. Decryption goes through the shared `btn::ReaderKit`
implementation. There is no JS reimplementation of any crypto primitive.

## Install for development

1. Build the SDK and vendor it into the extension. From the repo root:

   ```
   bash tools/build-extension.sh
   ```

   That compiles `ts-sdk/` and copies `dist/core/encoding.js` +
   `dist/core/emk.js` into `extensions/tn-decrypt/vendor/sdk-core/`. After
   it runs, this directory has no out-of-tree imports — it's complete on
   its own.

2. (Only if `wasm/tn_wasm.js` and `wasm/tn_wasm_bg.wasm` are missing or
   stale.) Build `tn-wasm` for the web target:

   ```
   cd crypto/tn-wasm
   wasm-pack build --target web --release --out-dir pkg-web
   cp pkg-web/tn_wasm.js     ../../extensions/tn-decrypt/wasm/
   cp pkg-web/tn_wasm_bg.wasm ../../extensions/tn-decrypt/wasm/
   ```

3. In Chrome: `chrome://extensions`, turn on **Developer mode**, click
   **Load unpacked**, pick this directory.

4. Click the extension icon, go to **Manage keystore**, import a plaintext
   keystore bundle (from tnproto-org's "Coming from another device?" step
   or any `*.keystore.json` file you produced with `tn-js` or the Python
   SDK). Pick a passphrase for this extension's stored copy.

5. Click the extension icon again and **Unlock** with that passphrase.

6. Open any page that displays a TN envelope. Entries with ciphertexts
   the imported kit can open are highlighted with a green `TN` badge and
   the decrypted fields are shown inline. Entries from other publishers
   you don't hold kits for are left alone.

## Test page

A minimal fixture lives at `test-page.html` in this directory. Serve it
locally (`python -m http.server 8080`) or open it as `file://`; it embeds
one decrypted envelope in a `<pre>` block the way Datadog would show a
log line. With the extension unlocked, the group payload will flip from
a base64 blob to the decrypted fields.

## Scope

- Reads btn ciphertexts. JWE groups would need Rust JWE first (see the
  TN TS-client handoff doc).
- Does not send anything over the network. No telemetry.
- Does not write to the page's forms or inputs; purely visual.
- Treats `ciphertext` in JSON contexts as the extraction point. More
  exotic encodings (YAML, CSV column bleed) are out of scope.
