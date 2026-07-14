# TN Decrypt (Chrome extension)

Decrypts TN envelopes in the page you're looking at. Your dashboard vendor
(Datadog, Splunk, Kibana, webmail, any random HTML rendering of an
ndjson log) stores the ciphertext as opaque text. When you click the
extension on a page, it scans the DOM, finds the envelopes, asks its
service worker to decrypt each group payload using a kit you've imported,
and rewrites the page in place. Keys stay on this machine; only the active
browser session holds them in memory.

> **Activation model.** As of 0.6.0 the extension uses the `activeTab`
> permission: it does **not** read pages in the background. It only runs
> on the current tab when you click the toolbar icon and choose
> "Decrypt this page" (or right after you unlock a keystore). Nothing is
> scanned until you ask for it.

> **Distribution.** Published on the Chrome Web Store. You can also load
> it unsigned from source via developer mode (`Load unpacked`) for
> development — see below.

## Why this exists

Vendor tools do not have per-field decryption. They ingest bytes and
index what they see. Running a TN reader kit inside the browser makes
the same page legible only for people who hold the kit, and stays
opaque for everyone else looking over the same shoulder.

## How it maps to the Rust core

Uses the exact same `tn-wasm` build (web target) that the Python SDK
and Node CLI wrap. Decryption goes through the shared `btn::ReaderKit`
implementation. There is no JS reimplementation of any crypto primitive.

---

## Install (users)

This is the path for anyone who just wants to try the extension. No
build tooling required.

1. Clone or download this repository:

   ```
   git clone https://github.com/cyaxios/tn-proto
   ```

   (Or download a release archive from the GitHub releases page if you
   prefer not to clone.)

2. In Chrome, open `chrome://extensions`, turn on **Developer mode**
   (top-right toggle), click **Load unpacked**, and select the
   `extensions/tn-decrypt/` directory from your clone.

3. Click the extension icon → **Manage keystore** → import a plaintext
   keystore bundle (from tnproto-org's "Coming from another device?"
   step, or any `*.keystore.json` file you produced with `tn-js` or
   the Python SDK). Pick a passphrase for this extension's stored copy.

4. Click the extension icon again → **Unlock** with that passphrase.

5. Open any page that displays a TN envelope, click the extension icon,
   and choose **Decrypt this page**. Entries with ciphertexts the
   imported kit can open are highlighted with a green `TN` badge and the
   decrypted fields are shown inline. Entries from other publishers you
   don't hold kits for are left alone. (The extension only reads a page
   after you click — it has no background access to your tabs.)

The repo ships the prebuilt `vendor/sdk-core/` JS and the prebuilt
`wasm/tn_wasm*` artifacts directly so step 1 is all you need. If you
ever see a console error about a missing vendor file, run the build
step from the next section.

---

## Build (contributors)

You only need this section if you're modifying the SDK / wasm / extension
code itself. Users following the install section above can skip it.

The build script does both pieces in one shot:

```
bash tools/build-extension.sh
```

This compiles `ts-sdk/`, copies `dist/core/encoding.js` +
`dist/core/emk.js` into `extensions/tn-decrypt/vendor/sdk-core/`,
builds `crypto/tn-wasm` for the web target with `wasm-pack`, and
copies `tn_wasm.js` + `tn_wasm_bg.wasm` into
`extensions/tn-decrypt/wasm/`. After it runs, this directory has no
out-of-tree imports — it's complete on its own and ready to load
unpacked.

Requirements for the build script:

- Node 20+ and `npm` for the TS compile step
- Rust toolchain + `wasm-pack` (`cargo install wasm-pack`) for the
  WASM step

Reload the extension on `chrome://extensions` after rebuilding to pick
up changes.

---

## Test page

A minimal fixture lives at `test-page.html` in this directory. Serve
it locally (`python -m http.server 8080`) or open it as `file://`; it
embeds one envelope the way Datadog would show a log line. With the
extension unlocked, the group payload will flip from a base64 blob to
the decrypted fields.

## Scope

- This extension imports BTN reader kits. Standard JWE is available through
  tn-core, tn-wasm, and the SDK runtime surfaces; reader-local X25519 keys are
  outside this extension's key-import contract.
- Does not send anything over the network. No telemetry.
- Does not write to the page's forms or inputs; purely visual.
- Treats `ciphertext` in JSON contexts as the extraction point. More
  exotic encodings (YAML, CSV column bleed) are out of scope.
