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

Uses the web target of `tn-wasm`, which exposes the shared Rust
cryptographic core also used by the Python SDK and Node CLI. Group
decryption goes through the shared `btn::ReaderKit` implementation.

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
   keystore bundle (from the TN vault's "Coming from another device?"
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

Run these commands in Bash from the repository root:

```bash
cd crypto/tn-wasm
wasm-pack build --target nodejs --release
wasm-pack build --target web --release --out-dir pkg-web
cd ../..
npm --prefix ts-sdk ci
bash tools/build-extension.sh
cp crypto/tn-wasm/pkg-web/tn_wasm.js extensions/tn-decrypt/wasm/tn_wasm.js
cp crypto/tn-wasm/pkg-web/tn_wasm_bg.wasm extensions/tn-decrypt/wasm/tn_wasm_bg.wasm
```

The Node WASM build supplies the TypeScript SDK's local dependency.
`tools/build-extension.sh` compiles the SDK, copies `encoding.js`,
`emk.js`, and `Entry.js` into `vendor/sdk-core/`, and checks the
extension's imports. It does not build or copy WASM; the separate
commands above build the web target and copy its two runtime files
into `wasm/`.

Requirements for these build steps:

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

- Reads BTN group ciphertexts through WASM. Native tn-core supports JWE,
  but the extension does not expose that cipher.
- Does not send anything over the network. No telemetry.
- Does not write to the page's forms or inputs; purely visual.
- Treats `ciphertext` in JSON contexts as the extraction point. More
  exotic encodings (YAML, CSV column bleed) are out of scope.
