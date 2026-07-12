# TN Decrypt — Chrome Web Store submission kit

Everything needed to fill out the Web Store developer dashboard, plus the
final packaging and smoke-test steps. Visibility target: **Public**.

## Developer account (one-time, you do this)

1. Go to https://chrome.google.com/webstore/devconsole and sign in with the
   Google account that should own the listing.
2. Pay the one-time USD 5 registration fee and accept the developer
   agreement.
3. Verify a contact email and (for a public listing) complete the
   one-time identity / payment-method verification Google asks for.

## Listing fields

**Name:** TN Decrypt

**Summary (132 chars max):**
> Reveal TN-encrypted content on the page you're viewing, using keys stored
> only in your browser. Click to decrypt. Keys never leave your device.

**Category:** Developer Tools

**Language:** English

**Detailed description:**
> TN Decrypt reveals TN protocol ciphertexts that appear as opaque text in
> dashboards and web tools (observability consoles, log viewers, webmail,
> any page that renders TN envelopes).
>
> How it works: you import a reader kit (from a file, or by pairing your
> tn-proto.org vault). When you open a page and click "Decrypt this page",
> the extension finds TN ciphertexts on that tab and rewrites the ones your
> kit can open, in place. Content you do not hold a kit for stays opaque.
>
> Privacy by design:
> - Keys are stored only in your browser and used only on your device.
> - The extension reads a page only when you click it (activeTab). It has
>   no background access to your tabs and no broad host permissions.
> - No analytics, no telemetry, no network requests beyond the vault
>   pairing you explicitly start.
>
> TN Decrypt does the decryption with the same cryptographic core
> (compiled to WebAssembly) used by the TN SDKs. There is no JavaScript
> reimplementation of any crypto primitive.

**Privacy policy URL:** host `store/PRIVACY.md` and put the URL here.
Suggested: https://tn-proto.org/extension-privacy (or a GitHub raw/Pages URL).

**Homepage / support URL:** https://tn-proto.org  ·  support: gil@cyaxios.com

## Single purpose (required statement)

> The single purpose of TN Decrypt is to decrypt TN protocol ciphertexts
> displayed on the web page the user is viewing, using reader keys the user
> holds locally, and to show the decrypted content in place on that page.

## Permission justifications (paste into the dashboard)

- **activeTab** — "Used to read and rewrite the content of the current tab,
  only after the user clicks the extension, so it can locate TN ciphertexts
  on that page and display their decrypted values in place."
- **scripting** — "Used to inject the in-page decrypt-and-render script into
  the current tab when the user clicks 'Decrypt this page'. Injection is
  on-demand and user-initiated."
- **storage** — "Used to store the user's imported reader keys (keystores)
  locally in the browser so they persist between sessions. No data is sent
  off-device."
- **Remote code:** None. All scripts and the WebAssembly module are packaged
  in the extension. CSP is `script-src 'self' 'wasm-unsafe-eval'`.
- **externally_connectable (`https://vault.tn-proto.org`)** — "Lets the
  user's own tn-proto.org vault deliver reader kits the user explicitly
  pairs. The receiving handler validates the origin and the payload shape."

## Data-use disclosures (Privacy practices tab)

- Does this item collect or use user data? Answer the questionnaire as:
  - The extension handles **website content** locally to decrypt it, but
    does **not** collect or transmit it.
  - It stores **user-provided keys** locally; these are not transmitted.
  - It does **not** collect: personally identifiable info, health, financial,
    authentication, personal communications, location, web history, or user
    activity for any off-device purpose.
- Certify all three compliance checkboxes:
  - Not selling/transferring data to third parties (true).
  - Not using/transferring data for purposes unrelated to the single purpose
    (true).
  - Not using/transferring data to determine creditworthiness / lending
    (true).

## Required image assets

- **Store icon:** `icons/icon128.png` (128x128). A 512 master is at
  `icons/icon512.png` if the dashboard wants a larger app tile.
- **Screenshots:** at least one, 1280x800 or 640x400 PNG/JPEG. Capture the
  extension decrypting `test-page.html` (open it, click "Decrypt this page",
  screenshot the green TN pills) and the popup. These must be produced from
  a real Chrome session.
- **Small promo tile (optional):** 440x280.

## Package + smoke test (before upload)

Run from `extensions/tn-decrypt/`:

```
npm test                     # 4 suites, must be all-green
pwsh tools/package.ps1       # writes extensions/tn-decrypt-<version>.zip (store payload only)
```

The zip contains only the runtime payload (manifest at root, scripts, icons
16/48/etc., vendor/, wasm/). Verified excluded: test/, tools/, store/,
package.json, README.md, test-page.html, icon512.png.

Then load-unpacked and smoke test in real Chrome (the Node tests cannot
exercise the manifest/injection wiring):

1. `chrome://extensions` -> Developer mode -> Load unpacked -> select this dir.
2. Confirm the icon renders and there are no manifest errors.
3. Options -> import a kit (or use the vault pair flow).
4. Open `test-page.html`, click the icon -> "Decrypt this page". Confirm the
   ciphertext flips to a green TN pill and back via the badge.
5. Confirm it does NOT auto-run on a fresh page until you click.
6. Check the service-worker console for errors (especially the wasm load
   line `[ext:wasm] ready`). If wasm fails to load, re-add a
   `web_accessible_resources` entry for `wasm/*` (it should not be needed
   because the service worker loads it from the extension origin).

When the smoke test passes, upload the zip in the dashboard, paste the
fields above, submit for review.
