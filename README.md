# tn-proto

TestigoNodo (TN) — attested logging protocol with broadcast encryption.

A small protocol for emitting log entries that are signed, encrypted to a
named group of recipients, and chain-linked. Two ciphers ship in this
release:

- **JWE** — pure Python, X25519 + AES-KW + AES-GCM. No native deps.
- **btn** — NNL subset-difference broadcast, Rust core via `tn-core` /
  `tn-btn` pyo3 wheels. O(log n) revocation, ~0.4 ms/op.

## Languages

| Channel       | Package                                                 | Status                          |
|---------------|---------------------------------------------------------|---------------------------------|
| Python        | `pip install -i https://test.pypi.org/simple/ tn-protocol` | 0.3.0a1 alpha (TestPyPI)        |
| TypeScript    | `npm install @tnproto/sdk`                              | 0.3.0-alpha.1 (in tree, not yet on npm) |
| Rust          | `cargo add tn-core`                                     | in tree, not yet published      |
| Chrome ext    | [`tn-decrypt-0.3.0.zip`](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.3.0) | 0.3.0 (manual install, see below) |

The TypeScript SDK split off from a pre-Phase-2 `TNClient` god-class
into a `Tn` class with namespaced sub-objects (`tn.admin/pkg/vault/agents/handlers`),
a browser-safe Layer 1 entry at `@tnproto/sdk/core` that the Chrome
extension consumes for audited crypto + EMK + zip primitives, and a
new `tn.watch()` async-iterable verb (mirrored on Python). See
[`docs/sdk-parity.md`](docs/sdk-parity.md) for the cross-language verb table.

## Quick start (Python)

```bash
# Alpha builds live on TestPyPI; the --extra-index-url lets pip pull
# transitive deps (cryptography, etc.) from real PyPI normally.
pip install -i https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            tn-protocol==0.3.0a1
```

```python
import tn

tn.init("./tn.yaml")          # mints a fresh ceremony if none exists
tn.info("order.created", order_id="A100", amount=4999)

for entry in tn.read():
    print(entry["event_type"], entry.get("order_id"))

tn.flush_and_close()
```

## Chrome extension (`tn-decrypt`)

A Manifest V3 extension that decrypts TN envelopes inside any browser tab.
Vendor dashboards (Datadog, Splunk, Kibana, webmail, etc.) keep storing
the ciphertext as opaque text; the extension scans the DOM, asks its
service worker to decrypt each group payload using a kit you've imported,
and rewrites the rendered page in place. Keys never leave the browser.

It uses the same `tn-wasm` build that the Python SDK and `tn-js` CLI
wrap, plus the audited EMK helpers from `@tnproto/sdk/core` (vendored
into `vendor/sdk-core/` at build time so the unzipped directory is
self-contained — no sibling repo needed).

### Install (manual, until the Chrome Web Store listing is live)

1. **Download** `tn-decrypt-0.3.0.zip` from the
   [latest release](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.3.0).
2. **Unzip** into a directory you'll keep around (Chrome reads the
   directory live, so don't delete it after install).
3. Open **`chrome://extensions`**, toggle **Developer mode** in the
   top-right.
4. Click **Load unpacked** and pick the unzipped directory.
5. Click the extension icon → **Manage keystore** → import a plaintext
   keystore bundle (from tnproto-org's "Coming from another device?"
   step, or any `*.keystore.json` you produced with `tn-js` or the
   Python SDK). Pick a passphrase for the extension's local copy.
6. Click the icon again → **Unlock** with that passphrase.
7. Open any page that displays a TN envelope. Entries the imported kit
   can open get a green `TN` badge with the decrypted fields inline;
   entries from publishers you don't hold kits for are left alone.

A minimal fixture lives at `test-page.html` inside the extension; serve
it locally (`python -m http.server 8080`) or open as `file://` to verify
decryption end-to-end.

### Building from source

If you've cloned the repo and want a development build (e.g. to hack on
`unlock.js` or test SDK changes before they ship):

```bash
bash tools/build-extension.sh
```

This compiles `ts-sdk/`, copies `dist/core/encoding.js` + `dist/core/emk.js`
into `extensions/tn-decrypt/vendor/sdk-core/`, and verifies the directory
has no out-of-tree imports. Then point Chrome's "Load unpacked" at
`extensions/tn-decrypt/`.

### Scope

- Reads **btn** ciphertexts. JWE groups need the wasm-side JWE decrypter
  (planned).
- Does not send anything over the network. No telemetry.
- Does not write to the page's forms or inputs; purely visual.
- Treats `ciphertext` in JSON contexts as the extraction point — exotic
  encodings (YAML, CSV column bleed) are out of scope.

## Layout

```
python/                  # Python SDK (PyPI: tn-protocol)
crypto/
  tn-core/               # Rust core (crates.io: tn-core, planned)
  tn-btn/                # btn cipher Rust crate
  tn-wasm/               # WASM build for browser / Node
  tn-core-py/            # pyo3 bindings  (PyPI: tn-core)
  tn-btn-py/             # pyo3 bindings  (PyPI: tn-btn)
ts-sdk/                  # @tnproto/sdk + tn-js CLI
                         #   src/core/  — Layer 1 (browser-safe, used by extensions)
                         #   src/       — Layer 2 (Node entry; Tn class + namespaces)
extensions/tn-decrypt/   # Chrome MV3 extension (consumes @tnproto/sdk/core)
docs/sdk-parity.md       # Cross-language verb parity table (CI gate)
tools/check_parity.py    # CI script that fails on missing parity rows
```

## License

Apache-2.0. See [LICENSE](LICENSE).
