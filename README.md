# tn-proto

**TN — The agent transaction protocol.** Attested logging with broadcast
encryption: every entry is signed, encrypted to a named group of
recipients, and chain-linked. Browsers, services, and CLI tools can
all write to the same log and read each other's entries when they
hold the right kit.

Two ciphers ship in this release:

- **btn** — NNL subset-difference broadcast, Rust core via `tn-core` /
  `tn-btn` pyo3 wheels. O(log n) revocation, ~0.4 ms/op. Default.
- **JWE** — pure Python, X25519 + AES-KW + AES-GCM. No native deps.

## Languages

| Channel       | Package                                                          | Status                                  |
|---------------|------------------------------------------------------------------|-----------------------------------------|
| Python        | `pip install -i https://test.pypi.org/simple/ tn-protocol`       | **0.4.1a2** alpha (TestPyPI)            |
| TypeScript    | `npm install @tnproto/sdk`                                       | **0.4.1-alpha.2** (in tree; npm pending)|
| Rust          | `cargo add tn-core`                                              | in tree, not yet published              |
| Chrome ext    | [`tn-decrypt-0.4.0.zip`](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.4.0) | **0.4.0** (manual install, see below)   |

Both SDKs share the same wire format (the byte-identical wasm-compiled
Rust core); a Python publisher's log decrypts cleanly under a TS reader
and vice versa. See [`docs/sdk-parity.md`](docs/sdk-parity.md) for the
cross-language verb table that CI gates on.

## Quick start (Python)

```bash
# Alpha builds live on TestPyPI; the --extra-index-url lets pip pull
# transitive deps (cryptography, etc.) from real PyPI normally.
pip install -i https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            "tn-protocol>=0.4.1a2,<0.5"
```

```python
import tn

tn.init()                                # mints a fresh ceremony in ./.tn/default/
tn.info("order.created", order_id="A100", amount=4999)

for entry in tn.read():
    print(entry.event_type, entry.fields.get("order_id"))

tn.flush_and_close()
```

`tn.init(link=True)` adds opt-in vault auto-backup: a single-use claim
URL is printed at init time, the user opens it in a browser, and the
keystore is recoverable from a different machine.

## Quick start (TypeScript)

```bash
# Once @tnproto/sdk lands on npm (release-typescript.yml fires on
# the same v-tag push that release-python.yml uses):
npm install @tnproto/sdk
```

```ts
import { Tn } from "@tnproto/sdk";

const tn = await Tn.use("default");
tn.info("order.created", { order_id: "A100", amount: 4999 });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.fields.order_id);
}

await tn.close();
```

## Chrome extension (`tn-decrypt`)

A Manifest V3 extension that decrypts TN envelopes inside any browser
tab. Vendor dashboards (Datadog, Splunk, Kibana, webmail, etc.) keep
storing the ciphertext as opaque text; the extension scans the DOM,
asks its service worker to decrypt each group payload using a kit
you've imported, and rewrites the rendered page in place. Keys never
leave the browser.

It uses the same `tn-wasm` build that the Python SDK and `tn-js` CLI
wrap, plus the audited EMK helpers from `@tnproto/sdk/core` (vendored
into `vendor/sdk-core/` at build time so the unzipped directory is
self-contained — no sibling repo needed).

### Install (manual, until the Chrome Web Store listing is live)

1. **Download** `tn-decrypt-0.4.0.zip` from the
   [latest release](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.4.0).
2. **Unzip** into a directory you'll keep around (Chrome reads the
   directory live, so don't delete it after install).
3. Open **`chrome://extensions`**, toggle **Developer mode** in the
   top-right.
4. Click **Load unpacked** and pick the unzipped directory.
5. Click the extension icon → **Manage keystore** → import a plaintext
   keystore bundle (from tn-proto-org's "Coming from another device?"
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

If you've cloned the repo and want a development build:

```bash
bash tools/build-extension.sh
```

This compiles `ts-sdk/`, copies `dist/core/encoding.js` + `dist/core/emk.js`
into `extensions/tn-decrypt/vendor/sdk-core/`, and verifies the directory
has no out-of-tree imports. Then point Chrome's "Load unpacked" at
`extensions/tn-decrypt/`.

### Scope

- Reads **btn** ciphertexts. JWE groups need the wasm-side JWE
  decrypter (planned).
- Does not send anything over the network. No telemetry.
- Does not write to the page's forms or inputs; purely visual.
- Treats `ciphertext` in JSON contexts as the extraction point —
  exotic encodings (YAML, CSV column bleed) are out of scope.

## Regression suite

`regression/` holds the cross-language crawl-tier suite that gates
every release. Nine silos cover module-level + object-level logging
in both Python and TS, groups + recipients in-process (including the
load-bearing browser shape), CLI verbs, vault auto-backup, restore on
a new machine, and inline decrypt in the Chrome extension. Run locally
with `make -C regression all` or per-silo via `make c1` … `make c9`.

Cross-language tests prove the same envelope decrypts identically
under either runtime: a Python publisher's log opens cleanly under a
TS reader (the "browser audits server logs" shape) and a TS-written
log opens under Python (the "service audits browser actions" shape).

## Layout

```
python/                  # Python SDK (PyPI: tn-protocol)
crypto/
  tn-core/               # Rust core (compiled into the PyPI tn-core wheel + the wasm bundle)
  tn-btn/                # btn cipher Rust crate
  tn-wasm/               # WASM build for browser / Node
  tn-core-py/            # pyo3 bindings (PyPI: tn-core)
  tn-btn-py/             # pyo3 bindings (PyPI: tn-btn)
ts-sdk/                  # @tnproto/sdk + tn-js CLI
                         #   src/core/  — Layer 1 (browser-safe, used by extensions)
                         #   src/       — Layer 2 (Node entry; Tn class + namespaces)
extensions/tn-decrypt/   # Chrome MV3 extension (consumes @tnproto/sdk/core)
regression/              # Cross-language regression suite (crawl tier)
docs/sdk-parity.md       # Cross-language verb parity table (CI gate)
tools/check_parity.py    # CI script that fails on missing parity rows
```

## License

Apache-2.0. See [LICENSE](LICENSE).
