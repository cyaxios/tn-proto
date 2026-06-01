# tn-proto

TN is an append-only log where every entry is signed, encrypted to a
named group of recipients, and chain-linked. The Python and
TypeScript SDKs share one wire format, so a log a Python service
writes can be read in a browser, and the other way around.

There are two ciphers. `btn` is the default, built on a Rust core
that supports thousands of readers with selective revocation in
sub-millisecond time. `jwe` is the pure-Python option for small
fixed reader sets.

| | Install | Latest |
|---|---|---|
| Python | `pip install -i https://test.pypi.org/simple/ tn-protocol` | 0.4.2a1 |
| TypeScript | `npm install @tnproto/sdk` | 0.4.2-alpha.1 (in tree; npm pending) |
| Chrome extension | [`tn-decrypt-0.4.0.zip`](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.4.0) | 0.4.0 (manual install) |

## Hello, log

Write one event and read it back. `tn.init()` creates a fresh
ceremony at `./.tn/default/` the first time it runs, then attaches
to it on every subsequent call.

```python
import tn

tn.init()
tn.info("app.hello", a=1, b="two")

for entry in tn.read():
    print(entry.event_type, entry.fields)
```

The TypeScript shape is the same.

```ts
import * as tn from "@tnproto/sdk";

await tn.init();
tn.info("app.hello", { a: 1, b: "two" });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.fields);
}
```

## Two streams in one process

Named ceremonies are isolated. Each handle has its own keys, its own
log, and its own reader list. `tn.use(name)` returns the handle.

```python
import tn

payments = tn.use("payments")
billing  = tn.use("billing")

payments.info("charge", amount=1000, currency="USD")
billing.info("invoice", invoice_id="INV-42")
```

A read on `payments` returns only the payments events. Cross-stream
mixing is impossible by construction.

## Share your log with someone

The publisher mints a reader kit for a recipient's DID and hands the
recipient the resulting `.tnpkg` file. After the recipient absorbs
that file, they can decode the publisher's entries with their own
keystore.

The snippet below simulates both sides in one process. In real use,
the publisher and recipient live on separate machines and the
`.tnpkg` travels over whatever channel you prefer.

```python
import tn

# Publisher side: hand Frank a kit.
tn.init()
publisher_log = tn.current_config().resolve_log_path()

tn.pkg.bundle_for_recipient(
    recipient_did="did:key:zFrank...",
    out_path="./frank.tnpkg",
)

tn.info("sale.line", item="bread", quantity=1, unit_price="3.25")
tn.flush_and_close()

# Recipient side: absorb the kit, read the publisher's log.
tn.init()
tn.pkg.absorb("./frank.tnpkg")

for entry in tn.read(
    log=publisher_log,
    as_recipient=tn.current_config().keystore,
    group="default",
):
    print(entry.event_type, dict(entry.fields))
```

The recipient's read prints the publisher's `sale.line` event in
cleartext. Python publisher to TypeScript reader works the same way,
as does TypeScript publisher to Python reader.

## Vault backup at `init`

Pass `link=True` and TN uploads an encrypted snapshot of your
keystore to the configured vault, writes a claim URL to a local
file, and keeps a pending-claim record. The decryption key travels
in the URL fragment, so the vault server never sees it. Opening the
claim URL in a browser binds the keystore to your account.

```python
import tn
from pathlib import Path
from tn.sync_state import get_pending_claim

tn.init(link=True)
cfg = tn.current_config()
claim_url = (Path(cfg.yaml_path).parent / ".tn" / "sync" / "claim_url.txt").read_text().strip()
print(claim_url)

pc = get_pending_claim(cfg.yaml_path)
print(pc["vault_id"], pc["expires_at"])
```

If the vault is unreachable, init falls through and the ceremony
keeps working locally. Re-running `init(link=True)` inside the claim
TTL reuses the same vault id, so it stays idempotent.

## Restore on a new machine

The reverse of backup. The browser claims the URL, the vault returns
the backup ciphertext under a short-lived JWT, and a helper decrypts
it with the key from the URL fragment and lays out `tn.yaml` plus
the keystore directory. `tn.init(yaml)` then binds the runtime to
the recovered ceremony.

```python
import tn
from regression._shared.vault_test_helpers import (
    dev_auth_login,
    fetch_pending_claim,
    parse_claim_url,
    restore_keystore_to,
)

vault_id, bek = parse_claim_url(claim_url)
login = dev_auth_login(VAULT_URL, handle="alice")
ciphertext = fetch_pending_claim(VAULT_URL, vault_id, login["token"])

yaml_b = restore_keystore_to(machine_b_tmpdir, ciphertext, bek)
tn.init(yaml_b)
```

The ceremony DID on machine B matches the original on machine A.
The chain continues forward as if you had never moved machines.

## Revoke and rotate

Forward-only access revocation. Mint a kit for Carol, write some
events while she has access, then revoke her and rotate the group
key. Events she could already read stay readable. Anything written
after the rotation is opaque to her.

```python
import tn

tn.init()

# Carol joins. Keep the returned add-result around so you can
# refer to her by name later.
carol = tn.admin.add_recipient(
    "default",
    recipient_did="did:key:zCarol...",
    out_path="./carol.btn.mykit",
)

tn.info("invoice.created", id="INV-1")

# Carol leaves.
tn.admin.revoke_recipient("default", leaf_index=carol.leaf_index)
tn.admin.rotate("default")

tn.info("invoice.created", id="INV-2")
```

Carol's existing kit still decodes `INV-1`. The new `INV-2` entry is
opaque to her; only readers who get a fresh kit after the rotation
can decode it.

## CLI

The CLI mirrors the Python verbs. Useful when you want to onboard a
reader from the shell or roll keys as part of a deploy.

```bash
tn init myproject --no-link --skip-confirm
tn add_recipient default did:key:zFrank... --yaml myproject/tn.yaml
tn rotate default --yaml myproject/tn.yaml
tn read --yaml myproject/tn.yaml
```

Both `tn add_recipient` and `tn bundle` accept `--seal-for-recipient`,
which wraps the kit body under the recipient's public key. Useful
when a CDN or vault is going to relay the file and you want the
relay to stay opaque to the body.

## Chrome extension

`tn-decrypt` is a Manifest V3 extension that finds TN ciphertext in
the DOM (Datadog, Splunk, Kibana, webmail) and rewrites it inline.
Decryption happens entirely in the browser, using the same Rust core
the SDKs wrap, compiled to wasm.

To install the prebuilt extension:

1. Download `tn-decrypt-0.4.0.zip` from the
   [latest release](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.4.0).
2. Unzip into a directory Chrome can keep reading.
3. Visit `chrome://extensions`, enable Developer mode, click
   "Load unpacked", and pick the directory.
4. Open the extension popup, import a `*.keystore.json`, and pick a
   local passphrase.
5. Unlock with that passphrase.

Open any page that contains a TN envelope. Entries your kit can open
get a green `TN` badge with the decrypted fields shown inline.

To build from source:

```bash
bash tools/build-extension.sh
```

Then point Chrome's "Load unpacked" at `extensions/tn-decrypt/`.

## Regression suite

The `regression/` tree pins every pattern above to a passing test.
Run the whole suite with `make -C regression all`, or pick a single
silo with `make c1` through `make c9`. Cross-language tests prove
the same envelope decrypts identically under Python and TypeScript.

The cross-language parity table lives at
[`docs/sdk-parity.md`](docs/sdk-parity.md) and is enforced by CI.

## Development: rebuilding the Rust core

`btn` (and templated `logs.path` rendering + file writing) lives in the
shared Rust core at `crypto/tn-core`. Both SDKs delegate to it — Python
through the `tn_core` PyO3 wheel, TypeScript through `tn-wasm` — so a
core edit is **invisible** until you rebuild the downstream artifact and
reinstall it into the active interpreter.

`maturin develop` is unreliable here: it reports success but leaves the
already-loaded `site-packages/tn_core/_core.pyd` in place, so tests keep
running the old binary. Build a wheel and force-reinstall it instead:

```bash
cd crypto/tn-core-py
python -m maturin build --out ../../dist          # debug build is fine for iteration
WHEEL=$(ls -t ../../dist/tn_core-*.whl | head -1)
python -m pip install --force-reinstall --no-deps "$WHEEL"
```

Confirm the core actually recompiled by looking for `Compiling tn-core`
in the maturin output (if it's absent, only the binding rebuilt), and
sanity-check the install by comparing the `mtime` of
`site-packages/tn_core/_core.pyd` against your edit.

The TypeScript/wasm side is the analogous rebuild. The node target is a
symlinked dep, so no reinstall is needed; the browser target is separate
and easy to forget — rebuild both:

```bash
cd crypto/tn-wasm
wasm-pack build --target nodejs --release             # consumed by ts-sdk + its tests
wasm-pack build --target web --release --out-dir pkg-web   # browser bundle
```

**Windows pip-lock gotcha** (pip 26.x): if any Python process still has
`_core.pyd` mmapped — a hung `pytest` is the usual culprit —
`--force-reinstall` prints "Installed 1 package" but does **not**
overwrite the locked file. It renames it to `~~_core` and silently
leaves `tn_core/` empty. Recover by:

1. Killing the stale Python processes and deleting any leftover
   `~-_core` / `~~_core` / `~n_core` directories in
   `…/Python3xx/Lib/site-packages/`.
2. Extracting the wheel by hand (it's a zip) over the package:

```powershell
Expand-Archive $WHEEL $tmp -Force
Copy-Item $tmp/tn_core <site-packages>/tn_core -Recurse -Force
Copy-Item $tmp/tn_core-*.dist-info <site-packages>/ -Recurse -Force
```

## Releasing to TestPyPI

Releases are automated by
[`.github/workflows/release-python.yml`](.github/workflows/release-python.yml).
It builds all three Python packages — `tn-btn`, `tn-core` (Rust wheels
via maturin, across Linux/macOS/Windows), and `tn-protocol` (pure-Python
wheel + sdist) — collects every artifact, and uploads them with
`pypa/gh-action-pypi-publish` (`skip-existing: true`, so re-runs are
idempotent). TestPyPI is the default target; real PyPI is opt-in.

The canonical, full release flow:

```bash
# 1. Bump the version in python/pyproject.toml (PEP 440, e.g. 0.5.0a5).
#    Keep the three packages aligned per docs/sdk-parity.md.

# 2. Commit, then tag with a leading v and push the tag — this is what
#    triggers the publish workflow.
git tag -a v0.5.0a5 -m "0.5.0a5: <summary>"
git push origin <branch>
git push origin v0.5.0a5

# 3. Watch the run; alpha/beta/rc tags auto-flag as a prerelease and a
#    GitHub Release is created from the tag's annotation.
gh run watch --repo cyaxios/tn-proto
```

To dry-run (or publish) **without** cutting a tag, use the manual
dispatch and pick the target (`testpypi` | `pypi` | `none`):

```bash
gh workflow run release-python.yml --repo cyaxios/tn-proto -f target=testpypi
```

Required repo secrets: `TESTPYPI_API_TOKEN` (and `PYPI_API_TOKEN` only
when promoting to real PyPI). Tokens are generated at
<https://test.pypi.org/manage/account/token/>.

Install a published TestPyPI build. TestPyPI doesn't host the regular
dependencies, so point `--extra-index-url` at real PyPI for those:

```bash
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  tn-protocol
```

## Layout

```
python/                  Python SDK (PyPI: tn-protocol)
crypto/                  Rust core, btn cipher, wasm build, pyo3 bindings
ts-sdk/                  @tnproto/sdk + tn-js CLI
extensions/tn-decrypt/   Chrome MV3 extension
regression/              Cross-language regression suite
docs/sdk-parity.md       Verb parity table (CI gate)
tools/check_parity.py    CI script that fails on missing parity rows
```

## License

Apache-2.0. See [LICENSE](LICENSE).
