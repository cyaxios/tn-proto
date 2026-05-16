# tn-proto

**TN — The agent transaction protocol.** Attested logging with broadcast
encryption. Every entry is signed, encrypted to a named group of
recipients, and chain-linked. Browsers, services, and CLI tools share
one log; whoever holds the right kit can read.

Two ciphers:

- **btn** (default) — NNL subset-difference broadcast, Rust core via
  `tn-core` / `tn-btn` pyo3 wheels. O(log n) revocation, ~0.4 ms/op.
- **JWE** — pure Python, X25519 + AES-KW + AES-GCM. No native deps.

| | Package | Current |
|---|---|---|
| Python | `pip install -i https://test.pypi.org/simple/ tn-protocol` | **0.4.1a2** (TestPyPI) |
| TypeScript | `npm install @tnproto/sdk` | **0.4.1-alpha.2** (in tree; npm pending) |
| Chrome ext | [`tn-decrypt-0.4.0.zip`](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.4.0) | **0.4.0** (manual install) |

Both SDKs share the same wire format (byte-identical wasm-compiled Rust
core); a Python publisher's log decrypts cleanly under a TS reader and
vice versa. See [`docs/sdk-parity.md`](docs/sdk-parity.md) for the
cross-language verb table that CI gates on.

---

# Coding guide

Examples are lifted directly from the regression suite under
`regression/crawl/`. Each pattern is gated by a passing test — if
the snippet here drifts from the test, CI fails. **Run the test for
the canonical input/output.**

## 1. Write a log and read it back (simplest case)

`tn.init()` with no args mints `./.tn/default/` if the discovery chain
finds nothing. After that, the bare verbs work.

```python
import tn

tn.init()                                  # discovers or mints ./.tn/default/
tn.info("app.hello", a=1, b="two")

for entry in tn.read():
    print(entry.event_type, entry.fields)
# → app.hello {'a': 1, 'b': 'two'}

tn.flush_and_close()
```

Test: [`c1_python_module_log/test_default_handlers.py`](regression/crawl/c1_python_module_log/test_default_handlers.py).

```ts
import * as tn from "@tnproto/sdk";

await tn.init();
tn.info("app.hello", { a: 1, b: "two" });

for (const entry of tn.read()) {
  console.log(entry.event_type, entry.fields);
}

await tn.close();
```

Test: [`c3_ts_module_log/default_handlers.test.ts`](regression/crawl/c3_ts_module_log/default_handlers.test.ts).

## 2. Multiple ceremonies in one process

Use `tn.use(name)` (or `Tn.use(name)` in TS) for named streams. Each
handle owns its own runtime — `payments.info(...)` and
`billing.info(...)` never cross.

```python
import tn

payments = tn.use("payments")
billing  = tn.use("billing")

payments.info("charge", amount=1000, currency="USD")
billing.info("invoice", invoice_id="INV-42")

assert "invoice" not in [e.event_type for e in payments.read()]
assert "charge" not in [e.event_type for e in billing.read()]
```

Test: [`c2_python_object_log/test_multi_ceremony_isolation.py`](regression/crawl/c2_python_object_log/test_multi_ceremony_isolation.py).

## 3. Group + recipient round-trip (the browser shape)

Alice publishes encrypted-to-group entries; Frank holds a recipient
kit and decrypts them. Both sides run in the same process here for
documentation, but the wire is the same as cross-machine.

```python
import tn
from pathlib import Path

# ── Alice (publisher) ─────────────────────────────────────────────
tn.init()
alice_cfg = tn.current_config()
alice_log = alice_cfg.resolve_log_path()

bundle_dir = Path("./alice_workspace")
bundle_dir.mkdir(exist_ok=True)
kit_path = bundle_dir / "default.btn.mykit"

tn.admin.add_recipient(
    "default",
    recipient_did="did:key:zFrank...",
    out_path=kit_path,
)
tn.pkg.export(
    bundle_dir / "frank.tnpkg",
    kind="kit_bundle",
    cfg=alice_cfg,
    keystore=bundle_dir,
    to_did="did:key:zFrank...",
    groups=["default"],
)
tn.info("sale.line", item="bread", quantity=1, unit_price="3.25")
tn.flush_and_close()

# ── Frank (recipient, separate cwd in real life) ──────────────────
tn.init()                                  # Frank's own ceremony
receipt = tn.pkg.absorb(bundle_dir / "frank.tnpkg")
frank_keystore = tn.current_config().keystore
tn.flush_and_close()

# Decrypt Alice's log under Frank's kit.
for entry in tn.read(log=alice_log, as_recipient=frank_keystore, group="default"):
    if "default" not in entry.hidden_groups:
        print(entry.event_type, dict(entry.fields))
# → sale.line {'item': 'bread', 'quantity': 1, 'unit_price': '3.25'}
```

Test: [`c5_groups_recipients_inproc/test_recipient_decrypts_publisher_log.py`](regression/crawl/c5_groups_recipients_inproc/test_recipient_decrypts_publisher_log.py).

The TS equivalent is byte-identical at the wire level:

```ts
import { Tn } from "@tnproto/sdk";

// Alice
const alice = await Tn.use("default");
await alice.admin.addRecipient("default", { recipientDid: "did:key:zFrank..." });
await alice.pkg.bundleForRecipient({
  recipientDid: "did:key:zFrank...",
  outPath: "./alice_workspace/frank.tnpkg",
  groups: ["default"],
});
alice.info("sale.line", { item: "bread", quantity: 1, unit_price: "3.25" });
await alice.close();

// Frank
const frank = await Tn.use("default");          // separate cwd in real life
await frank.pkg.absorb("./alice_workspace/frank.tnpkg");
for (const e of frank.read({
  log: alice.logPath,
  asRecipient: frank.config().keystorePath,
  group: "default",
})) {
  if (!e.hidden_groups.includes("default")) console.log(e.event_type, e.fields);
}
```

Test: [`c5_groups_recipients_inproc/ts_recipient_decrypts_publisher_log.test.ts`](regression/crawl/c5_groups_recipients_inproc/ts_recipient_decrypts_publisher_log.test.ts).

**Cross-language works in both directions.** A Python publisher's log
decrypts cleanly under a TS reader, and a TS publisher's log decrypts
under Python. Both shapes are pinned by tests:
- [`ts_cross_language_python_publisher.test.ts`](regression/crawl/c5_groups_recipients_inproc/ts_cross_language_python_publisher.test.ts) (Python → TS)
- [`ts_cross_language_ts_publisher.test.ts`](regression/crawl/c5_groups_recipients_inproc/ts_cross_language_ts_publisher.test.ts) (TS → Python)

## 4. Vault auto-backup at init

`tn.init(link=True)` uploads an encrypted snapshot of the keystore to
the vault, persists a claim URL to disk, and stamps `.tn/sync/`. The
BEK travels in the URL fragment — the vault never sees it. Opening
the claim URL in a browser is what binds the keystore to your account.

```python
import tn
from pathlib import Path
from tn.sync_state import get_pending_claim

tn.init(link=True)                         # POSTs to $TN_VAULT_URL
cfg = tn.current_config()

claim_url = (Path(cfg.yaml_path).parent / ".tn" / "sync" / "claim_url.txt").read_text().strip()
print(claim_url)
# → http://127.0.0.1:8790/claim/01HXX...#k=<32 bytes base64url>

pc = get_pending_claim(cfg.yaml_path)
print(pc["vault_id"], pc["expires_at"])
```

Tests:
- [`c7_key_custody_default/test_init_link_mints_claim_url.py`](regression/crawl/c7_key_custody_default/test_init_link_mints_claim_url.py) (happy path)
- [`c7_key_custody_default/test_idempotent_reinit.py`](regression/crawl/c7_key_custody_default/test_idempotent_reinit.py) (re-init reuses vault_id within TTL)
- [`c7_key_custody_default/test_offline_init_no_abort.py`](regression/crawl/c7_key_custody_default/test_offline_init_no_abort.py) (vault unreachable → ceremony still works)

## 5. Restore on a new machine

The reverse of (4). Browser claims the URL, the backup ciphertext is
fetchable with the bearer JWT, decrypt with the BEK from the URL
fragment, lay out `tn.yaml` + `keys/`, call `tn.init(yaml)` → same
ceremony DID, chain continues.

```python
from regression._shared.vault_test_helpers import (
    dev_auth_login, fetch_pending_claim, parse_claim_url, restore_keystore_to,
)
import tn

# claim_url was emitted on machine A's tn.init(link=True)
vault_id, bek = parse_claim_url(claim_url)
login = dev_auth_login(VAULT_URL, handle="alice")
ciphertext = fetch_pending_claim(VAULT_URL, vault_id, login["token"])

yaml_b = restore_keystore_to(machine_b_tmpdir, ciphertext, bek)
tn.init(yaml_b)
assert tn.current_config().device.did == machine_a_did
```

Tests:
- [`c8_restore_new_machine/test_restore_recovers_same_ceremony_did.py`](regression/crawl/c8_restore_new_machine/test_restore_recovers_same_ceremony_did.py)
- [`c8_restore_new_machine/test_restore_can_sign_new_entries.py`](regression/crawl/c8_restore_new_machine/test_restore_can_sign_new_entries.py)
- [`c8_restore_new_machine/cross_language_restore.test.ts`](regression/crawl/c8_restore_new_machine/cross_language_restore.test.ts) (Python A → TS B)

## 6. Revoke + rotate locks out a recipient (forward-only)

Add Carol, bundle her kit, write an entry (Carol can decrypt), revoke
+ rotate, write another (Carol cannot decrypt the new one but the old
one stays readable).

```python
import tn

tn.init()
alice_log = tn.current_config().resolve_log_path()
carol_add = tn.admin.add_recipient("default", recipient_did=CAROL_DID, out_path=kit_path)
# … bundle Carol's kit, save aside …

tn.info("pre.revoke", marker="visible")

tn.admin.revoke_recipient("default", leaf_index=carol_add.leaf_index)
tn.admin.rotate("default")                 # advances group key

tn.info("post.revoke", marker="hidden")
tn.flush_and_close()

# Later, Carol absorbs her old kit:
for entry in tn.read(log=alice_log, as_recipient=carol_keystore, group="default"):
    if entry.event_type == "pre.revoke":
        assert "default" not in entry.hidden_groups       # decrypts
    elif entry.event_type == "post.revoke":
        assert "default" in entry.hidden_groups           # hidden
```

Tests: [`c5_groups_recipients_inproc/test_revoke_locks_out_recipient.py`](regression/crawl/c5_groups_recipients_inproc/test_revoke_locks_out_recipient.py) (Python) and [`ts_revoke_locks_out_recipient.test.ts`](regression/crawl/c5_groups_recipients_inproc/ts_revoke_locks_out_recipient.test.ts) (TS — un-skipped after the 0.4.1a2 fix).

## 7. CLI

```bash
python -m tn.cli init myproject --no-link --skip-confirm --keep-mnemonic
python -m tn.cli add_recipient default did:key:zFrank... --yaml myproject/tn.yaml
python -m tn.cli rotate default --yaml myproject/tn.yaml
python -m tn.cli read --yaml myproject/tn.yaml
```

Tests under [`regression/crawl/c6_cli_verbs/`](regression/crawl/c6_cli_verbs/) gate each verb's exit code and side effects.

TypeScript CLI is `tn-js`; verb shapes differ (positionals → flags, top-level → admin subcommand). See [`ts_cli_verb_parity.test.ts`](regression/crawl/c6_cli_verbs/ts_cli_verb_parity.test.ts) for the current snapshot.

---

# Chrome extension (`tn-decrypt`)

Manifest V3 extension. Vendor dashboards (Datadog, Splunk, Kibana,
webmail) store TN ciphertext as opaque text. The extension scans the
DOM, asks its service worker to decrypt each group payload with a kit
you've imported, and rewrites the rendered page in place. Keys never
leave the browser.

Same `tn-wasm` build the SDKs wrap, plus the audited EMK helpers
from `@tnproto/sdk/core`, vendored into the extension at build time.

### Install (manual)

1. Download `tn-decrypt-0.4.0.zip` from the [latest release](https://github.com/cyaxios/tn-proto/releases/tag/ext-v0.4.0).
2. Unzip into a directory Chrome can keep reading (don't delete it after install).
3. `chrome://extensions` → Developer mode → Load unpacked → pick the directory.
4. Click the extension icon → Manage keystore → import a `*.keystore.json` (from the vault's "Coming from another device?" flow or from `tn-js`/Python SDK output). Pick a passphrase for the local copy.
5. Click the icon → Unlock with that passphrase.
6. Open any page that displays a TN envelope. Entries your kit can open get a green `TN` badge with the decrypted fields inline.

Crypto-level proof that the bundled wasm decrypts what Python produces:
[`c9_chrome_ext_decrypt/test_ext_wasm_decrypts_python.test.ts`](regression/crawl/c9_chrome_ext_decrypt/test_ext_wasm_decrypts_python.test.ts).

### Building from source

```bash
bash tools/build-extension.sh
```

Then point Chrome's "Load unpacked" at `extensions/tn-decrypt/`.

---

# Regression suite

`regression/` holds the cross-language crawl-tier suite — nine silos
covering module-level + object-level logging on both runtimes, groups
+ recipients in-process, CLI verbs, vault auto-backup, restore on a
new machine, and inline decrypt in the Chrome extension.

Run all silos:

```bash
make -C regression all
```

Per-silo: `make c1` … `make c9`.

Cross-language tests prove the same envelope decrypts identically
under either runtime — Python publisher → TS reader (server logs,
browser audits) and TS publisher → Python reader (browser writes,
server audits).

---

# Layout

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

# License

Apache-2.0. See [LICENSE](LICENSE).
