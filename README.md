# tn-proto

TestigoNodo (TN) — attested logging protocol with broadcast encryption.

A small protocol for emitting log entries that are signed, encrypted to a
named group of recipients, and chain-linked. Two ciphers ship in this
release:

- **JWE** — pure Python, X25519 + AES-KW + AES-GCM. No native deps.
- **btn** — NNL subset-difference broadcast, Rust core via `tn-core` /
  `tn-btn` pyo3 wheels. O(log n) revocation, ~0.4 ms/op.

## Languages

| Channel       | Package                       | Status              |
|---------------|-------------------------------|---------------------|
| Python        | `pip install tn-protocol`     | 0.2.0a2 alpha       |
| TypeScript    | `npm install @tnproto/sdk`    | 0.3.0-alpha.1       |
| Rust          | `cargo add tn-core`           | in tree, not yet published |
| Chrome ext    | `extensions/tn-decrypt/`      | unpacked load only  |

The TypeScript SDK split off from a pre-Phase-2 `TNClient` god-class
into a `Tn` class with namespaced sub-objects (`tn.admin/pkg/vault/agents/handlers`),
a browser-safe Layer 1 entry at `@tnproto/sdk/core` that the Chrome
extension consumes for audited crypto + EMK + zip primitives, and a
new `tn.watch()` async-iterable verb (mirrored on Python). See
[`docs/sdk-parity.md`](docs/sdk-parity.md) for the cross-language verb table.

## Quick start (Python)

```bash
pip install tn-protocol
```

```python
import tn

tn.init("./tn.yaml")          # mints a fresh ceremony if none exists
tn.info("order.created", order_id="A100", amount=4999)

for entry in tn.read():
    print(entry["event_type"], entry.get("order_id"))

tn.flush_and_close()
```

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
