# tn-proto

The agent transaction protocol. Signed, encrypted, append-only logging where every action is a verifiable transaction, with byte-for-byte identical wire formats across Python, TypeScript, and the browser.

---

**Release:** `v0.6.0a2` · **Python:** `3.10`–`3.14` · **TypeScript:** Node / Browser / WASM · **License:** `MIT` / `Apache-2.0`

`tn-proto` lets you write ordinary structured logs that are cryptographically signed, hash-chained (tamper-evident), and encrypted so only the readers you choose can decrypt them. A single Rust engine produces the records, so every language binding agrees on the wire down to the byte.

What makes a TN record more than a log line:

- **Content-bound.** The signature covers the entry's contents, not just a timestamp.
- **Multi-recipient.** One sealed record can be read by several named recipients, each with their own key, and readers can be revoked without redistributing keys.
- **Identity-anchored.** Every entry is signed by a device DID; anyone can verify authorship and integrity offline.

---

## Repository layout

```text
python/        The Python SDK + `tn` CLI  (pip install tn-proto)   -> python/README.md
ts-sdk/        The TypeScript / Node / browser SDK
crypto/        The Rust workspace (the shared engine)              -> crypto/*/README.md
  tn-core/       runtime: canonical JSON, hash chain, signing, envelopes, cipher dispatch, log I/O
  tn-btn/        broadcast-transaction encryption (group keys, reader kits, rotation, revocation)
  tn-core-py/    PyO3 bindings for tn-core      (internal rlib)
  tn-btn-py/     PyO3 bindings for tn-btn       (internal rlib)
  tn-py/         umbrella crate -> the `tn._native` extension in the wheel
  tn-wasm/       wasm-bindgen build for Node + browser
extensions/    Browser extension (tn-decrypt)
docs/          Guides, cookbooks, and the protocol spec
```

The Python wheel bundles `tn-core` + `tn-btn` into one `tn._native` extension, so `pip install tn-proto` carries the whole engine with no separate packages and no C toolchain.

---

## Quickstart (Python)

```bash
pip install tn-proto
```

```python
import tn

tn.init("demo")
tn.info("order.created", order_id="o_100", amount=4999)

for entry in tn.read():
    print(f"[{entry.level or '-'}] {entry.event_type}: {entry.fields}")

tn.flush_and_close()
```

Full package docs, the vault account flow, sharing, and the CLI: **[python/README.md](python/README.md)**.

---

## Keys and the vault

Your private keys live only on your machine. The optional non-custodial vault at `https://vault.tn-proto.org` backs up your **keys and config only** (never your logs), holds ciphertext it cannot decrypt, and recovers via your mnemonic. Create an account at <https://vault.tn-proto.org/account>, skip it with `tn init <name> --no-link` (offline), or point elsewhere with `TN_VAULT_URL`. Details in [python/README.md](python/README.md#vault-backup-and-recovery-optional).

---

## Documentation

- [Getting started](docs/guide/getting-started.md)
- [Python cookbook](docs/guide/cookbook-python.md) / [TypeScript cookbook](docs/guide/cookbook-typescript.md)
- [Protocol guide](docs/guide/protocol.md) and [YAML reference](docs/guide/yaml-reference.md)

---

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
