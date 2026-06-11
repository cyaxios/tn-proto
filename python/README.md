# tn-proto

Signed, encrypted, append-only logging. One entry per event, cryptographically chained and private by default, with byte-for-byte identical wire formats across Python, TypeScript, and the browser.

---

**Python:** `3.10` – `3.14` · **Release:** `v0.6.0a2` · **License:** `MIT` / `Apache-2.0` · **Key escrow:** non-custodial vault (optional)

`tn-proto` is a secure logging library. You write ordinary structured logs; the library signs each entry with your device key, chains it to the previous one (tamper-evident), and encrypts the fields so only the readers you choose can decrypt them. A shared Rust engine, compiled into the wheel as the `tn._native` extension, guarantees the Python and TypeScript SDKs produce the same records on the wire.

One `pip install tn-proto` ships everything: the pure-Python `tn` package plus the bundled Rust core. There are no separate `tn-core` / `tn-btn` packages, no C toolchain, no OpenSSL to set up. The wheel is `abi3`, so a single build per platform covers Python 3.10 through 3.14.

---

## Table of contents

1. [Install](#install)
2. [Quickstart](#quickstart)
3. [Forwarding a record downstream](#forwarding-a-record-downstream)
4. [Vault: backup and recovery (optional)](#vault-backup-and-recovery-optional)
   - [Create an account on vault.tn-proto.org](#create-an-account-on-vaulttn-protoorg)
   - [Run without a vault (offline, or your own)](#run-without-a-vault-offline-or-your-own)
5. [Sharing logs: groups, reader kits, revocation](#sharing-logs-groups-reader-kits-revocation)
6. [Where files live](#where-files-live)
7. [CLI](#cli)
8. [Governance for AI agents (tn-agt)](#governance-for-ai-agents-tn-agt)
9. [Documentation](#documentation)
10. [License](#license)

---

## Install

```bash
pip install tn-proto
```

That is the whole install. `import tn` works immediately.

---

## Quickstart

```python
import tn

# Start (or attach to) a project. Creates a local keypair + config on first run.
tn.init("demo")

# Log structured events. Field values are encrypted on disk.
tn.info("order.created", order_id="o_100", amount=4999)
tn.warning("payment.retry", order_id="o_100", attempt=2)

# Read it back. tn.read() decrypts the records you can read and
# returns typed Entry objects (verifying the signature chain as it goes).
for entry in tn.read():
    print(f"[{entry.level or '-'}] {entry.event_type}: {entry.fields}")

tn.flush_and_close()
```

The verbs map to levels: `tn.debug`, `tn.info`, `tn.warning`, `tn.error`, and `tn.log` (severity-less, or any custom `level=`). They are fire-and-forget except `tn.log` (see below).

`tn.read()` returns a typed `Entry` by default (`entry.event_type`, `entry.level`, `entry.fields`, ...). Pass `raw=True` only when you want the underlying envelope dict.

---

## Forwarding a record downstream

`tn.log(...)` returns the **signed on-wire envelope** that was written, as a JSON-ready dict. That lets you hand the attested record straight to another system:

```python
import requests

envelope = tn.log("audit.checkpoint", level="audit", row=42)
# envelope = {"device_identity": ..., "event_type": "audit.checkpoint",
#             "sequence": ..., "prev_hash": ..., "row_hash": ...,
#             "signature": ..., <encrypted group blocks>, ...}

requests.post("https://collector.example/ingest", json=envelope)
```

`tn.log` is the only verb that returns the record. The threshold-aware verbs (`tn.info`, `tn.warning`, `tn.debug`, `tn.error`) are fire-and-forget and return `None`. The same split applies to per-stream handles and `tn.session(...)`.

---

## Vault: backup and recovery (optional)

Your private keys live only on your machine. Losing them means losing the ability to read your own encrypted logs. The vault is a non-custodial backup for exactly that:

- **Keys and config only.** The vault stores your `tn.yaml` and the encrypted group ciphers. Your application **logs never leave your machine**.
- **Zero-knowledge.** The vault holds ciphertext it cannot decrypt. Recovery is gated by your mnemonic recovery phrase, which only you have.

By default `tn.init(...)` backs up to `https://vault.tn-proto.org`. Restore on a new machine with:

```bash
tn wallet restore --mnemonic
```

### Create an account on vault.tn-proto.org

The backup is tied to your device identity from the first `tn init`. To own it, be able to manage it from a browser, and recover it anywhere, claim it under an account:

1. **Sign in.** Open <https://vault.tn-proto.org/account> and sign in (Google or passkey). That creates your account.
2. **Initialize a project locally.** `tn init myproject` mints your device identity and pushes the encrypted keys+config to the vault. The CLI prints the account sign-in URL and the project URL it created.
3. **Link the project to your account.** Sign in (step 1), then attach the project to your account so it shows up in your dashboard and is recoverable under your login:
   ```bash
   tn wallet link ./myproject/tn.yaml --vault https://vault.tn-proto.org
   ```
   (The dashboard can also issue a one-time connect code that `tn` redeems to link without copying URLs around.)
4. **Recover anywhere.** On a new machine, `tn wallet restore --mnemonic` rebuilds your keystore from the recovery phrase.

### Run without a vault (offline, or your own)

You never have to touch `vault.tn-proto.org`:

```bash
# Fully offline. No network, no backup, ever.
tn init myproject --no-link
```

```bash
# Point at a different vault (self-hosted, staging, etc.) for this run...
tn init myproject --link https://vault.example.internal

# ...or set it once as a machine-wide default via the system parameter:
export TN_VAULT_URL="https://vault.example.internal"
tn init myproject
```

Resolution order is: explicit `--link` argument, then the `TN_VAULT_URL` environment variable, then the built-in default. `--no-link` opts out of all of it.

---

## Sharing logs: groups, reader kits, revocation

Access control is cryptographic, not credential-sharing. You never hand out a master password or your private key.

- **Decentralized identities (DIDs).** Every device generates a local identity with a public DID (`did:key:z6Mk...`). Private keys never leave the device.
- **Encrypted groups.** Logs are organized into named groups (default: `default`). Fields written to a group are encrypted on disk.
- **Reader kits.** To let an auditor or teammate read a group, you mint a reader kit addressed to their public DID, send it as a `.tnpkg` file, and they absorb it. They can now decrypt that group, and nothing else.
- **Tamper-evident.** Every line is Ed25519-signed and hash-chained to the previous one. A reader can verify, offline, that the log is authentic, came from you, and has not been altered or had entries removed.
- **Revocation without redistribution.** Revoke a reader's DID and future entries are encrypted under a key cover that excludes them. Every other active reader keeps reading with no key rotation on their end.

See the [cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-python.md) for `tn add_recipient`, `tn invite`, `tn group`, `tn rotate`, and `tn absorb`.

---

## Where files live

Everything for a project lives under a hidden `.tn/` directory in your workspace:

```text
.tn/
  <project-name>/
    tn.yaml          # config: groups, routes, ciphers
    keys/
      local.public   # your public identity (DID)
      local.private  # your private device seed — keep secret
    logs/
      default.ndjson # your application logs (local only)
    admin/
      default.ndjson # protocol + key-management audit log
```

---

## CLI

`tn-proto` installs a `tn` command. Common verbs:

```bash
tn init <name> [--no-link | --link <url>]   # start a project
tn read [--event <type>] [--all-runs]       # read + verify the log
tn add_recipient <kit-or-did>               # grant a reader
tn rotate <group>                           # rotate a group's keys
tn invite / tn absorb                       # share + receive reader kits
tn wallet link / restore                    # vault account + recovery
tn seal / tn verify                         # sealed-message round trip
tn show env                                 # inspect the TN_* environment
```

Full reference with runnable examples: the [Python cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-python.md).

---

## Governance for AI agents (tn-agt)

For AI agent systems, `tn-proto` underlies `tn-agt`, the TN evidence layer for the Microsoft Agent Governance Toolkit (AGT). The model: **AGT decides, TN proves.**

- **Bound context.** Policies, constraints, and intent are cryptographically bound to the message payload, producing a self-attesting record.
- **Sealed proofs.** When an agent makes a tool call, `tn-agt` seals AGT's evaluation decision into a signed, multi-recipient TN receipt.
- **Cross-boundary audit.** Because the governance metadata travels in the message, anyone can verify the trail offline:
  ```bash
  tn-agt verify <agt-log.jsonl>
  ```

---

## Documentation

- [Getting started](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/getting-started.md)
- [Python cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-python.md) — runnable recipes for every verb
- [Protocol guide](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/protocol.md) — the wire format, groups, and the `tn.agents` policy group
- [Examples](https://github.com/cyaxios/tn-proto/tree/main/python/examples)

---

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
