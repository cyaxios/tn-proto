<div align="center">

# tn-proto

### Every action, a TransactioN.

Signed, encrypted, append-only logging. One entry per event, with byte-for-byte identical wire formats across Python, TypeScript, and the browser.

[![PyPI version](https://img.shields.io/pypi/v/tn-proto?style=flat-square&color=orange&label=pypi)](https://pypi.org/project/tn-proto/)
[![Python versions](https://img.shields.io/pypi/pyversions/tn-proto?style=flat-square)](https://pypi.org/project/tn-proto/)
[![Status: alpha](https://img.shields.io/badge/status-alpha-yellow?style=flat-square)](https://pypi.org/project/tn-proto/)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-green.svg?style=flat-square)](#license)
[![Keys: non-custodial vault](https://img.shields.io/badge/keys-non--custodial%20vault-brightgreen.svg?style=flat-square)](#non-custodial-vault-backups)

</div>

---

> **Alpha release — `0.6.0a3`.** This is an early alpha. The API and on-the-wire format may still change between alpha releases; pin an exact version for anything you depend on. Install: `pip install tn-proto`.

`tn-proto` is a secure logging library. You write ordinary structured logs; it signs each entry with your device key, chains it to the previous one (tamper-evident), and encrypts the fields so only the readers you choose can decrypt them. A shared Rust engine, bundled into the wheel as the `tn._native` extension, guarantees the Python and TypeScript SDKs produce identical records on the wire. One `pip install tn-proto` carries the whole engine, no separate packages and no C toolchain.

---

## Table of Contents
1. [Installation](#installation)
2. [Quickstart](#quickstart)
3. [How Log Sharing & Cryptographic Groups Work](#how-log-sharing--cryptographic-groups-work)
4. [Non-Custodial Vault Backups](#non-custodial-vault-backups)
5. [Default File Locations](#default-file-locations)
6. [Data Governance with `tn-agt`](#data-governance-with-tn-agt)

---

## Installation

### Python SDK
Install the stable release directly from PyPI:

```bash
pip install tn-proto
```

### TypeScript SDK
Install the npm package:

```bash
npm install tn-proto
```

---

## Quickstart

### Python

```python
import tn

# Initialize the default logger (names a project "demo")
tn.init("demo")

# Log structured events. Fields are automatically encrypted.
tn.info("order.created", order_id="o_100", amount=4999)

# Read the log back (automatically decrypts records you have access to)
for entry in tn.read():
    print(f"[{entry.level.upper()}] {entry.event_type}: {entry.fields}")

tn.flush_and_close()
```

### TypeScript

```typescript
import * as tn from "tn-proto";
import type { Entry } from "tn-proto";

// Load project configurations
const project = await tn.use("demo");
await tn.init(project.config().yamlPath);

// Log events
tn.info("order.created", { order_id: "o_100", amount: 4999 });

// Read logs
for (const e of tn.read()) {
  const entry = e as Entry;
  console.log(`[${entry.level.toUpperCase()}] ${entry.event_type}:`, JSON.stringify(entry.fields));
}

await tn.close();
```

---

## How Log Sharing & Cryptographic Groups Work

One of `tn-proto`'s biggest advantages is how it handles access control. Instead of sharing a single master password or database credential, you use **cryptographic groups** and **decentralized identities (DIDs)**.

### 🔑 The Access Model:
1. **Decentralized Identities (DIDs):** Every device running `tn-proto` generates its own local identity represented by a public DID (e.g., `did:key:z6Mk...`).
2. **Encrypted Groups:** Logs are organized into named groups (the default is called `default`). All fields written to a group are encrypted on disk.
3. **No Key Sharing:** You **never** share your private keys.
4. **Reader Kits:** To allow another user (e.g., an auditor or a developer) to read a group's logs:
   - You mint a **Reader Kit** addressed to their public DID.
   - You send them the kit as a `.tnpkg` file.
   - They absorb the kit into their local setup. They can now decrypt and read the logs in that group, but nothing else.
5. **Tamper-Evident Signatures:** Every log line is signed with your device's Ed25519 key. When a reader opens the log, they can instantly verify that the logs are authentic, came from you, and have not been altered or deleted.

### 🚫 Revoking Access:
If a recipient leaves the team or no longer needs access:
* You simply revoke their DID from the group.
* Future log entries will be encrypted using a key cover that excludes them.
* They can no longer read any new log entries, while all other active readers continue reading without any interruption or key redistribution.

---

## Non-Custodial Vault Backups

By default, initializing a project sets up a secure, automatic backup of your keys to **`vault.tn-proto.org`**.

```text
                   ┌──────────────────────────────────────────────┐
                   │               vault.tn-proto.org             │
                   │                                              │
                   │   [ Opaque Ciphertext Only ]                 │
                   │   • encrypted group keys                     │
                   │   • configuration (tn.yaml)                  │
                   └──────────────────────┬───────────────────────┘
                                          │
                        Secure Backup     │   Restore via Mnemonic
                        (No Log Sync)     │   or Passphrase
                                          ▼
                   ┌──────────────────────────────────────────────┐
                   │             Your Local Machine               │
                   │                                              │
                   │   .tn/keys/      ──► Device Identity & Keys  │
                   │   .tn/logs/      ──► LOCAL APPLICATION LOGS  │
                   └──────────────────────────────────────────────┘
```

### 🔒 Key points of the Vault system:
* **Just the Keys:** Only your project configuration (`tn.yaml`) and your encrypted group ciphers/keys are backed up to the vault.
* **Logs Never Leave Your Machine:** Your actual application log files (`.ndjson` files under `.tn/<project>/logs/`) are **never** uploaded or synced to the vault. They remain strictly local and completely private under your control.
* **Non-Custodial Design:** The vault stores keys only as opaque ciphertexts. Decryption is derived locally using your device seed or account recovery phrase. The server hosting `vault.tn-proto.org` cannot read your keys or decrypt your logs.
* **Disaster Recovery:** If your local machine crashes or your `.tn/` folder is deleted, you can restore your keys on a new machine using your recovery phrase (mnemonic) or account passphrase:
  ```bash
  tn wallet restore --mnemonic
  ```
* **Offline Mode:** If you do not want vault backups or online connectivity:
  ```bash
  tn init myproject --no-link
  ```

### 👤 Creating an Account on vault.tn-proto.org

The backup is tied to your device identity from the first `tn init`. To own it, manage it from a browser, and recover it anywhere, claim it under an account:

1. **Sign in.** Open <https://vault.tn-proto.org/account> and sign in (Google or passkey) to create your account.
2. **Initialize locally.** `tn init myproject` mints your device identity and pushes the encrypted keys + config. The CLI prints your account sign-in URL and the project it created.
3. **Link the project to your account** so it appears in your dashboard and is recoverable under your login:
   ```bash
   tn wallet link ./myproject/tn.yaml --vault https://vault.tn-proto.org
   ```
4. **Recover anywhere** with `tn wallet restore --mnemonic`.

### 🛠️ Using Your Own Vault (or None)

You are never tied to `vault.tn-proto.org`:

```bash
# Point at a different vault for one run...
tn init myproject --link https://vault.example.internal

# ...or set it once as a machine-wide default (system parameter):
export TN_VAULT_URL="https://vault.example.internal"
tn init myproject
```

Resolution order: explicit `--link`, then the `TN_VAULT_URL` environment variable, then the built-in default. `--no-link` opts out entirely.

---

## Default File Locations

All config, identity keys, and log entries live under a hidden `.tn/` directory in your workspace:

```text
.tn/
  <project-name>/
    tn.yaml          # Config (groups, routes, ciphers)
    keys/
      local.public   # Your public identity (DID)
      local.private  # Your private device seed (keep secret!)
    logs/
      default.ndjson # Local application logs
    admin/
      default.ndjson # Protocol and key audit logs
```

---

## Data Governance with `tn-agt`

For AI agent systems, `tn-proto` integrates with `tn-agt`—the TN evidence layer for the **Microsoft Agent Governance Toolkit** (AGT).

> **"AGT decides. TN proves."**

Under this model, **messages carry their own governance**, derived from a compile-time association of context. By utilizing cryptographic ciphers, we can secure and verify actions regardless of whether the messages flow internally, cross organizational boundaries, or operate in multi-party environments.

* **Bound Context:** Policies, constraints, and intent are cryptographically bound directly to the message payload, creating a self-attesting record.
* **Sealed Proofs:** When an AI agent makes a tool call, `tn-agt` intercepts AGT's evaluation decision and seals it into a signed, multi-recipient TN receipt.
* **Cross-Boundary Audits:** Because the governance metadata is embedded in the message itself, anyone can verify the compliance trail offline without relying on central databases or local logging configurations:
  ```bash
  # Verify the AGT logs against the sealed TN ledger
  tn-agt verify <agt-log.jsonl>
  ```

---

## Documentation

Full guides live in [`docs/guide/`](https://github.com/cyaxios/tn-proto/tree/main/docs/guide):

- [Getting started](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/getting-started.md) and the [Python cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-python.md) — every verb and command, with runnable examples.
- [Profiles](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/profiles.md) — pick the evidence and performance trade-off (transaction, audit, secure_log, telemetry, stdout).
- [Groups, readers, bundles, rotation](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/groups-readers-rotation.md) — encrypted groups, granting and revoking readers, `.tnpkg` bundles, key rotation.
- [Running in containers and CI](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/deploy-containers.md) — the `TN_API_KEY` bootstrap (hand one secret to your platform), disk-wins-over-env, identity paths.
- [Advanced usage](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/advanced-usage.md) — reading modes (`all_runs`), scoped lifecycles (`tn.session`), templated log paths, cross-language parity.
- [Protocol](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/protocol.md) and [YAML reference](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/yaml-reference.md) — the wire format and every config field.

---

## License

Dual-licensed under the MIT License or Apache License (Version 2.0).
