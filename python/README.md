# tn-proto

Signed, encrypted, append-only logging — one entry per event, with identical byte-for-byte wire formats in Python, TypeScript, and the browser.

---

**Python Support:** `3.10` to `3.14` | **TypeScript Support:** `Node` / `Browser` / `WASM` | **Release:** `v0.6.0a1` | **License:** `MIT` / `Apache-2.0` | **Key Escrow:** `Non-Custodial Vault`

`tn-proto` is a secure logging library. It lets you write structured logs that are cryptographically signed, chained, and private-by-default. Under the hood, a shared Rust engine guarantees that both the Python and TypeScript SDKs produce identical log records.

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

* **Keys & Configuration Only:** The vault only backs up your project settings (`tn.yaml`) and encrypted group ciphers/keys.
* **Logs Stay Local:** Your actual application logs (the log files where your telemetry and business records reside) are **never** sent to the vault. They remain strictly on your machine.
* **Zero-Knowledge Recovery:** The vault cannot decrypt your keys. If you lose your computer, you can restore your keys on a new machine using your mnemonic recovery phrase:
  ```bash
  tn wallet restore --mnemonic
  ```
* **Offline Mode:** If you do not want vault backups or online connectivity:
  ```bash
  tn init myproject --no-link
  ```

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

## License

Dual-licensed under the MIT License or Apache License (Version 2.0).
