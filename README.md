<!--
[DOCUMENTATION-SPEC: LOCKED]
This README follows the tn-proto documentation guidelines.
DO NOT simplify this document into generic summaries.
DO NOT remove:
  - The Shields.io badges or the ASCII architecture diagrams.
  - The side-by-side Python + TypeScript quickstart examples (with output).
  - The full CLI reference, the "How log sharing works" section, or the
    "AI coding agents - tn-skills" section.
  - The non-custodial vault section, including key recovery and how to disable it.
Maintain a straightforward, developer-friendly voice. Avoid parameter-heavy explanations.
-->

# tn-proto

---

[![PyPI](https://img.shields.io/pypi/v/tn-proto?style=flat-square&color=orange&label=pypi)](https://pypi.org/project/tn-proto/)
[![npm](https://img.shields.io/npm/v/@cyaxios/tn-proto?style=flat-square&color=cb3837&label=npm)](https://www.npmjs.com/package/@cyaxios/tn-proto)
[![Runtimes](https://img.shields.io/badge/runtimes-Python%20%7C%20Node%20%7C%20Browser%20%7C%20WASM-3178c6.svg?style=flat-square)](#one-core-every-language)
[![Keys](https://img.shields.io/badge/keys-non--custodial%20vault-brightgreen.svg?style=flat-square)](#non-custodial-vault-backup)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-green.svg?style=flat-square)](#license)

**`tn-proto` keeps every record readable only by the people you've authorized - and leaves cryptographic proof that it did.** Fields are encrypted per reader, so the wrong people simply can't decrypt them; each entry is signed by your device and hash-chained, so anyone can verify offline - from the log file alone - who was allowed to read what, and that nothing was altered after the fact.

## Installation

```bash
pip install tn-proto            # Python
npm install @cyaxios/tn-proto   # Node / TypeScript
```

The Rust core ships compiled into each package (a wheel for Python, bundled WebAssembly for Node): one install, no native toolchain.

## Quickstart

The first run mints a ceremony under `./.tn/` - nothing to configure.

**Python**
```python
import tn

tn.init()                                       # or tn.init("billing") for a named project
tn.info("order.created", order_id="A100", amount=4999)
tn.warning("order.flagged", order_id="A100", reason="hold")

for entry in tn.read():
    print(entry.level, entry.event_type, entry.fields)
```
```text
info order.created {'amount': 4999, 'order_id': 'A100'}
warning order.flagged {'order_id': 'A100', 'reason': 'hold'}
```

`tn.read()` hands you back decrypted fields. The same entry **as written to disk** is sealed: your values are encrypted into the group, the row is signed and hash-chained.

```json
{
  "device_identity": "did:key:z6MkeWpUKjEJ8PNmJWT4X4kXudbcaJ3kWVkKZ21vBdksX3x5",
  "event_type": "order.created",
  "level": "info",
  "sequence": 1,
  "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "row_hash": "sha256:9ab903c5772710619b2b5a43b41b7ff0b13dd2651fafcb64b054232cd8022c3e",
  "signature": "jvOHz3BfZwPx57eHwzXgUhhe8xlwkAZfFH5J7swZcrg1edWuBo0iyIdKNrMw7ggZ…",
  "default": {
    "ciphertext": "twEB/kT5M/D6sO4HPyjtmpkX6oCxc5SPm41fpXf/Ukbr9GMAAAAAAAEAFJ+sOaP…",
    "field_hashes": { "amount": "hmac-sha256:v1:35e986d4e9152723…" }
  }
}
```

`order_id` and `amount` appear nowhere in the clear: only the `ciphertext` sealed to the `default` group, plus equality-search hashes. Anyone without a reader key sees exactly this.

**TypeScript / Node** - byte-identical records:
```ts
import * as tn from "@cyaxios/tn-proto";

await tn.init();
tn.info("order.created", { order_id: "A100", amount: 4999 });
for (const entry of tn.read()) console.log(entry.level, entry.event_type, entry.fields);
await tn.close();
```

Set `TN_NO_STDOUT=1` to silence the stdout echo. In Python the SDK drains on interpreter exit (`tn.flush_and_close()` to force it); in Node always `await tn.close()` on shutdown.

## What you get

TN does two jobs at once: it keeps each record from reaching the wrong eyes, and it leaves a verifiable receipt that you kept it that way.

**Control who can read what**
- **Private by default** - field values are encrypted on disk. The wrong people don't get a redacted view; they get ciphertext they can't open.
- **Per-reader** - one entry can be sealed for several named parties, each with their own key, so each sees only what they're authorized to.
- **Revocable** - cut a reader off and the next entry is already beyond their reach; everyone else keeps reading, no rekeying.

**Prove you did**
- **Signed** - each entry carries an Ed25519 signature from the device that wrote it: who wrote it, provably.
- **Tamper-evident** - entries are hash-chained, so altering, reordering, or deleting one fails verification.

You confirm all of it offline, from the log file and a public key alone - no server to trust, no vendor's word to take.

## The verbs

| Verb (Python · TypeScript) | What it does |
|---|---|
| `tn.init()` / `await tn.init()` | resolve or create a ceremony and bind it as the module runtime |
| `tn.use("name")` / `await tn.use("name")` | open or create a named ceremony as a standalone handle for juggling several projects in one process; unlike `init` it does not rebind the module default |
| `tn.info` / `.warning` / `.error` / `.debug` | one signed, encrypted entry at that level |
| `tn.log(...)` | emits regardless of the level threshold, so it always writes; in Python it returns the written envelope as a dict, in Node it returns an `EmitReceipt`. Reach for it when you need a level outside debug/info/warning/error |
| `tn.read()` | iterate decoded `Entry` objects |
| `tn.watch()` | tail the log live |
| `tn.export` / `tn.absorb` | produce or install a `.tnpkg` bundle |
| `tn.scope(...)` | layer request-context fields onto every entry inside the block (Python: `with tn.scope(k=v):`; Node: `tn.scope({k:v}, () => …)`); metadata that rides along, not a group |

### Reading: all entries, this run, admin

```python
for e in tn.read():                  # default: every entry on disk (all_runs=True)
    ...
for e in tn.read(all_runs=False):    # only what THIS process emitted
    ...
for e in tn.read(log="admin"):       # the admin log (ceremony lifecycle: tn.* events)
    print(e.level, e.event_type)
```

`tn.read(verify=True)` (Node: `tn.read({ verify: true })`) re-checks every signature and the full hash chain as it reads, and raises the moment something doesn't add up.

## The CLI

Each package installs a CLI - `tn` for Python, `tn-js` for Node. It's non-interactive by default - safe to drop straight into CI and containers.

| Command | What it does |
|---|---|
| `tn init [name]` | provision identity + ceremony under `./.tn/` |
| `tn read [--all-runs]` | decoded entries to stdout |
| `tn info --event <type> [--field k=v]…` | emit one attested entry from the shell |
| `tn add_recipient <group> <name>` | mint a reader kit for someone, wrapped as a `.tnpkg` |
| `tn invite` | invite a reader (by email/label) |
| `tn group` | add / inspect groups |
| `tn rotate` | rotate group keys; emit one per-reader `.tnpkg` |
| `tn absorb` / `tn import` | install a `.tnpkg` someone sent you |
| `tn export` / `tn compile` / `tn bundle` | produce `.tnpkg` bundles from your keystore |
| `tn wallet` | vault: `status`, `link`, `restore`, `sync` |
| `tn account` / `tn vault` | manage the vault account / emit vault events |
| `tn streams` | list ceremonies under `./.tn/` |
| `tn validate` | validate the project's config tree |
| `tn show env` / `tn show profiles` | reflective inspection (secrets redacted) |
| `tn seal` / `tn verify` / `tn canonical` | attest / verify / canonicalize envelopes from stdin |

```bash
tn init                                   # provision in ./.tn/
tn info --event order.created --field order_id=A100 --field amount=4999
tn read --all-runs                        # include entries from prior runs
```

## How log sharing works

You never share a password or a private key. Access is cryptographic:

- **Identity (DID).** Every device has its own identity - a public `did:key:z6Mk…` derived from its Ed25519 key. Private keys never leave the machine.
- **Groups.** Events land in named groups (default: `default`); each group is its own encrypted domain with its own reader list. Readers of `payments` can decrypt `payments` events, and only those.
- **Reader kits.** To let someone read a group, you mint a kit addressed to their DID and send it. They absorb it and can decrypt that group - and nothing else.
- **Revocation.** Revoke a reader and future entries are encrypted to exclude them; every other reader keeps working, no rekeying.

Grant access (Python):
```python
import tn
tn.init()
result = tn.admin.add_recipient(
    group="default",
    recipient_did="did:key:z6Mk…",           # the reader's real Ed25519 DID
    out_path="./alice.btn.mykit",
)
print(result.leaf_index, result.kit_path)
```

Or one-shot from the CLI (mints the kit and wraps a `.tnpkg`):
```bash
$ tn add_recipient default alice
[tn add_recipient] wrote /your/cwd/alice.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:zLabel-alice
```

The CLI synthesizes a friendly **label DID** (`did:key:zLabel-alice`) from the name so you can try sharing without copying real keys around; production readers are addressed by their own `did:key:z6Mk…`.

Revoke when you need to:
```python
tn.admin.revoke_recipient(group="default", leaf_index=1)
```

## Groups and field routing

A **group** is an encrypted domain with its own reader list; **routing** a field into it means that field's value is sealed to that group's readers and to no one else. One command creates the group and routes fields in a single step, identical in both runtimes:

```bash
tn group add payments --fields order_id,amount,card_last4       # Python
tn-js group add payments --fields order_id,amount,card_last4    # TypeScript
```

From then on, any `tn.info(...)` carrying `order_id`, `amount`, or `card_last4` seals those into `payments`; every other field stays in `default`.

```python
# Python, in-process
tn.ensure_group(tn.current_config(), "payments", fields=["order_id", "amount", "card_last4"])
```
```ts
// TypeScript, in-process
await tn.admin.ensureGroup("payments", { fields: ["order_id", "amount", "card_last4"] });
```

Or hand-edit the `groups:` and `fields:` blocks in `tn.yaml` (see [Configuration](#configuration-tnyaml)); the SDK picks up the change in the same process.

## Bundles (`.tnpkg`)

A `.tnpkg` is a signed zip with a manifest and body files - the unit everything is shared as.

```python
# Producer: seal a kit so only the named DID can open it.
tn.export("alice.tnpkg", kind="kit_bundle", to_did="did:key:z6Mk…", seal_for_recipient=True)

# Reader: absorb merges it into your current ceremony (run tn.init() first).
tn.init()
receipt = tn.absorb("./alice.tnpkg")
print(receipt.kind, receipt.accepted_count, receipt.deduped_count)   # -> kit_bundle 1 0
```

## Rotation

`tn rotate` writes a new generation of group keys and emits one `.tnpkg` per surviving reader. Hand each reader their file (vault push, CI artifact, email); they run `tn absorb`. A revoked reader isn't in the new generation, so they keep old entries but can't read anything after the rotation.

```bash
$ tn rotate
[tn rotate] rotated 1 group(s); emitted 1 .tnpkg artifact(s) into /your/cwd/rotated_20260612T194533Z
             default: epoch=1
             -> did_key_zLabel-alice.tnpkg
```

## Non-custodial vault backup

Your keys live on your machine and nowhere else - so nobody, us included, can read your data. The optional vault at `vault.tn-proto.org` is the safety net for when that machine dies.

```text
    ┌────────────────────────────────────────────────────┐
    │ vault.tn-proto.org                                 │
    │ stores ciphertext it CANNOT decrypt:               │
    │   - your encrypted group keys                      │
    │   - your config (tn.yaml)                          │
    └────────────────────────────────────────────────────┘
                  ▲                       │
    backup:       │                       │   restore:
    keys + config │                       ▼   your mnemonic
    ┌────────────────────────────────────────────────────┐
    │ your machine                                       │
    │ .tn/<project>/keys/   ->  backed up to the vault   │
    │ .tn/<project>/logs/   ->  100% local, never sent   │
    └────────────────────────────────────────────────────┘
```

- **Keys & config only.** Your `tn.yaml` and encrypted group keys are backed up. Your `.ndjson` log files are **100% local** and never uploaded.
- **Zero-knowledge.** The vault holds ciphertext it cannot read; recovery is gated by a mnemonic phrase only you hold.

### Your first init prints a claim link

Unless you pass `--no-link`, the first `tn init` (`tn-js init` prints the same) mints your device identity, pushes the encrypted keys + config, and prints a **claim link**:

```text
$ tn init demoproj
[tn init] Ceremony local_233ff998 created at ./.tn/demoproj/tn.yaml
[tn init]   project: demoproj
[tn init]   cipher: btn
[tn init]   keystore: ./.tn/demoproj/keys

[tn init] Backed up to https://vault.tn-proto.org
[tn init]   vault_id:   01KTYX…                  # id of the pending backup
[tn init]   expires:    2026-06-13 17:56          # the claim link is good for ~24h

[tn init] CLAIM URL - open this in your browser to attach the project to your account:
  https://vault.tn-proto.org/claim/01KTYX…#k=••••••••

[tn init] Already have a vault account, or want to attach this project later?
[tn init]   1. Sign in at https://vault.tn-proto.org/account
[tn init]   2. On the Projects tab, mint a connect code
[tn init]   3. Run:  tn account connect <code> --yaml ./.tn/demoproj/tn.yaml
```

**Open the claim link** and a vault page attaches this backup to your account (Google or passkey), so you can restore it on any machine later. Two parts of that URL matter:

- `/claim/01KTYX…` points at the encrypted backup this `init` just pushed.
- `#k=••••••••` is the **decryption key**, carried in the URL *fragment*. Browsers never send the fragment to the server, so the claim page decrypts in your browser and the vault still never sees your key. That is what keeps it zero-knowledge.

Treat the whole link like a password: anyone holding it (fragment included) can claim that backup, and it stops working after the `expires:` time. Already have an account? Skip the link and use the sign-in + connect-code steps it prints.

**Key recovery.** Sign in at <https://vault.tn-proto.org/account> (the dashboard also lets you invite readers by email and trigger rotations). To recover on a new machine:
```bash
tn wallet status            # is this machine linked, and to what
tn wallet restore           # rebuild every ceremony's keystore from your recovery phrase
```

**Turn it off.** You are never tied to the vault:
```bash
tn init --no-link                          # fully offline; never contacts a vault
export TN_NO_LINK=1                         # same, as an environment switch
export TN_VAULT_URL="https://my-vault…"     # or point at your own
```

## Profiles

A profile is a named bundle of three independent guarantees - pick the trade-off, not the knobs:

- **Encryption - always on.** Field values are encrypted into their groups in every profile. There is no plaintext mode; this is the floor.
- **Signing** - an Ed25519 signature from the writing device on each entry, proving authorship. The evidence profiles keep it; the lightweight ones drop it for speed.
- **Chaining (verification)** - the hash link from each entry to the one before it. This is what makes the log tamper-evident and ordered, and what `read(verify=True)` checks. The evidence profiles keep it.

```python
tn.init(profile="audit")                       # Python
```
```ts
await tn.init(undefined, { profile: "audit" }); // TypeScript
```

| Profile | Encrypt | Sign | Chain | Use it for |
|---|:---:|:---:|:---:|---|
| `transaction` *(default)* | ✓ | ✓ | ✓ | grants, payments, agent actions, security events - full evidence |
| `audit` | ✓ | ✓ | ✓ | normal business events; same evidence, buffered for throughput |
| `secure_log` | ✓ | ✓ | - | signed app logs where authorship matters more than ordering |
| `telemetry` | ✓ | - | - | high-volume traces / metrics; near-zero overhead, stdout |
| `stdout` | ✓ | - | - | dev / notebook scratchpad, encryption still on |

## Configuration (`tn.yaml`)

`tn.yaml` is **generated by `tn init`** (`tn-js init` in Node), and the CLI and SDK keep it in sync for you (`tn group add`, the ensure-group + vault verbs all write it). **You normally never edit it by hand - reach for a verb instead.** It is plain YAML, so you *can* hand-edit it once you know the schema, but a malformed file can break loading or field routing, so treat that as an advanced path. It is shown here in full (comments are explanatory; the emitted file has none) so you can see what the tools manage:

```yaml
ceremony:
  id: local_f2bb8224             # ceremony identifier
  mode: local                    # local | linked  (linked = backed by a vault)
  linked_vault: ''               # vault URL; empty when offline
  linked_project_id: ''          # vault-side project id; filled by `tn wallet link`
  sync_logs: false               # also sync ndjson logs to the vault
  cipher: btn                    # ceremony-wide cipher
  sign: true                     # Ed25519-sign every row
  admin_log_location: ./admin/default.ndjson   # tn.* admin events; read via tn.read(log="admin")
  log_level: debug               # debug | info | warning | error
  profile: transaction           # evidence profile (see Profiles)
  chain: true                    # maintain the per-event-type hash chain

  project_name: demoproj         # human label; sent as X-Project-Name on vault push

logs:
  path: ./logs/default.ndjson    # main user-log ndjson destination

keystore:
  path: ./keys                   # holds local.private, *.btn.state, etc.

device:
  device_identity: did:key:z6Mk…   # this machine's DID

handlers:                        # output sinks; replaces the implicit default
  - kind: file.rotating
    name: main
    path: ./logs/default.ndjson
    max_bytes: 5242880
    backup_count: 5
  - kind: stdout

public_fields:                   # fields always written in the clear (additive to defaults)
  - timestamp
  - event_id
  - event_type
  - level

default_policy: private          # policy for fields not routed to any group

groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - recipient_identity: did:key:z6Mk…        # you
  payments:                                       # a group you added
    policy: private
    cipher: btn
    fields: [order_id, amount, card_last4]        # route these fields into 'payments'
    recipients:
      - recipient_identity: did:key:z6Mk…         # who may read 'payments'
  tn.agents:                     # reserved protocol group, auto-injected for agent policy
    policy: private
    cipher: btn
    fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]
    recipients:
      - recipient_identity: did:key:z6Mk…

fields: {}                       # field-routing overrides; groups carry their own

llm_classifier:                  # optional auto-classification of fields into groups
  enabled: false
  provider: ''
  model: ''
```

A single `tn.info(...)` can fan one event into several groups, each encrypted to that group's readers only. Log and admin paths also accept **templated paths** (`{event_class}`, `{date}`, `{event_id}`, …) so events sort themselves on disk. Calling `tn.init("billing")` against a project creates a named **stream** that shares the project's identity (`.tn/default/keys`) while owning its own log.

> **Every `tn.yaml` field - groups, field routing, ciphers, handlers, profiles, ceremony/link state - is documented in the [`tn.yaml` reference](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/yaml-reference.md).**

## Containers & CI

No home directory, no baking keys into an image. Set one secret - `TN_API_KEY` - and the container trades it with the vault for its keystore on first boot, then runs normally. If a keystore already exists on disk, that wins and the env var is ignored. Full guide: [running in containers and CI](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/deploy-containers.md).

## Environment variables

Everything has a sensible default; these override it. `tn show env` prints the full canonical surface (secrets redacted).

| Variable | What it does |
|---|---|
| `TN_API_KEY` | Container/CI bootstrap: traded with the vault for this project's keystore on first boot. Ignored when a local keystore already exists. |
| `TN_NO_LINK=1` | Never auto-link a fresh ceremony to a vault - fully offline. |
| `TN_VAULT_URL` | Base URL of the vault to use. Default: `https://vault.tn-proto.org`. |
| `TN_NO_STDOUT=1` | Silence the stdout echo of each entry. |
| `TN_IDENTITY_DIR` | Directory holding your `identity.json`. Default: the OS data dir (`~/.local/share/tn`, `%APPDATA%\tn`). |
| `TN_YAML` | Explicit path to `tn.yaml` for init / discovery. |
| `TN_HOME` | Root for shared TN state. Default: `~/.tn`. |
| `TN_STRICT=1` | Disable ceremony auto-discovery; `init()` must be given an explicit project. |

## AI coding agents - tn-skills

[`tn-skills`](https://github.com/cyaxios/tn-skills) teaches your AI coding agent to use `tn-proto` correctly. With it installed, the agent routes PII into the right encrypted group, calls `tn.init` once at startup (not inside a request handler), never logs a secret like a CVV, and cites the right regulation when a file's domain matches one of its built-in industry kits. It keeps agent-written code from quietly telling the wrong thing to the wrong people.

Install it in Claude Code:
```text
/plugin marketplace add cyaxios/tn-skills
/plugin install tn-logging@tn-skills
```

For other AI tools, drop the repo's `AGENTS.md` into your agent. The bundled skills and industry kits are documented at <https://github.com/cyaxios/tn-skills>.

## One core, every language

The wire format is identical across Python, Node, and the browser, checked on every change - write in one, read in another.

| Runtime | Install |
|---|---|
| Python | `pip install tn-proto` |
| Node / TypeScript | `npm install @cyaxios/tn-proto` |
| Browser | the `@cyaxios/tn-proto/core` subpath (no Node deps) |

## Documentation

- [Getting started](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/getting-started.md) · [Python cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-python.md) · [TypeScript cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-typescript.md)
- [Groups, readers, bundles, rotation](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/groups-readers-rotation.md) · [Running in containers and CI](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/deploy-containers.md)
- [Profiles](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/profiles.md) · [tn.yaml reference](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/yaml-reference.md) · [protocol spec](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/protocol.md)
- [Authentication & accounts](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/auth.md) · [Environment variables](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/environment-variables.md)

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
