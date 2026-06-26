<!--
[DOCUMENTATION-SPEC: LOCKED]
This README follows the tn-proto documentation guidelines.
DO NOT simplify this document into generic summaries.
DO NOT remove:
  - The Shields.io badges or the ASCII architecture diagrams.
  - The side-by-side TypeScript + Python quickstart examples (with output).
  - The full CLI reference, the "How log sharing works" section, or the
    "AI coding agents - tn-skills" section.
  - The non-custodial vault section, including key recovery and how to disable it.
Maintain a straightforward, developer-friendly voice. Avoid parameter-heavy explanations.
-->

# @cyaxios/tn-proto

---

[![npm](https://img.shields.io/npm/v/@cyaxios/tn-proto?style=flat-square&color=cb3837&label=npm)](https://www.npmjs.com/package/@cyaxios/tn-proto)
[![Runtimes](https://img.shields.io/badge/runtimes-Node%20%7C%20Browser%20%7C%20WASM-3178c6.svg?style=flat-square)](#one-core-every-language)
[![Also](https://img.shields.io/badge/also-Python-blue.svg?style=flat-square)](https://pypi.org/project/tn-proto/)
[![Keys](https://img.shields.io/badge/keys-non--custodial%20vault-brightgreen.svg?style=flat-square)](#non-custodial-vault-backup)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-green.svg?style=flat-square)](#license)

**`@cyaxios/tn-proto` keeps every record readable only by the people you've authorized - and leaves cryptographic proof that it did.** Fields are encrypted per reader, so the wrong people simply can't decrypt them; each entry is signed by your device and hash-chained, so anyone can verify offline - from the log file alone - who was allowed to read what, and that nothing was altered after the fact.

## Installation

```bash
npm install @cyaxios/tn-proto
```

The Rust core ships bundled in as WebAssembly: one install, no native toolchain, no separate package.

## Quickstart

The first run mints a ceremony under `./.tn/` - nothing to configure.

**TypeScript / Node**
```ts
import { tn } from "@cyaxios/tn-proto";

await tn.init();
tn.info("order.created", { order_id: "A100", amount: 4999 });
tn.warning("order.flagged", { order_id: "A100", reason: "hold" });

for (const entry of tn.read()) console.log(entry.level, entry.event_type, entry.fields);
await tn.close();
```
```text
info order.created { amount: 4999, order_id: 'A100' }
warning order.flagged { order_id: 'A100', reason: 'hold' }
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

**Python** - byte-identical records:
```python
import tn

tn.init()                                       # or tn.init("billing") for a named project
tn.info("order.created", order_id="A100", amount=4999)
for entry in tn.read():
    print(entry.level, entry.event_type, entry.fields)
```

Always `await tn.close()` on shutdown to flush handlers. Set `TN_NO_STDOUT=1` to silence the stdout echo of each entry.

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

| Verb | What it does |
|---|---|
| `await tn.init()` | resolve or create a ceremony and bind the module runtime |
| `await tn.use("name")` | open or create a named ceremony and get its handle (`const t = await tn.use("billing"); t.info(...)`); this is how you address a named project, and how you hold several at once |
| `tn.info` / `.warning` / `.error` / `.debug` | one signed, encrypted entry at that level |
| `tn.log("evt", {...})` | emits regardless of the level threshold, so it always writes; reach for it when you need a level outside debug/info/warning/error |
| `tn.read(opts?)` | iterate decoded `Entry` objects |
| `tn.watch(opts?)` | async-iterate the log live |
| `tn.export(opts, outPath)` / `tn.absorb(src)` | produce or install a `.tnpkg` bundle |
| `tn.scope({...}, () => {…})` | layer request-context fields onto every entry inside the callback (metadata that rides along; this is not a group) |
| `await tn.close()` | flush handlers and release the ceremony |

Every emit returns an `EmitReceipt` (`{ eventId, rowHash, sequence }`) acknowledging the write. The full signed, encrypted envelope is what lands in the log on disk (shown above); the receipt is the in-process acknowledgement, handy for correlating a write with a downstream action.

### Reading: all entries, this run, admin

```ts
for (const e of tn.read()) { /* default: every entry on disk (allRuns: true) */ }
for (const e of tn.read({ allRuns: false })) { /* only what THIS process emitted */ }
for (const e of tn.read({ log: "admin" })) {   // the admin log (ceremony lifecycle: tn.* events)
  console.log(e.level, e.event_type);
}
```
```text
info tn.ceremony.init
info tn.group.added
```

`tn.read({ verify: true })` re-checks every signature and the full hash chain as it reads, and throws the moment something doesn't add up. Pass `verify: "skip"` to drop invalid rows silently instead.

## The CLI

Installing the package gives you a `tn-js` command. It's non-interactive by default - safe to drop straight into CI and containers.

| Command | What it does |
|---|---|
| `tn-js init [name]` | provision identity + ceremony under `./.tn/` |
| `tn-js read [--all-runs]` | decoded entries to stdout |
| `tn-js info --event <type> [--field k=v]…` | emit one attested entry from the shell |
| `tn-js add_recipient <group> <name>` | mint a reader kit for someone, wrapped as a `.tnpkg` |
| `tn-js invite` | invite a reader (by email/label) |
| `tn-js group` | add / inspect groups |
| `tn-js rotate` | rotate group keys; emit one per-reader `.tnpkg` |
| `tn-js absorb` / `tn-js import` | install a `.tnpkg` someone sent you |
| `tn-js export` / `tn-js compile` / `tn-js bundle` | produce `.tnpkg` bundles from your keystore |
| `tn-js wallet` | vault: `status`, `link`, `restore`, `sync` |
| `tn-js account` / `tn-js vault` | manage the vault account / emit vault events |
| `tn-js streams` | list ceremonies under `./.tn/` |
| `tn-js validate` | validate the project's config tree |
| `tn-js show env` / `tn-js show profiles` | reflective inspection (secrets redacted) |
| `tn-js seal` / `tn-js verify` / `tn-js canonical` | attest / verify / canonicalize envelopes from stdin |

```bash
tn-js init                                   # provision in ./.tn/
tn-js info --event order.created --field order_id=A100 --field amount=4999
tn-js read --all-runs                        # include entries from prior runs
tn-js watch ./tn.yaml | jq .                 # follow the log live
```

## How log sharing works

You never share a password or a private key. Access is cryptographic:

- **Identity (DID).** Every device has its own identity - a public `did:key:z6Mk…` derived from its Ed25519 key. Private keys never leave the machine.
- **Groups.** Events land in named groups (default: `default`); each group is its own encrypted domain with its own reader list. Readers of `payments` can decrypt `payments` events, and only those.
- **Reader kits.** To let someone read a group, you mint a kit addressed to their DID and send it. They absorb it and can decrypt that group - and nothing else.
- **Revocation.** Revoke a reader and future entries are encrypted to exclude them; every other reader keeps working, no rekeying.

Grant access (TypeScript):
```ts
import { tn } from "@cyaxios/tn-proto";
await tn.init();
const result = await tn.admin.addRecipient("default", {
  recipientDid: "did:key:z6Mk…",            // the reader's real Ed25519 DID
  outPath: "./alice.btn.mykit",
});
console.log(result.leafIndex, result.kitPath);   // -> 1 ./alice.btn.mykit
```

Or one-shot from the CLI (mints the kit and wraps a `.tnpkg`):
```bash
$ tn-js add_recipient default alice
[tn add_recipient] wrote /your/cwd/alice.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:zLabel-alice
```

The CLI synthesizes a friendly **label DID** (`did:key:zLabel-alice`) from the name so you can try sharing without copying real keys around; production readers are addressed by their own `did:key:z6Mk…`.

Revoke when you need to:
```ts
await tn.admin.revokeRecipient("default", { leafIndex: 1 });
```

## Groups and field routing

A **group** is an encrypted domain with its own reader list; **routing** a field into it means that field's value is sealed to that group's readers and to no one else. One command creates the group and routes fields in a single step:

```bash
tn-js group add payments --fields order_id,amount,card_last4    # creates the group + routes the fields
```

From then on, any `tn.info(...)` carrying `order_id`, `amount`, or `card_last4` seals those into `payments`; every other field stays in `default`. The same in-process, in one call:

```ts
await tn.admin.ensureGroup("payments", { fields: ["order_id", "amount", "card_last4"] });

tn.info("order.created", { order_id: "A100", amount: 4999, note: "ship today" });
// order_id + amount  ->  sealed to 'payments'
// note               ->  'default'
```

You can also hand-edit the `groups:` and `fields:` blocks in `tn.yaml` (see [Configuration](#configuration-tnyaml)); the SDK picks up the change in the same process.

## Bundles (`.tnpkg`)

A `.tnpkg` is a signed zip with a manifest and body files - the unit everything is shared as. Produce one with `tn-js add_recipient` or `tn-js export`; absorb one programmatically:

```ts
// Reader: absorb merges it into your current ceremony (run tn.init() first).
await tn.init();
const receipt = await tn.absorb("./alice.tnpkg");
console.log(receipt.kind, receipt.acceptedCount, receipt.dedupedCount);   // -> kit_bundle 1 0
```

To produce a recipient bundle in code: `await tn.export({ bundle: { recipientDid: "did:key:z6Mk…", outPath: "./alice.tnpkg" } }, "./alice.tnpkg")`.

## Rotation

`tn-js rotate` writes a new generation of group keys and emits one `.tnpkg` per surviving reader. Hand each reader their file (vault push, CI artifact, email); they run `tn-js absorb`. A revoked reader isn't in the new generation, so they keep old entries but can't read anything after the rotation.

```bash
$ tn-js rotate
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

Unless you pass `--no-link`, the first `tn-js init` mints your device identity, pushes the encrypted keys + config, and prints a **claim link**:

```text
$ tn-js init demoproj
[tn init] Ceremony local_a82b34ec created at ./.tn/demoproj/tn.yaml
[tn init]   project: demoproj
[tn init]   cipher: btn
[tn init]   keystore: ./.tn/demoproj/keys

[tn init] Backed up to https://vault.tn-proto.org
[tn init]   vault_id:   01KTYX…                  # id of the pending backup
[tn init]   expires:    2026-06-13 17:57          # the claim link is good for ~24h

[tn init] CLAIM URL - open this in your browser to attach the project to your account:
  https://vault.tn-proto.org/claim/01KTYX…#k=••••••••

[tn init] Already have a vault account, or want to attach this project later?
[tn init]   1. Sign in at https://vault.tn-proto.org/account
[tn init]   2. On the Projects tab, mint a connect code
[tn init]   3. Run:  tn-js account connect <code> --yaml ./.tn/demoproj/tn.yaml
```

(`tn-js init` also writes a final `{"ok":true,"claim_url":"…",…}` JSON line to stdout, for scripting.)

**Open the claim link** and a vault page attaches this backup to your account (Google or passkey), so you can restore it on any machine later. Two parts of that URL matter:

- `/claim/01KTYX…` points at the encrypted backup this `init` just pushed.
- `#k=••••••••` is the **decryption key**, carried in the URL *fragment*. Browsers never send the fragment to the server, so the claim page decrypts in your browser and the vault still never sees your key. That is what keeps it zero-knowledge.

Treat the whole link like a password: anyone holding it (fragment included) can claim that backup, and it stops working after the `expires:` time. Already have an account? Skip the link and use the sign-in + connect-code steps it prints.

**Key recovery.** Sign in at <https://vault.tn-proto.org/account> (the dashboard also lets you invite readers by email and trigger rotations). To recover on a new machine:
```bash
tn-js wallet status          # is this machine linked, and to what
tn-js wallet restore         # rebuild every ceremony's keystore from your recovery phrase
```

**Turn it off.** You are never tied to the vault:
```bash
tn-js init --no-link                       # fully offline; never contacts a vault
export TN_NO_LINK=1                         # same, as an environment switch
export TN_VAULT_URL="https://my-vault…"     # or point at your own
```

## Profiles

A profile is a named bundle of three independent guarantees - pick the trade-off, not the knobs:

- **Encryption - always on.** Field values are encrypted into their groups in every profile. There is no plaintext mode; this is the floor.
- **Signing** - an Ed25519 signature from the writing device on each entry, proving authorship. The evidence profiles keep it; the lightweight ones drop it for speed.
- **Chaining (verification)** - the hash link from each entry to the one before it. This is what makes the log tamper-evident and ordered, and what `read({ verify: true })` checks. The evidence profiles keep it.

```ts
await tn.init(undefined, { profile: "audit" });
```

| Profile | Encrypt | Sign | Chain | Use it for |
|---|:---:|:---:|:---:|---|
| `transaction` *(default)* | ✓ | ✓ | ✓ | grants, payments, agent actions, security events - full evidence |
| `audit` | ✓ | ✓ | ✓ | normal business events; same evidence, buffered for throughput |
| `secure_log` | ✓ | ✓ | - | signed app logs where authorship matters more than ordering |
| `telemetry` | ✓ | - | - | high-volume traces / metrics; near-zero overhead, stdout |
| `stdout` | ✓ | - | - | dev / notebook scratchpad, encryption still on |

## Configuration (`tn.yaml`)

`tn.yaml` is **generated by `tn-js init`**, and the CLI and SDK keep it in sync for you (`tn-js group add`, `tn.admin.ensureGroup`, the vault verbs all write it). **You normally never edit it by hand - reach for a verb instead.** It is plain YAML, so you *can* hand-edit it once you know the schema, but a malformed file can break loading or field routing, so treat that as an advanced path. It is shown here in full (comments are explanatory; the emitted file has none) so you can see what the tools manage:

```yaml
ceremony:
  id: local_f2bb8224             # ceremony identifier
  mode: local                    # local | linked  (linked = backed by a vault)
  linked_vault: ''               # vault URL; empty when offline
  linked_project_id: ''          # vault-side project id; filled by `tn-js wallet link`
  sync_logs: false               # also sync ndjson logs to the vault
  cipher: btn                    # ceremony-wide cipher
  sign: true                     # Ed25519-sign every row
  admin_log_location: ./admin/default.ndjson   # tn.* admin events; read via tn.read({ log: "admin" })
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

A single `tn.info(...)` can fan one event into several groups, each encrypted to that group's readers only. Log and admin paths also accept **templated paths** (`{event_class}`, `{date}`, `{event_id}`, …) so events sort themselves on disk.

> **Every `tn.yaml` field - groups, field routing, ciphers, handlers, profiles, ceremony/link state - is documented in the [`tn.yaml` reference](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/yaml-reference.md).**

## Scoped lifecycle

For tests and short-lived processes that shouldn't leave a `./.tn/` behind, `tn.session()` mints a fresh ceremony in a private tempdir that is removed on `close()`:
```ts
const s = await tn.session();
s.info("order.created", { order_id: "A100" });
await s.close();              // tempdir removed; nothing left under ./.tn/
```

Layer contextual fields onto everything logged inside a block with `tn.scope`:
```ts
tn.scope({ request_id: "r-42" }, () => {
  tn.info("order.created", { order_id: "A100" });   // request_id rides along
});
```

For long-running services, call `await tn.init()` once at startup and `await tn.close()` on shutdown.

## Containers & CI

No home directory, no baking keys into an image. Set one secret - `TN_API_KEY` - and the container trades it with the vault for its keystore on first boot, then runs normally. If a keystore already exists on disk, that wins and the env var is ignored. Full guide: [running in containers and CI](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/deploy-containers.md).

## Environment variables

Everything has a sensible default; these override it. `tn-js show env` prints the full canonical surface (secrets redacted).

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

[`tn-skills`](https://github.com/cyaxios/tn-skills) teaches your AI coding agent to use TN correctly. With it installed, the agent routes PII into the right encrypted group, calls `tn.init` once at startup (not inside a request handler), never logs a secret like a CVV, and cites the right regulation when a file's domain matches one of its built-in industry kits - so agent-written code doesn't quietly tell the wrong thing to the wrong people.

Install it in Claude Code:
```text
/plugin marketplace add cyaxios/tn-skills
/plugin install tn-logging@tn-skills
```

For other AI tools, drop the repo's `AGENTS.md` into your agent. The bundled skills and industry kits are documented at <https://github.com/cyaxios/tn-skills>.

## One core, every language

The wire format is identical across Node, Python, and the browser, checked on every change - write in one, read in another.

| Runtime | Install |
|---|---|
| Node / TypeScript | `npm install @cyaxios/tn-proto` |
| Python | `pip install tn-proto` |
| Browser | the `@cyaxios/tn-proto/core` subpath (no Node deps) |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `tn.read()` shows entries from previous runs | the default is `allRuns: true`; pass `{ allRuns: false }` to scope to this run |
| `tn.watch()` shows no `tn.*` events | by design - pass `{ log: "admin" }` for ceremony events |
| `tn.usingRust()` is `false` | the WASM core attaches lazily on the first emit; check after emitting |
| `no ceremony found` on `tn.absorb` | absorb merges into an existing ceremony; run `tn.init()` first |

## Documentation

- [Getting started](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/getting-started.md) · [TypeScript cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-typescript.md) · [Python cookbook](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/cookbook-python.md)
- [Groups, readers, bundles, rotation](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/groups-readers-rotation.md) · [Running in containers and CI](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/deploy-containers.md)
- [Profiles](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/profiles.md) · [tn.yaml reference](https://github.com/cyaxios/tn-proto/blob/main/docs/guide/yaml-reference.md)

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
