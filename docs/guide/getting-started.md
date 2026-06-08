# TN protocol: getting started

TN is an attested logging protocol. Every entry you write is encrypted,
content-addressed, hash-chained, and signed, so that later anyone holding
the right key can read it back and prove it was not altered. There are two
implementations that produce byte-identical records: a Python SDK + `tn`
CLI, and a TypeScript SDK + `tn-js` CLI.

This guide is the just-the-facts entry point. Deeper references:

- [yaml-reference.md](yaml-reference.md) — every field of `tn.yaml`.
- [cookbook-python.md](cookbook-python.md) — every Python verb and CLI command, with real output.
- [cookbook-typescript.md](cookbook-typescript.md) — the same for TypeScript.
- [protocol.md](protocol.md) — the on-the-wire record format and the BTN cipher.

---

## 1. Core concepts

### Everything is encrypted

When you write an entry, its fields are encrypted per **group** before they
touch disk. A group is a named audience (`default` is created for you). The
record that lands in your log file holds ciphertext, not your data. Reading
it back requires a key for that group. Fields you explicitly mark `public`
in the config are the only ones written in the clear.

The default cipher is **BTN**, a broadcast scheme: one encrypted block can be
read by many recipients, each holding their own reader kit, without
re-encrypting per person. The cipher mechanics are in
[protocol.md](protocol.md).

### The `.tn` directory is your keys and your default logger

A ceremony lives under `./.tn/<project>/`. Two things live there: the keys
that are your identity and your group ciphers, and the log files that are
your default logger output.

```
.tn/<project>/
  tn.yaml                     the ceremony config (audiences, fields, handlers)
  keys/                       YOUR KEYS — never share this directory
    local.private             Ed25519 device private seed (your identity)
    local.public              Ed25519 device public key
    index_master.key          master key; per-group search-index keys derive from it
    default.btn.state         BTN publisher state for the "default" group (publisher secret)
    default.btn.mykit         your own reader kit for "default" (lets you read your own log)
    tn.agents.btn.state       publisher state for the reserved tn.agents policy group
    tn.agents.btn.mykit       your reader kit for tn.agents
  logs/                       YOUR DEFAULT LOGGER — main data log (logs/tn.ndjson)
  admin/                      the admin log (admin.ndjson): ceremony/recipient/rotation events
  vault/                      vault sync state (only used when linked to a vault)
```

The split that matters in day-to-day use:

- **Your data events** (event types with no `tn.` prefix, e.g. `order.created`)
  go to the main log under `logs/` and are what `tn.read()` returns.
- **Protocol events** (the reserved `tn.` prefix, e.g. `tn.ceremony.init`,
  `tn.group.added`, `tn.recipient.added`, `tn.rotation.completed`) go to the
  admin log under `admin/`. Do not use the `tn.` prefix for your own events
  or they will be routed to the admin log.

### How keys reach other people

You never hand out `keys/local.private`. To let someone read a group, you
**mint a reader kit for their DID** and deliver it. The kit is derived from
the group's BTN publisher state and only grants read access to that group.

Producer side (mint + package a kit):

- `add_recipient <group> <did>` — one-shot: mint a kit and write a `.tnpkg`.
- `bundle <did> <out>` — package a kit bundle for an existing recipient.
- `invite <did> <out>` — mint a `tn-invite-<id>.zip` (kit + manifest) to send.
- `compile --keystore <dir> --out <file.tnpkg>` — package existing kits.

Recipient side (install the kit):

- `absorb <package.tnpkg>` — install a delivered kit into the active ceremony.
- `inbox accept <zip>` (TypeScript) — accept an invitation zip locally.

To remove someone, **rotate** the group (`rotate <group>` / `admin rotate`):
the group gets a new epoch, surviving recipients receive a fresh `.tnpkg`,
and the revoked recipient can no longer read entries written after the
rotation. Records written before the rotation stay readable by the kits that
were valid then.

A recipient DID is a `did:key:...` string, which is just the public half of
that party's TN identity. They generate it with their own `tn init`.

---

## 2. Install

The PyPI package is `tn-proto`; the npm package is `tn-proto`.

```bash
pip install tn-proto      # Python SDK + the `tn` CLI
npm install tn-proto      # TypeScript SDK + the `tn-js` CLI
```

```python
import tn
```

```typescript
import * as tn from "tn-proto";
```

The Python import name is `tn`; the npm package and its import specifier are
both `tn-proto`. Until the beta is published to the registries, install from a
source checkout of this repo (`pip install -e python/`, and `npm install` in
`ts-sdk/`).

---

## 3. CLI reference (Python and TypeScript)

Python CLI is `tn` (or `python -m tn.cli`). TypeScript CLI is `tn-js`. A `—`
means that side does not expose the command at the same path. Full worked
examples with real output are in the two cookbooks; the code columns show
the equivalent SDK call where one exists.

| CLI (Python) | CLI (TypeScript) | Key options | Description | Python code | TypeScript code |
|---|---|---|---|---|---|
| `tn init [name]` | `tn-js init [name]` | `--cipher btn\|jwe`, `--link <url>`, `--no-link`, `--words N`, `--force`, `--skip-confirm`, `--keep-mnemonic` | Scaffold identity + ceremony at `./.tn/<project>/`. Universal entry point. | `tn.init("./.tn/demo/tn.yaml")` | `tn.init("./.tn/demo/tn.yaml")` |
| `tn info` | `tn-js info` | `--yaml`, `--event <type>`, `--level`, `--field k=v` (repeatable) | Append one attested entry from the CLI. | `tn.log("evt", k=v)` / `tn.info("evt", k=v)` | `tn.log("evt",{k:v})` / `tn.info("evt",{k:v})` |
| `tn read` | `tn-js read` | `--yaml`, `--log`, (TS) `--compact`, (PY) `--all-runs` | Print the log in flat decrypted form. | `for e in tn.read(): ...` | `for (const e of tn.read()) ...` |
| — | `tn-js watch` | `--since start\|now\|<seq>\|<iso>`, `--verify`, `--poll <ms>`, `--once` | Tail the log, one decoded entry per line. | — | `tn.watch({since:"now"})` |
| `tn streams` | `tn-js streams` | (PY) `--project-dir`, `--format human\|json` | List ceremonies under `./.tn`. | — | — |
| `tn validate` | `tn-js validate` | (PY) `--project-dir` | Load every ceremony under `./.tn` and report validity. | — | — |
| `tn show env` | `tn-js show env` | `--format human\|env\|json`, (TS) `--yaml` | Print the resolved ceremony config / TN_* env surface. | — | — |
| `tn show profiles` | `tn-js show profiles` | `--format human\|json` | Print the curated profile catalog. | — | — |
| `tn group add <name>` | `tn-js group add <name>` | `--fields a,b,c`, `--cipher btn\|jwe`, `--yaml` | Add a group to an existing ceremony. | `tn.ensure_group(cfg, "name", fields=[...])` | (CLI) |
| `tn add_recipient <group> <did>` | `tn-js add_recipient <group> <did>` | `--out`, `--yaml`, `--seal-for-recipient` | One-shot: mint a reader kit and write a `.tnpkg`. | `tn.admin.add_recipient("group", recipient_did=did)` | (CLI) |
| — | `tn-js admin add-recipient` | `--yaml`, `--group`, `--out <kit>`, `--recipient-did` | Mint a reader kit for a new recipient leaf. | `tn.admin.add_recipient(...)` | (CLI) |
| — | `tn-js admin revoke-recipient` | `--yaml`, `--group`, `--leaf <index>`, `--recipient-did` | Revoke a recipient leaf in a group. | — | (CLI) |
| — | `tn-js admin revoked-count` | `--yaml`, `--group` | Report the count of revoked leaves. | — | (CLI) |
| `tn rotate <group>` | `tn-js admin rotate` | `--groups a,b,c`, `--out <dir>`, `--yaml` | Rotate group keys, bump epoch, write a `.tnpkg` per surviving recipient. | `tn.admin.rotate("group")` | (CLI) |
| `tn bundle <did> <out>` | `tn-js bundle <did> <out>` | `--yaml`, `--groups a,b`, `--seal-for-recipient` | Mint a kit_bundle `.tnpkg` for one recipient. | `tn.export(out, kind="kit_bundle", to_did=did, groups=[...])` | (CLI) |
| `tn invite <did> <out>` | — | `--group`, `--yaml`, `--from-email`, `--note` | Mint a `tn-invite-<id>.zip` (kit + manifest). | (CLI) | — |
| `tn compile` | `tn-js compile` | `--keystore <dir>`, `--out <file.tnpkg>`, `--kit <group>` (repeatable), `--label`, `--full` | Package `*.btn.mykit` files into an importable `.tnpkg`. | (CLI) | (CLI) |
| `tn absorb <package>` | `tn-js absorb <package>` | `--yaml`, `--allow-self-absorb` | Install a `.tnpkg` into the active ceremony. | `tn.absorb(path)` | (CLI) |
| — | `tn-js inbox accept <zip>` | `--yaml` | Accept an invitation zip and install its kit. | — | (CLI) |
| — | `tn-js inbox list-local` | `--dir <path>` | List downloaded `tn-invite-*.zip` files (no vault contact). | — | (CLI) |
| `tn seal` | `tn-js seal` | stdin JSON -> ndjson | Sign one public-only envelope per stdin line. | (CLI) | (CLI) |
| `tn verify` | `tn-js verify` | stdin ndjson | Recompute row hash and check the signature. | (CLI) | (CLI) |
| `tn canonical` | `tn-js canonical` | stdin JSON | Emit the deterministic canonical UTF-8 bytes of each line. | (CLI) | (CLI) |
| `tn wallet status` | `tn-js wallet status` | (positional `yaml`) | Print identity, link state, and active ceremony. | `tn.wallet.status(...)` | (CLI) |
| `tn wallet link` | `tn-js wallet link <url>` | `--vault`, (TS) `--name`, `--yaml` | Create a vault project and flip ceremony to linked. | `tn.wallet.link(...)` | (CLI) |
| `tn wallet unlink` | `tn-js wallet unlink` | `--yaml` | Flip ceremony back to local (vault project untouched). | `tn.wallet.unlink(...)` | (CLI) |
| `tn wallet sync` | `tn-js wallet sync` | `--pull`, `--push-only`, `--drain-queue`, `--passphrase`, `--vault` | Two-way vault sync: pull + absorb, then push the body backup. | `tn.wallet.sync(...)` | (CLI) |
| `tn wallet pull-prefs` | `tn-js wallet pull-prefs` | `--vault` | Refresh the identity's account prefs from the vault. | (CLI) | (CLI) |
| `tn wallet restore` | `tn-js wallet restore` | `--vault`, `--out`, `--mnemonic`/`--mnemonic-file`, `--all-projects`, `--passphrase` | Restore ceremonies from the vault. | (CLI) | (CLI) |
| `tn wallet export-mnemonic` | `tn-js wallet export-mnemonic` | `--yes` | Re-display the BIP-39 phrase (needs `--keep-mnemonic` ceremony). | (CLI) | (CLI) |
| `tn account connect <code>` | `tn-js account connect <code>` | `--yaml`, `--vault`, `--identity` | Redeem a vault connect code; bind device DID to the account. | (CLI) | (CLI) |
| `tn vault link <did> <pid>` | `tn-js vault link <did> <pid>` | `--yaml` | Append a `tn.vault.linked` attested event to the log. | `tn.vault.link(...)` | (CLI) |
| `tn vault unlink <did> <pid>` | `tn-js vault unlink <did> <pid>` | `--reason`, `--yaml` | Append a `tn.vault.unlinked` attested event to the log. | `tn.vault.unlink(...)` | (CLI) |
| — | `tn-js firehose stats\|list\|get` | `<tenant>`, `--did`, `--out` | Firehose tenant stats / object list / fetch (gated on `TN_FIREHOSE_URL`). | — | (CLI) |

Commands marked `(requires a linked vault)` in the cookbooks (`wallet sync`,
`wallet link/restore`, `account connect`, `firehose`, `inbox accept`) talk to
a running vault server; the offline commands work against a local ceremony
with no network.

---

## 4. Quickstart

### Python

```python
import tn

# 1. init: load or create a ceremony, open its default logger
tn.init("./.tn/demo/tn.yaml")

# 2. log: keyword args become typed, encrypted fields
tn.log("app.started", component="api")
tn.info("order.created", order_id="o_123", amount=4999, currency="USD")

# 3. read: tn.read() yields typed Entry objects from the main log
for e in tn.read():
    print(e.event_type, e.sequence, e.fields)

tn.flush_and_close()
```

```
app.started 1 {'component': 'api'}
order.created 1 {'amount': 4999, 'currency': 'USD', 'order_id': 'o_123'}
```

Read the same log from the CLI:

```bash
tn read --yaml ./.tn/demo/tn.yaml
```

### TypeScript

```typescript
import * as tn from "tn-proto";
import type { Entry } from "tn-proto";

// 1. create/attach a ceremony, then make it the process default logger.
//    tn.use(name) mints or attaches; tn.init(yamlPath) sets the default.
const t = await tn.use("demo");
await tn.init(t.config().yamlPath);

// 2. log: the argument after the event type is a fields object
tn.log("app.started", { component: "api" });
tn.info("order.created", { order_id: "o_123", amount: 4999, currency: "USD" });

// 3. read: iterate typed Entry objects from the main log
for (const e of tn.read()) {
  const entry = e as Entry;
  console.log(entry.event_type, entry.sequence, JSON.stringify(entry.fields));
}
await tn.close();
```

```
app.started 1 {"component":"api"}
order.created 1 {"amount":4999,"currency":"USD","order_id":"o_123"}
```

Read the same log from the CLI:

```bash
tn-js read --yaml ./.tn/demo/tn.yaml
```

The exact runnable forms, including how each SDK flushes and the precise
receipt shape returned by `log`/`info`, are in
[cookbook-python.md](cookbook-python.md) and
[cookbook-typescript.md](cookbook-typescript.md).

---

## 5. The `.tn` directory, element by element

| Path | What it is |
|---|---|
| `tn.yaml` | The ceremony config: groups (audiences), field routing, handlers, cipher, and the link state. Full field list in [yaml-reference.md](yaml-reference.md). |
| `keys/local.private` | Your Ed25519 device private seed. This file is your identity. Never share it. |
| `keys/local.public` | Your Ed25519 device public key (the basis of your `did:key:...`). |
| `keys/index_master.key` | Master key. Per-group equality-search index keys are derived from it via HKDF. |
| `keys/<group>.btn.state` | BTN publisher state for a group. Holds the publisher secret used to mint reader kits and encrypt that group's records. |
| `keys/<group>.btn.mykit` | Your own reader kit for a group, so you can read back what you wrote. |
| `keys/<group>.btn.mykit.retired.<epoch>` | A reader kit retained from before a rotation, so prior-epoch records stay readable. |
| `keys/*.lock` | Advisory file locks that serialize keystore and log writes. |
| `logs/tn.ndjson` | The main data log. Your non-`tn.` events land here; this is what `tn.read()` returns. |
| `admin/admin.ndjson` | The admin log. Protocol events (`tn.ceremony.init`, `tn.group.added`, `tn.recipient.added`, `tn.rotation.completed`, `tn.vault.linked`, ...) land here. |
| `vault/` | Sync state used only when the ceremony is linked to a vault. |

Both log files are append-only NDJSON: one JSON record per line, hash-chained
to the record before it. The record format is documented in
[protocol.md](protocol.md).
