# TN protocol: getting started

TN is an attested logging protocol. Every entry you write is encrypted,
hash-chained, and signed, so that later anyone holding the right key can read
it back and prove it was not altered. There are two implementations that
produce identical records: a Python SDK with the `tn` command, and a
TypeScript SDK with the `tn-js` command.

## Glossary

A few terms recur throughout, worth grounding before any code:

- **ceremony** - the on-disk project record under `.tn/<project>/`: its
  identity, keystore, and config. Called "project" in prose.
- **stream** - a named log within a project; `tn.use("name")` opens one.
- **group** - an encrypted domain with its own reader list; fields routed to
  it are sealed to those readers only.
- **reader kit / `.btn.mykit`** - one reader's decryption material for a group.
- **bundle / `.tnpkg`** - a signed zip that wraps a kit plus manifest for
  hand-off; what `tn.absorb` consumes.
- **DID** - `did:key:z6Mk...`, a device's public identity.
- **profile** - an encrypt/sign/chain preset stamped onto a ceremony.

## Install

```bash
# Python SDK + the tn command
pip install tn-proto

# TypeScript SDK + the tn-js command
npm install @cyaxios/tn-proto
```

```python
import tn
```

```typescript
import * as tn from "@cyaxios/tn-proto";
```

The Python import name is `tn` (pip package `tn-proto`); the npm package and
its import specifier are both `@cyaxios/tn-proto`.

To work from a source checkout of this repository instead:

```bash
git clone https://github.com/cyaxios/tn-proto.git
cd tn-proto

# Python. The SDK installs from source; its Rust crypto wheels (tn-core,
# tn-btn) resolve from TestPyPI:
pip install -e ./python --extra-index-url https://test.pypi.org/simple/

# TypeScript. Build the Rust core to WebAssembly once (needs a Rust
# toolchain and wasm-pack), then build the SDK:
cd crypto/tn-wasm
wasm-pack build --target nodejs --release
wasm-pack build --target web --release --out-dir pkg-web
cd ../../ts-sdk
npm install
npm run build
node bin/tn-js.mjs --help    # the CLI, runnable in place
```

## Quickstart in code

### Python

```python
import tn

# Create or open a project and make it the default logger.
# tn.init() uses or mints a default project; tn.init("demo") names one.
tn.init("demo")

# Log entries. Keyword arguments become encrypted fields.
tn.log("app.started", component="api")
tn.info("order.created", order_id="o_123", amount=4999, currency="USD")

# Read your log back, decrypted, as typed Entry objects.
for e in tn.read():
    print(e.event_type, e.sequence, e.fields)

tn.flush_and_close()
```

By default `tn.read()` returns ALL runs on disk; pass `all_runs=False`
(TypeScript `{ allRuns: false }`) to scope it to this process's run only.

```
app.started 1 {'component': 'api'}
order.created 1 {'amount': 4999, 'currency': 'USD', 'order_id': 'o_123'}
```

### TypeScript

```typescript
import * as tn from "@cyaxios/tn-proto";
import type { Entry } from "@cyaxios/tn-proto";

// tn.use creates or opens a project; tn.init makes it the default logger.
const t = await tn.use("demo");
await tn.init(t.yamlPath);

tn.log("app.started", { component: "api" });
tn.info("order.created", { order_id: "o_123", amount: 4999, currency: "USD" });

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

### Cross-language gotchas

The two SDKs mirror each other, but three things differ between them. Watch for
these:

- **`tn.init` argument differs by language.** Python `tn.init("billing")` opens
  a project by NAME; a value ending in `.yaml`/`.yml` or containing a path
  separator is treated as an explicit yaml path (advanced). TypeScript
  `tn.init(yamlPath)`'s argument is ALWAYS a yaml path; to open a NAMED project
  in TS use `await tn.use("billing")`. Never write `tn.init("billing")` in
  TypeScript - it would be read as a path.
- **Module verbs vs a handle.** The module-level `tn.log` / `tn.info` /
  `tn.read` only work after `tn.init()` sets the process default - they throw
  before that. A handle from `tn.use(...)` (or `Tn.init(...)`) works
  immediately: call `t.log(...)` / `t.read(...)` on it. This is why the
  TypeScript quickstart above is two calls: `const t = await tn.use("demo");
  await tn.init(t.yamlPath);` - `use` opens (or creates) the project, and
  `init` makes it the module default so the bare `tn.*` calls below it target
  that project.
- **Return values differ.** Python `tn.log` returns the written record (a dict
  whose `str()` is valid JSON); the leveled verbs (`tn.info` / `tn.warning` /
  `tn.error` / `tn.debug`) return `None`. TypeScript: every write verb returns
  an `EmitReceipt` (`{ eventId, rowHash, sequence }`), not the full record -
  re-read with `tn.read()` for the stored fields.

## Using the command line

Installing the Python package gives you a `tn` command (the TypeScript
package gives you `tn-js`, with the same verbs). Open a terminal and run the
full loop.

Create an identity and a project. Run this in an empty folder:

```bash
tn init mybackuptest
```

```
[tn init] Reusing identity at /home/you/.config/tn/identity.json
[tn init]   DID: did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS
[tn init] Ceremony local_861a3532 created at ./.tn/mybackuptest/tn.yaml
[tn init]   project: mybackuptest
[tn init]   cipher: btn
[tn init]   keystore: ./.tn/mybackuptest/keys

[tn init] Attached to your vault account (no browser needed).
[tn init]   project:  mybackuptest
[tn init]   linked:   https://vault.tn-proto.org/projects/01KTMC5A5J3RQ17CK5230TV558
[tn init]   uploaded: 0 file(s)
```

The `linked:` line is your project's page at the vault,
`https://vault.tn-proto.org`.

`tn init <name>` does two things. It creates one identity per machine (your
Ed25519 keypair and DID, reused for every project after the first) and a
project under `./.tn/<name>/`. You run it once per project.

By default it also backs that project up to your vault account, one entry per
project. The backup is an encrypted copy of the project's keys and config:
the vault is non-custodial and stores only ciphertext, so it cannot read your
keys. You restore a project from it on another machine, or after losing the
local `.tn/` directory, using your account passphrase or recovery phrase. The
vault is `https://vault.tn-proto.org` unless you have linked another (it falls
back to your saved `linked_vault`, then `$TN_VAULT_URL`).

To stay fully offline with no vault contact and no backup, pass `--no-link`:

```bash
tn init myproject --no-link
```

```
[tn init] Reusing identity at /home/you/.config/tn/identity.json
[tn init]   DID: did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS
[tn init] Ceremony local_5c55a621 created at ./.tn/myproject/tn.yaml
[tn init]   project: myproject
[tn init]   cipher: btn
[tn init]   keystore: ./.tn/myproject/keys
```

In code, `tn.init("myproject")` creates the same project on disk. A plain
script stays local; the vault backup runs automatically only inside a
notebook. Pass `link=True` to force the backup from a script, or `link=False`
to keep it offline.

Write a log entry. `--event` names it; each `--field k=v` adds one encrypted
field:

```bash
tn info --yaml ./.tn/myproject/tn.yaml --event order.created --field amount=4999 --field currency=USD
```

```
info: emitted event_type='order.created' level='info' fields=2
```

Read it back, decrypted:

```bash
tn read --yaml ./.tn/myproject/tn.yaml
```

```
2026-06-08T17:10:42.278832+00:00  info  order.created  amount='4999' currency='USD'
```

Every command takes `--yaml <path>` to choose which project to act on. Leave
it off and `tn` looks for `./tn.yaml` or `./.tn/default/tn.yaml`. Run any
command with `--help` to see its options, for example `tn info --help`.

As an advanced option, `tn.init` in code also accepts an explicit yaml path,
`tn.init("./.tn/demo/tn.yaml")`, to bind a project at a path of your choosing
rather than under `./.tn/<name>/`.

## Log levels

`tn.log` records an entry with a custom, severity-less level and always writes,
regardless of the level threshold; the leveled verbs respect the threshold. It
is NOT an alias for `tn.info`. The severity verbs set a level:

```python
tn.debug("cache.miss", key="k")
tn.info("order.created", id="o_1")
tn.warning("quota.near", used=0.92)
tn.error("charge.failed", txn="t_42")
```

The levels, lowest to highest, are `debug`, `info`, `warning`, `error`. A
threshold drops anything below it: set it with `tn.set_level("info")` in code
or `ceremony.log_level` in the yaml, and `debug` entries are then not written.
`tn.log` has no level and is always written.

From the CLI, `tn info` writes at `info`; pass `--level` to choose another:

```bash
tn info --yaml ./.tn/myproject/tn.yaml --event quota.near --level warning --field used=0.92
```

## What a DID is

A DID (Decentralized Identifier) is a name for an identity that needs no
central registry to issue or verify. TN uses the `did:key` method, where the
identifier is the public key itself, encoded into the string.

A TN DID looks like `did:key:z6Mk...`. The part after `did:key:` is the
base58-encoded Ed25519 public key of a TN identity. Because the public key is
embedded in the identifier, anyone can verify a signature from that DID
without looking anything up: they decode the key straight out of the string.

When you run `tn init`, TN generates an Ed25519 keypair for the device and
derives your DID from the public half. The private half stays in
`.tn/<project>/keys/local.private` and never leaves your machine. The DID is
the part you share: it is how others address a log entry to you as a
recipient, and how readers verify that an entry you wrote is yours.

You do not register a DID anywhere. You generate it locally with `tn init`.

## Sharing a log with someone else

You never hand out your private key. To let someone read a group, you mint a
reader kit addressed to their DID and deliver it as a `.tnpkg` file. The kit
grants read access to that one group and nothing else.

Producer side, mint and package a kit:

```bash
tn add_recipient default did:key:z6MkOther...   # mint a kit + write a .tnpkg
tn bundle did:key:z6MkOther... out.tnpkg         # package a kit for a recipient
tn invite did:key:z6MkOther... invite.zip        # mint a tn-invite-<id>.zip
```

Recipient side, install the delivered kit:

```bash
tn absorb out.tnpkg            # install a kit into the active project
```

```
absorb: kind=kit_bundle accepted=1
```

In code:

```python
tn.admin.add_recipient("default", recipient_did="did:key:z6MkOther...")
tn.absorb("out.tnpkg")
```

### Removing access

To drop a recipient, revoke them. That is all it takes:

```python
tn.admin.revoke_recipient("default", recipient_did="did:key:z6MkOther...")
```

Revocation moves that recipient's leaf into the group's revoked set. From then
on, every entry is encrypted to a cover that excludes them, so their kit can no
longer read new entries. This is the point of the broadcast cipher: the other
recipients are unaffected and keep the kits they already have. There is no
re-key and nothing to redistribute. Revocation is forward-only; entries written
before it stay readable by whoever could read them then.

Rotation (`tn.admin.rotate("default")`) is a separate, heavier operation. It
mints a fresh publisher seed for the group, which you would do to reset the
group's keys after a suspected compromise of the publisher state. It re-keys
everyone, so surviving recipients receive new kits. You do not need it to
remove a recipient.

## CLI reference

`tn` is the Python command; `tn-js` is the TypeScript command. A few Python
capabilities are reached through a module (`python -m tn.watch`) or the code
API rather than a `tn` subcommand; those are noted. The code columns show the
function each verb calls.

| Command | Python CLI | TypeScript CLI | Description | Python code | TypeScript code |
|---|---|---|---|---|---|
| init | `tn init <project>` | `tn-js init [<yaml>]` | Create identity + project at `./.tn/<project>/`; back it up to the vault unless `--no-link`. | `tn.init("demo")` / `tn.init()` | `await tn.use("demo")` |
| info / log | `tn info --event <t> --field k=v` | `tn-js info --event <t> --field k=v` | Append one attested entry. | `tn.info("evt", k=v)` / `tn.log("evt", k=v)` | `tn.info("evt", {k:v})` / `tn.log("evt", {k:v})` |
| read | `tn read [--all-runs]` | `tn-js read [--compact]` | Print the log, decrypted. | `for e in tn.read(): ...` | `for (const e of tn.read()) ...` |
| watch | `python -m tn.watch <yaml> [--once --since]` | `tn-js watch [--since --verify --poll --once]` | Tail the log, one entry per line. | `tn.watch(since=...)` | `tn.watch({ since })` |
| streams | `tn streams [--format]` | `tn-js streams` | List projects under `./.tn`. | `tn._layout.list_ceremonies_on_disk()` | `listCeremonies()` |
| validate | `tn validate` | `tn-js validate` | Load every project and report validity. | (CLI) | (CLI) |
| show env | `tn show env [--format]` | `tn-js show env` | Print the resolved config. | (CLI) | (CLI) |
| show profiles | `tn show profiles [--format]` | `tn-js show profiles` | Print the profile catalog. | `tn._profiles.get(name)` | (CLI) |
| group add | `tn group add <name> [--fields]` | `tn-js group add <name>` | Add a group to a project. | `tn.ensure_group(cfg, "name", fields=[...])` | `tn.admin.ensureGroup("name", {})` |
| add_recipient | `tn add_recipient <group> <did>` | `tn-js add_recipient <group> <did>` | Mint a kit and write a `.tnpkg`. | `tn.pkg.bundle_for_recipient(did, out, groups=["g"])` | `tn.pkg.bundleForRecipient({...})` |
| admin add-recipient | code / `tn add_recipient` | `tn-js admin add-recipient --out <kit>` | Mint a reader kit for a recipient. | `tn.admin.add_recipient("g", recipient_did=did)` | `tn.admin.addRecipient("g", {...})` |
| admin revoke-recipient | code / `python` | `tn-js admin revoke-recipient --leaf <n>` | Revoke a recipient leaf in a group. | `tn.admin.revoke_recipient("g", recipient_did=did)` | `tn.admin.revokeRecipient("g", {...})` |
| admin revoked-count | code | `tn-js admin revoked-count` | Count revoked leaves in a group. | `tn.admin.revoked_count("g")` | `tn.admin.revokedCount("g")` |
| rotate | `tn rotate <group>` | `tn-js admin rotate` | Re-key a group, issue fresh kits to survivors. | `tn.admin.rotate("g")` | `tn.admin.rotateGroup("g")` |
| bundle | `tn bundle <did> <out>` | `tn-js bundle <recipient> <out>` | Package a kit for an existing recipient. | `tn.pkg.bundle_for_recipient(did, out)` | `tn.pkg.bundleForRecipient({...})` |
| invite | `tn invite <did> <out.zip>` | (none) | Mint a `tn-invite-<id>.zip` (kit + manifest). | `tn.admin.add_recipient(..., raw=True)` + zip | (none) |
| compile | `tn compile --keystore <d> --out <f>` | `tn-js compile --keystore <d> --out <f>` | Package `.btn.mykit` files into a `.tnpkg`. | `tn.compile.compile_kit_bundle(...)` | `compileKitBundle(...)` |
| absorb | `tn absorb <pkg>` | `tn-js absorb <pkg>` | Install a `.tnpkg` into the active project. | `tn.absorb(path)` | `tn.pkg.absorb(src)` |
| inbox accept | `python -m tn.inbox accept <zip>` | `tn-js inbox accept <zip>` | Accept an invitation zip and install its kit. | `tn.inbox.accept(zip, yaml)` | (CLI) |
| inbox list-local | `python -m tn.inbox list-local` | `tn-js inbox list-local` | List downloaded `tn-invite-*.zip` files. | `tn.inbox.list_local(dir)` | (CLI) |
| seal | `tn seal` | `tn-js seal` | Sign one public-only envelope from stdin. | (crypto primitives) | (crypto primitives) |
| verify | `tn verify` | `tn-js verify` | Recompute the row hash and check the signature. | (crypto primitives) | (crypto primitives) |
| canonical | `tn canonical` | `tn-js canonical` | Emit the canonical bytes of each stdin line. | `tn.canonical._canonical_bytes(v)` | `canonicalize(v)` |
| wallet status | `tn wallet status` | `tn-js wallet status` | Print identity + project status. | `Identity.load(...)` | `tn.wallet.status(yamlPath)` |
| wallet link | `tn wallet link --vault <url>` | `tn-js wallet link <url>` | Create a vault project, mark the project linked. | `tn.wallet.link_ceremony(cfg, client)` | `tn.wallet.link(client, yamlPath)` |
| wallet unlink | `tn wallet unlink` | `tn-js wallet unlink` | Mark the project local again. | `tn.admin.set_link_state(cfg, mode="local")` | `tn.wallet.unlink(yamlPath)` |
| wallet sync | `tn wallet sync [--pull --push-only]` | `tn-js wallet sync` | Two-way vault sync: pull, absorb, push. | `tn.wallet.sync_ceremony(...)` | `tn.wallet.sync(opts)` |
| wallet pull-prefs | `tn wallet pull-prefs` | `tn-js wallet pull-prefs` | Refresh account prefs from the vault. | `VaultClient.get_prefs()` | (CLI) |
| wallet restore | `tn wallet restore [--mnemonic]` | `tn-js wallet restore` | Restore projects from the vault. | `tn.wallet.restore_ceremony(...)` | `tn.wallet.restore(client, opts)` |
| wallet export-mnemonic | `tn wallet export-mnemonic` | `tn-js wallet export-mnemonic` | Re-display the recovery phrase. | `Identity.mnemonic_stored` | (CLI) |
| account connect | `tn account connect <code>` | `tn-js account connect <code>` | Bind this device to a vault account. | `vault_client.redeem_connect_code(...)` | (CLI) |
| vault link (event) | `tn vault link <vault-did> <project-id>` | `tn-js vault link <vault-did> <project-id>` | Append a `tn.vault.linked` entry to the log. | `tn.vault.link(vault_did, project_id)` | `tn.vault.link(vaultDid, projectId)` |
| vault unlink (event) | `tn vault unlink <vault-did> <project-id>` | `tn-js vault unlink <vault-did> <project-id>` | Append a `tn.vault.unlinked` entry to the log. | `tn.vault.unlink(...)` | `tn.vault.unlink(...)` |
| firehose | `tn firehose stats\|list\|get` | `tn-js firehose stats\|list\|get` | Firehose tenant stats / list / fetch. Gated by env. | (CLI) | (CLI) |

`wallet sync`, `wallet link`, `wallet restore`, `account connect`, `firehose`,
and `inbox accept` against a vault need a running vault server. Everything
else works against a local project with no network.

Profiles (`transaction`, `audit`, `secure_log`, `telemetry`, `stdout`) decide
how much signing, chaining, and durability each entry carries. See
[profiles.md](profiles.md).

## How it works

### Everything is encrypted

When you write an entry, its fields are encrypted per group before they touch
disk. A group is a named audience; `default` is created for you. The record
on disk holds ciphertext, not your data, and reading it back requires a key
for that group. Fields you mark `public` in the config are the only ones
written in the clear.

The default cipher is BTN, a broadcast scheme: one encrypted block can be read
by many recipients, each holding their own reader kit, without re-encrypting
per person. The mechanics are in [protocol.md](protocol.md).

### The .tn directory

A project lives under `./.tn/<project>/`. It holds your keys and your log
files.

| Path | What it is |
|---|---|
| `tn.yaml` | The project config: groups, field routing, handlers, cipher, link state. Generated and kept in sync by the CLI and SDK; hand-editable. Fields in [yaml-reference.md](yaml-reference.md). |
| `keys/local.private` | Your Ed25519 device private seed. This file is your identity. Never share it. |
| `keys/local.public` | Your Ed25519 device public key, the basis of your DID. |
| `keys/index_master.key` | Master key. Per-group search-index keys derive from it. |
| `keys/<group>.btn.state` | Publisher state for a group: the secret used to mint kits and encrypt that group. |
| `keys/<group>.btn.mykit` | Your own reader kit for a group, so you can read what you wrote. |
| `logs/<stream>.ndjson` | The main data log for a stream (`logs/default.ndjson` unless you named one with `tn.use`). Your events land here; this is what `tn.read()` returns. |
| `admin/<stream>.ndjson` | The admin log. Protocol events (`tn.ceremony.init`, `tn.recipient.added`, `tn.rotation.completed`, ...) land here. Read it with `tn.read(log="admin")`; the exact filename is recorded in the yaml, so never hardcode it. |
| `streams/<stream>.yaml` | Per-stream overlay config, minted by `tn.use(stream)`. |
| `vault/` | Sync state, used only when the project is linked to a vault. |

Event types that start with `tn.` are reserved protocol events and route to
the admin log; name your own events anything else and they land in the main
log.

## See also

- [profiles.md](profiles.md) - the logging profiles and how to set them.
- [yaml-reference.md](yaml-reference.md) - every field of `tn.yaml`.
- [cookbook-python.md](cookbook-python.md) - every Python verb and command.
- [cookbook-typescript.md](cookbook-typescript.md) - the same for TypeScript.
- [protocol.md](protocol.md) - the on-the-wire record format and the BTN cipher.
- [groups-readers-rotation.md](groups-readers-rotation.md) - encrypted groups, granting/revoking readers, `.tnpkg` bundles, and key rotation.
- [deploy-containers.md](deploy-containers.md) - the `TN_API_KEY` bootstrap for containers/CI, disk-wins-over-env, and identity paths.
- [advanced-usage.md](advanced-usage.md) - reading modes (`all_runs`), scoped lifecycles (`tn.session`), templated log paths, and the cross-language guarantee.
