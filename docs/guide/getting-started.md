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
import { tn } from "@cyaxios/tn-proto";
```

The Python import name is `tn` (pip package `tn-proto`); the npm package and
its import specifier are both `@cyaxios/tn-proto`. The `{ tn }` named import
gives you the same `tn.*` surface as Python.

## Deploy on Vercel, Lovable, and other serverless hosts

Serverless and edge runtimes (Vercel, AWS Lambda, Netlify, Cloud Run, Azure
Functions, and AI app builders like Lovable / v0 / Bolt that deploy onto them)
have an **ephemeral, mostly read-only filesystem** and a **fresh container per
cold start**. Two adjustments make TN work there:

1. Point TN's state at a writable directory — `/tmp` on every major platform.
2. Connect the deploy to your account. `tn.init()` detects a serverless runtime
   and, by default, backs the project up and returns a **claim link** you open
   once in a browser. For fully unattended deploys, provide a credential instead.

### Parameters

| Variable | Purpose | Serverless value |
|---|---|---|
| `TN_IDENTITY_DIR` | where the device identity (`identity.json`) is written | `/tmp/tn` |
| `TN_HOME` | shared TN state root | `/tmp/tn` |
| `TN_VAULT_URL` | vault base URL (optional) | unset → hosted vault |
| `TN_API_KEY` | unattended cold-start credential (no browser) | your key, in the host's env / secrets |
| `TN_NO_LINK` | set to `1` to stay fully offline (no vault contact) | unset |

### Option A — claim link (a person attaches the deploy, once)

On a serverless runtime `tn.init()` auto-links by default: it backs the project
up and exposes a claim URL on the returned instance as `tn.claimUrl`. Surface
it, open it once, sign in — the deploy is now attached to your account. Later
cold starts authenticate with the device key and need no human step.

```ts
// app/api/tn/route.ts  (Vercel route handler) — copy/paste
import { tn } from "@cyaxios/tn-proto";

// Serverless filesystems are read-only except /tmp.
process.env.TN_IDENTITY_DIR ||= "/tmp/tn";
process.env.TN_HOME ||= "/tmp/tn";

export async function GET() {
  const t = await tn.init();               // mints + auto-links on serverless
  tn.info("page.viewed", { path: "/" });   // your first attested event
  return Response.json({ claim: t.claimUrl }); // open this URL once to connect
}
```

```python
# Python serverless handler (AWS Lambda, Cloud Run, …) — copy/paste
import os, tn

os.environ.setdefault("TN_IDENTITY_DIR", "/tmp/tn")
os.environ.setdefault("TN_HOME", "/tmp/tn")

def handler(event, context):
    tn.init()                       # mints + auto-links on serverless
    tn.info("page.viewed", {"path": "/"})
    return {"ok": True}             # the claim URL is printed to the function logs
```

### Option B — no browser (CI and fully unattended deploys)

When no human will ever open a link, provision with a credential. Set
`TN_API_KEY` in the host's environment (the durable cold-start credential — it
provisions the keystore from a sealed bundle on first run), or enroll the deploy
once with a connect code:

```bash
# In your host's environment / secret store:
export TN_API_KEY="tn_apikey_…"
export TN_IDENTITY_DIR="/tmp/tn"
export TN_HOME="/tmp/tn"
# …then tn.init() runs unattended, no claim link needed.
```

```bash
# Or enroll a running deploy from your terminal with a connect code:
tn auth connect tn_connect_xxxxxxxx
```

Full sign-in story: [Authentication & accounts](auth.md). Every parameter, with
precedence and defaults: [Environment variables](environment-variables.md).

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
```

Handlers flush on interpreter exit, so a short script needs no explicit close.

By default `tn.read()` returns ALL runs on disk; pass `all_runs=False`
(TypeScript `{ allRuns: false }`) to scope it to this process's run only.

```
app.started 1 {'component': 'api'}
order.created 1 {'amount': 4999, 'currency': 'USD', 'order_id': 'o_123'}
```

### TypeScript

```typescript
import { tn, type Entry } from "@cyaxios/tn-proto";

// tn.init opens (or creates) the project by name and makes it the default.
await tn.init("demo");

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

### Cross-language notes

`tn.init` takes a project name or a `.yaml` path in both languages.
`tn.init("billing")` opens or creates the project at `.tn/billing/`; a value
ending in `.yaml` / `.yml` binds that explicit file. Python `tn.init` is
synchronous and returns the bound client; TypeScript `tn.init` returns a
`Promise` you `await`.

What each write verb returns:

| Verb | Python | TypeScript |
|---|---|---|
| `tn.log` | the written record — a `dict` whose `str()` is valid JSON | an `EmitReceipt`: `{ eventId, rowHash, sequence }` |
| `tn.info` / `tn.warning` / `tn.error` / `tn.debug` | `None` | an `EmitReceipt`: `{ eventId, rowHash, sequence }` |
| `tn.read` / `tn.watch` | an iterator of `Entry` | an iterator of `Entry` |

To read the stored fields of an entry you just wrote, iterate `tn.read()` — in
both languages it yields typed `Entry` objects with `event_type`, `sequence`,
and `fields`.

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
script stays local; the vault backup + claim link surface automatically inside
a notebook or a serverless deploy (Vercel, AWS Lambda, Netlify, Cloud Run,
Azure Functions). Pass `link=True` to force it from any script, or `link=False`
(or `TN_NO_LINK=1`) to keep it offline.

## Sign in to your account

To connect this machine to your vault account — so backups attach to you and
you can restore on another device — sign in:

```bash
tn auth login
```

This opens your browser to sign in, and also prints a short code to type if the
browser does not open (the standard device-authorization flow, the same one
`az login` and `gh auth login` use). The CLI waits, then connects this device;
your device key stays the principal, so nothing is pasted back. For CI or
headless boxes, use a connect code (`tn auth connect <code>`) or `TN_API_KEY`
instead. Full reference: [Authentication & accounts](auth.md).

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
regardless of the level threshold; the level verbs respect the threshold. It
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

## Commands by example

Worked invocations for the verbs beyond `init` / `info` / `read`, each with its
code equivalent. Every command takes `--yaml <path>` to pick a project (omitted
below — it discovers `./tn.yaml` or `./.tn/default/tn.yaml`). Run any command
with `--help` for its full flag set; the [cookbooks](cookbook-python.md) document
every option.

**Read a specific stream, a single run, or raw JSON.** The positional argument
is a stream name (resolved from `.tn/<name>/`) or a log path:

```bash
tn read orders                 # read the "orders" stream
tn read --no-all-runs          # only this process's run (default: all runs)
tn read --json                 # structured envelopes instead of the one-line view
```

```python
for e in tn.read(selector="order.created"):      # filter by event_type
    print(e.fields)
for e in tn.read(filter={"event_type_prefix": "order."}):
    print(e.event_type)
```

**Tail the log live.** `--since` picks the start; `--once` dumps a snapshot and
exits:

```bash
python -m tn.watch ./.tn/demo/tn.yaml --since start --once   # Python
tn-js watch --yaml ./.tn/demo/tn.yaml --since now            # TypeScript
```

```python
# tn.watch is an async generator — iterate it in an async context:
async for e in tn.watch(since="now"):
    print(e.event_type, e.fields)
```
```typescript
for await (const e of tn.watch({ since: "now" })) {
  console.log((e as Entry).event_type);
}
```

**Typed fields and a custom level.** `--field` is a string; `--int` / `--bool`
coerce; `--level` sets severity:

```bash
tn info --event quota.near --level warning --field region=us --int used=92 --bool blocked=true
```

**List and validate projects; inspect resolved config:**

```bash
tn streams --format json       # every project under ./.tn
tn validate                    # load each project, report problems (CI gate)
tn show env                    # the TN_* parameters this install reads
```

**Add a group with its own field routing:**

```bash
tn group add audit --fields actor,action,target --cipher btn
```

```python
tn.admin.ensure_group(tn.current_config(), "audit", fields=["actor", "action", "target"])
```
```typescript
await tn.admin.ensureGroup("audit", { fields: ["actor", "action", "target"] });
```

**Carry a whole project to another machine.** `export` writes an encrypted
`project_seed` (keys + config); `import` restores it into a fresh directory:

```bash
tn export --kind project_seed --out backup.tnpkg --include-secrets
tn import backup.tnpkg         # in an empty dir on the other machine
```

**Sync with your vault** (needs `tn auth login` first):

```bash
tn wallet sync                 # two-way: pull + absorb, then push the backup
tn wallet sync --pull          # pull + absorb only
tn wallet status               # identity + link state, no network
```

**Rotate a group's keys** (heavier than revoke; re-keys every survivor):

```bash
tn rotate audit
```

```python
tn.admin.rotate("audit")
```

## CLI reference

`tn` is the Python command; `tn-js` is the TypeScript command. A few Python
capabilities are reached through a module (`python -m tn.watch`) or the code
API rather than a `tn` subcommand; those are noted. The code columns show the
function each verb calls.

| Command | Python CLI | TypeScript CLI | Description | Python code | TypeScript code |
|---|---|---|---|---|---|
| init | `tn init <project>` | `tn-js init [<project>]` | Create identity + project at `./.tn/<project>/`; back it up to the vault unless `--no-link`. | `tn.init("demo")` / `tn.init()` | `await tn.init("demo")` |
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
| auth login | `tn auth login` | `tn-js auth login` | Sign in via the browser (device flow); connect this device. | `tn.auth.connect(...)` | `tn.auth.connect(...)` |
| account connect | `tn account connect <code>` | `tn-js account connect <code>` | Headless: bind this device to a vault account with a connect code. | `vault_client.redeem_connect_code(...)` | (CLI) |
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
