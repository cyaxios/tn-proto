# TN Python SDK + CLI cookbook

Recipes for the TN protocol Python SDK and the `tn` CLI.

Two ways in:

- **Code**: `import tn` and call the verbs (`tn.init`, `tn.log`,
  `tn.info`, `tn.read`, ...).
- **CLI**: `python -m tn.cli <command>` (installed as `tn`).

`tn init` is the universal entry point for both. A ceremony lives under
`./.tn/<project>/`.

The examples here run the module form against a checkout:

```bash
PYTHONPATH=python python -m tn.cli <command> [args]
```

When a CLI command has a code-level equivalent, the matching `tn.*` verb
is shown alongside it.

### Terms used below

- **ceremony** - the on-disk project record under `.tn/<project>/`, identified by its `ceremony_id`.
- **stream** - a named log under a project; opened with `tn.use("<stream>")` or the `stream=` keyword.
- **group** - a named set of fields encrypted to a shared key; recipients are enrolled per group.
- **reader kit / `.btn.mykit`** - the per-group key material a recipient needs to decrypt that group.
- **bundle / `.tnpkg`** - the absorbable package wrapping one or more reader kits plus a manifest.
- **DID** - a `did:key:z6Mk...` device identifier; the publisher's identity and each recipient's address.
- **`leaf_index`** - the recipient's slot in a group, assigned by TN - you never set it.
- **epoch** - the group's key generation, bumped by `tn.rotate` / `tn.admin.rotate`.

---

## Basics

### tn.init() in code

`tn.init("demo")` creates or opens a project named `demo` under
`./.tn/demo/` and opens its log. `tn.init()` with no argument discovers an
existing project (`$TN_YAML`, `./tn.yaml`, `./.tn/default/tn.yaml`,
`$TN_HOME/tn.yaml`) and mints a fresh default one if nothing is found. An
explicit yaml path, `tn.init("./.tn/demo/tn.yaml")`, is an advanced form for
binding a project at a path you choose.

TN reads the argument as a project NAME unless it ends in `.yaml` / `.yml`,
in which case it is treated as an explicit yaml path (advanced). Prefer the
name form. The same name-or-path rule applies in TypeScript.

```python
import os, tempfile, tn

work = tempfile.mkdtemp(prefix="tn_basics_")
os.chdir(work)
tn.init("demo")

cfg = tn.current_config()
print("ceremony_id:", cfg.ceremony_id)
print("cipher:", cfg.cipher_name)
print("groups:", list(cfg.groups.keys()))
```

```
ceremony_id: stream_demo_2030ef
cipher: btn
groups: ['default', 'tn.agents']
```

A fresh project is created with the `btn` cipher and two groups: the
`default` user group and the internal `tn.agents` policy group.

### Logging: tn.log and tn.info with fields

Write attested entries by calling the verbs directly. Keyword arguments
become typed fields on the entry.

Use the level verbs - `tn.info` / `tn.warning` / `tn.error` / `tn.debug` -
for the standard severities; they respect the configured level threshold.
`tn.log` is **not** a synonym for `tn.info`: reach for `tn.log(event,
level="...")` only when you need a custom or severity-less level. `tn.log`
always writes, regardless of the threshold.

Only `tn.log` returns the written record (a dict whose `str()` is valid
JSON); the level verbs `tn.info` / `.warning` / `.error` / `.debug`
return `None`. To get the record back, call `tn.log(..., level=...)` or
read it via `tn.read()`.

```python
import os, tempfile, tn

work = tempfile.mkdtemp(prefix="tn_full_")
os.chdir(work)
tn.init("demo")

tn.log("app.started", component="api")
tn.info("order.created", order_id="o_123", amount=4999, currency="USD")

for e in tn.read():
    print(e)

tn.flush_and_close()
```

```
15:25:02.569 LOG    seq=1  app.started
15:25:02.571 INFO   seq=1  order.created
15:25:02.569         seq=1  app.started  component='api'
15:25:02.571 INFO    seq=1  order.created  amount=4999  currency='USD'  order_id='o_123'
```

The first two lines are the stdout handler firing as each entry is
recorded. The last two are the `tn.read()` iteration printing each typed
`Entry`.

### Reading back in code: tn.read returns a typed Entry

`tn.read()` yields `Entry` objects. User fields land in `entry.fields`;
envelope and chain data surface as typed attributes (`event_type`,
`level`, `sequence`, `did`, ...).

`tn.read()` returns a lazy, single-pass iterator of `Entry` objects; wrap
in `list(...)` to index or re-iterate. It defaults to `all_runs=True`
(every run on disk); pass `all_runs=False` to scope to this process.

```python
import os, tempfile, tn

work = tempfile.mkdtemp(prefix="tn_entry_")
os.chdir(work)
tn.init("demo")
tn.info("order.created", order_id="o_123", amount=4999, currency="USD")

e = list(tn.read())[0]
print("type       :", type(e).__name__)
print("event_type :", e.event_type)
print("level      :", e.level)
print("sequence   :", e.sequence)
print("fields     :", e.fields)
print("amount     :", e.fields["amount"])
print("did        :", e.did)

tn.flush_and_close()
```

```
type       : Entry
event_type : order.created
level      : info
sequence   : 1
fields     : {'amount': 4999, 'currency': 'USD', 'order_id': 'o_123'}
amount     : 4999
did        : did:key:z6Mkw4XRnHLT79epXsohsUgBSJeitvTdDxkScW7Cho4UWfaU
```

### Reading from the CLI: tn read

`tn read` prints the ceremony's log in flat, decrypted form.

```bash
PYTHONPATH=python python -m tn.cli read --yaml .tn/demo/tn.yaml
```

```
2026-06-08T15:25:45.728904+00:00  info    order.created  amount='4999' order_id='o_123'
2026-06-08T15:25:46.866319+00:00  warning auth.failed  who='alice'
```

---

## CLI command reference

Each subsection shows the `--help` synopsis, an invocation with its
output, and the code-level equivalent where one exists.

### tn init

Scaffold identity + ceremony. The universal entry point.

```bash
usage: tn init [-h] [--version-name VERSION_NAME] [--cipher {btn,jwe}]
               [--words {12,15,18,21,24}] [--mnemonic-file MNEMONIC_FILE]
               [--link LINK] [--no-link] [--force] [--skip-confirm]
               [--keep-mnemonic]
               project
```

```bash
PYTHONPATH=python python -m tn.cli init demo --no-link --skip-confirm
```

```
[tn init] Reusing identity at C:\Users\gilsa\AppData\Roaming\tn\identity.json
[tn init]   DID: did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS
[tn init] Ceremony local_813e241b created at C:\codex\tn\tn_proto_doctmp\cli_demo\.tn\demo\tn.yaml
[tn init]   project: demo
[tn init]   cipher: btn
[tn init]   keystore: C:\codex\tn\tn_proto_doctmp\cli_demo\.tn\demo\keys
```

By default `tn init <name>` backs the project up to the vault and prints a
link to it (default `https://vault.tn-proto.org`, falling back to your saved
`linked_vault`, then `$TN_VAULT_URL`). `--no-link` opts out for an
offline-only project with no vault contact, as shown above. `--keep-mnemonic` stores the recovery
phrase in `identity.json` so `tn wallet export-mnemonic` can re-display it.
The project is created at `./.tn/<name>/`.

**Code equivalent:** `tn.init("<name>")`, or `tn.init()` for the default
project. See the Basics section above.

### tn wallet

Wallet / vault operations. Subcommands:

```bash
usage: tn wallet [-h]
                 {status,link,unlink,sync,pull-prefs,restore,export-mnemonic}
                 ...
```

#### tn wallet status

```bash
usage: tn wallet status [-h] [yaml]
```

```bash
PYTHONPATH=python python -m tn.cli wallet status .tn/demo/tn.yaml
```

```
Identity: did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS
  file:    C:\Users\gilsa\AppData\Roaming\tn\identity.json
  linked:  https://vault.tn-proto.org
  prefs:   default_new_ceremony_mode=local
           prefs_version=0
Ceremony: local_813e241b
  yaml:            C:\codex\tn\tn_proto_doctmp\cli_demo\.tn\demo\tn.yaml
  mode:            local
  cipher:          btn
  linked_vault:    (none)
  linked_project:  (none)
  groups:          ['default', 'tn.agents']
  pending_sync:    (queue empty)
```

#### tn wallet link

Link a ceremony to a vault and push the initial backup. (requires a
linked vault)

```bash
usage: tn wallet link [-h] [--vault VAULT] [yaml]
```

**Code equivalent:** `tn.wallet.link_ceremony(...)`.

#### tn wallet unlink

Sever the vault link recorded on the identity. (requires a linked vault)

```bash
usage: tn wallet unlink [-h] [yaml]
```

#### tn wallet sync

Two-way sync: pull the account inbox, absorb it, then push this
ceremony's backup. (requires a linked vault and `tn account connect`)

```bash
usage: tn wallet sync [-h] [--drain-queue] [--pull] [--push-only]
                      [--passphrase PASSPHRASE]
                      [yaml]
```

`--push-only` keeps the pre-two-way upload-only behavior. `--pull`
stages the inbox without absorbing. `--drain-queue` retries pending
autosync failures.

**Code equivalent:** `tn.wallet.sync_ceremony(...)` /
`tn.wallet.drain_sync_queue(...)`.

#### tn wallet pull-prefs

Pull account preferences from the vault. (requires a linked vault)

```bash
usage: tn wallet pull-prefs [-h] [--vault VAULT]
```

#### tn wallet restore

Restore one or more ceremonies from the vault (account-bound browser
flow, or `--passphrase` / mnemonic fallback). (requires a linked vault)

```bash
usage: tn wallet restore [-h] [--mnemonic MNEMONIC]
                         [--mnemonic-file MNEMONIC_FILE] [--vault VAULT]
                         [--project-ids PROJECT_IDS] [--all-projects]
                         [--out-dir OUT_DIR_FLAG] [--force] [--passphrase]
                         [--port PORT] [--timeout TIMEOUT]
                         [--credential-id CREDENTIAL_ID]
                         [--project-id PROJECT_ID] [--jwt JWT]
                         [out_dir]
```

**Code equivalent:** `tn.wallet.restore_ceremony(...)`.

#### tn wallet export-mnemonic

Re-display the recovery phrase. Only works when the ceremony was created
with `--keep-mnemonic`.

```bash
usage: tn wallet export-mnemonic [-h] [--yes]
```

With no stored phrase the command refuses:

```bash
PYTHONPATH=python python -m tn.cli wallet export-mnemonic
```

```
tn: error: no mnemonic stored on this machine. identity.json was created without --keep-mnemonic (the default and safer path), so the recovery phrase was only shown once at `tn init` time. Record it elsewhere when you first see it.

If you want future `tn wallet export-mnemonic` calls to work, re-run `tn init <new-project> --keep-mnemonic` on a fresh project. This stores the phrase in identity.json (trades some security for recovery convenience).
```

When the identity was minted with `--keep-mnemonic`, `--yes` confirms
the on-screen display:

```bash
PYTHONPATH=python python -m tn.cli wallet export-mnemonic --yes
```

```
============================================================================
  WRITE THIS DOWN NOW. You will NOT see it again without
  explicit re-display, and without it you CANNOT recover
  your TN identity if this machine is lost.
============================================================================

  jump replace museum accuse dilemma engage distance nature peanut drum source lock

============================================================================
```

### tn account

Vault account binding operations.

```bash
usage: tn account [-h] {connect} ...
```

#### tn account connect

Redeem a `tn_connect_<...>` code to bind this device's DID to a vault
account. (requires a live vault)

```bash
usage: tn account connect [-h] [--yaml YAML] [--vault VAULT]
                          [--identity IDENTITY]
                          code
```

Without a reachable vault the redeem fails at the HTTP layer; run it
against your linked vault with the single-use code copied from the
dashboard.

### Which packaging verb?

`add_recipient` enrolls a NEW reader (mutates the ceremony, assigns a leaf);
`bundle` / `export` hands an existing reader a read-only copy (no ceremony
change); `invite` is `add_recipient` wrapped in a shareable zip; `compile`
packages raw keystore kits.

### tn bundle

Mint a `kit_bundle` `.tnpkg` for one recipient.

```bash
usage: tn bundle [-h] [--yaml YAML] [--groups GROUPS] [--seal-for-recipient]
                 recipient_identity out
```

```bash
PYTHONPATH=python python -m tn.cli bundle \
  did:key:z6MkBundleTestRecipient000000000000000000000000 \
  ./bob.tnpkg --yaml .tn/demo/tn.yaml
```

```
[tn bundle] wrote C:\codex\tn\tn_proto_doctmp\cli_demo\bob.tnpkg
[tn bundle]   recipient: did:key:z6MkBundleTestRecipient000000000000000000000000
[tn bundle]   ceremony:  local_813e241b  (cipher=btn)
[tn bundle]   groups:    ['default']
```

`--groups` selects which groups to include (default: every non-`tn.agents`
group). `--seal-for-recipient` wraps the body under a per-export key only
the named recipient can unwrap, so a CDN or vault can host the file
blind.

**Code equivalent:**
`tn.export("./bob.tnpkg", kind="kit_bundle", to_did="did:key:z...", groups=["default"])`.

### tn add_recipient

One-shot: mint a kit for a recipient and write its `.tnpkg`.

```bash
usage: tn add_recipient [-h] [--out OUT] [--yaml YAML] [--seal-for-recipient]
                        group recipient
```

```bash
PYTHONPATH=python python -m tn.cli add_recipient default alice \
  --yaml .tn/demo/tn.yaml --out ./alice.tnpkg
```

```
[tn add_recipient] wrote C:\codex\tn\tn_proto_doctmp\cli_demo\alice.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:zLabel-alice
```

A friendly label (`alice`) is auto-prefixed into a placeholder DID
(`did:key:zLabel-alice`); pass a `did:key:z...` to target a known
device. `did:key:zLabel-<name>` is a non-resolvable placeholder TN
synthesizes from a friendly label so you can try flows offline. Never
construct these yourself for a real recipient - pass an actual
`did:key:z6Mk...` device DID to `recipient_did=`.

**Code equivalent:** `tn.admin.add_recipient("default", recipient_did="did:key:z6Mk...")`.

```python
res = tn.admin.add_recipient("default", recipient_did="did:key:z6MkwReader000000000000000000000000000000000")
# res -> AddRecipientResult(leaf_index, kit_path, updated_cfg)
tn.admin.recipients("default")   # -> [{'recipient_identity': 'did:key:z6MkwReader000000000000000000000000000000000', ...}]
```

### tn invite

Mint a `tn-invite-<id>.zip` (kit + manifest) for one recipient.

```bash
usage: tn invite [-h] [--group GROUP] [--yaml YAML] [--from-email FROM_EMAIL]
                 [--note NOTE]
                 recipient out
```

```bash
PYTHONPATH=python python -m tn.cli invite carol ./tn-invite-carol.zip \
  --yaml .tn/demo/tn.yaml --note "Welcome"
```

```
[tn invite] wrote C:\codex\tn\tn_proto_doctmp\cli_demo\tn-invite-carol.zip
[tn invite]   group:     default
[tn invite]   recipient: did:key:zLabel-carol
[tn invite]   leaf:      3
[tn invite]   kit_sha256:sha256:83a21e02db42b4ac1111be5bba77680a830aaa44d0c6246f6339d17a158f589f
[tn invite]   inner kit: default.btn.mykit
```

`--group` selects the group (default `default`). `--from-email` and
`--note` are recorded in the manifest the recipient sees.

### tn group

Group management for an existing ceremony.

```bash
usage: tn group [-h] {add} ...
```

#### tn group add

Add a group post-init.

```bash
usage: tn group add [-h] [--fields FIELDS] [--cipher {btn,jwe}] [--yaml YAML]
                    name
```

```bash
PYTHONPATH=python python -m tn.cli group add partners \
  --fields deal_size,partner_name --yaml .tn/demo/tn.yaml
```

```
[tn group add] added group 'partners'
[tn group add]   fields: deal_size, partner_name
[tn group add]   cipher: btn
```

`--fields` is the comma-separated set of field names routed into the new
group. `--cipher` defaults to the ceremony's cipher.

**Code equivalent:** `tn.ensure_group(cfg, "partners", fields=["deal_size", "partner_name"])`.

```python
cfg = tn.current_config()
tn.ensure_group(cfg, "partners", fields=["deal_size", "partner_name"])
list(tn.current_config().groups.keys())   # -> ['default', 'tn.agents', 'partners']
```

### tn absorb

Absorb a `.tnpkg` (kit bundle, enrolment, etc.) into the active
ceremony. Requires an existing ceremony to absorb into.

```bash
usage: tn absorb [-h] [--yaml YAML] [--allow-self-absorb] package
```

```bash
# In a fresh recipient project (after `tn init bob --no-link`):
PYTHONPATH=python python -m tn.cli absorb ../cli_demo/alice.tnpkg \
  --yaml .tn/bob/tn.yaml
```

```
[tn absorb] kind=kit_bundle accepted=1 skipped=0
[tn absorb] WARN: overwrote 1 existing kit file(s):
             C:\codex\tn\tn_proto_doctmp\recipient\.tn\bob\keys\default.btn.mykit
[tn absorb] prior bytes preserved at <name>.previous.<UTC_TS> in the same directory.
```

`--allow-self-absorb` is required to absorb a package this ceremony
itself minted (refused by default, since it would overwrite the publisher's
own keystore with a reader-kit copy).

**Code equivalent:** `tn.absorb("./alice.tnpkg")` (after `tn.init`).

### tn rotate

Rotate group keys and emit per-recipient `.tnpkg` artifacts (one per
surviving recipient).

```bash
usage: tn rotate [-h] [--groups GROUPS] [--out OUT] [--yaml YAML] [group]
```

```bash
PYTHONPATH=python python -m tn.cli rotate default \
  --yaml .tn/demo/tn.yaml --out ./rotated
```

```
[tn rotate] rotated 1 group(s); emitted 3 .tnpkg artifact(s) into C:\codex\tn\tn_proto_doctmp\cli_demo\rotated
             default: epoch=1
             -> did_key_zLabel-alice.tnpkg
             -> did_key_z6MkBundleTestRecipient000000000000000000000000.tnpkg
             -> did_key_zLabel-carol.tnpkg
```

Omit the positional `group` (and `--groups`) to rotate every
non-internal group. `--out` is a directory (one `.tnpkg` per recipient)
or a single `.tnpkg` path for single-recipient rotations.

**Code equivalent:** `tn.admin.rotate("default")` returns a
`RotateGroupResult` (`cipher`, `new_epoch`, `renewed_recipients`,
`renewal_output_dir`, ...).

### tn read

Print a log in flat, decrypted form (auto-routes cross-publisher logs
via `read_as_recipient`).

```bash
usage: tn read [-h] [--yaml YAML] [--all-runs | --no-all-runs] [log]
```

```bash
PYTHONPATH=python python -m tn.cli read --yaml .tn/demo/tn.yaml
```

```
2026-06-08T15:25:45.728904+00:00  info    order.created  amount='4999' order_id='o_123'
2026-06-08T15:25:46.866319+00:00  warning auth.failed  who='alice'
```

`--no-all-runs` restricts output to the current process run; the default
includes prior runs. An optional positional `log` path reads a specific
log (cross-publisher logs auto-route).

**Code equivalent:** `for e in tn.read(): ...` (yields typed `Entry`).

### tn streams

List ceremonies / streams under `.tn/` for the project.

```bash
usage: tn streams [-h] [--project-dir PROJECT_DIR] [--format {human,json}]
```

```bash
PYTHONPATH=python python -m tn.cli streams
```

```
NAME  PROFILE      YAML
----  -----------  ----
demo  transaction  C:\codex\tn\tn_proto_doctmp\cli_demo\.tn\demo\tn.yaml
```

```bash
PYTHONPATH=python python -m tn.cli streams --format json
```

```json
[
  {
    "name": "demo",
    "profile": "transaction",
    "yaml_path": "C:\\codex\\tn\\tn_proto_doctmp\\cli_demo\\.tn\\demo\\tn.yaml"
  }
]
```

### tn validate

Validate the project's `.tn/` configuration tree.

```bash
usage: tn validate [-h] [--project-dir PROJECT_DIR]
```

```bash
PYTHONPATH=python python -m tn.cli validate
```

```
WARNING: no 'default' ceremony at .tn/default/. The project's identity should live there; named streams normally extend from it.
OK: 1 ceremony valid.
```

### tn show

Reflective inspection commands.

```bash
usage: tn show [-h] {env,profiles} ...
```

#### tn show env

Print the canonical `TN_*` env-var surface.

```bash
usage: tn show env [-h] [--format {human,env,json}]
```

```bash
PYTHONPATH=python python -m tn.cli show env
```

```
# tn show env: canonical TN_* environment surface
# Reflective only. Secrets are redacted; use --format=env to paste.

## identity

  TN_IDENTITY_DIR               (unset)                       default: OS data dir + /tn
                                Override the directory holding identity.json.

  XDG_DATA_HOME                 (unset)                       default: ~/.local/share
                                POSIX user-data root; TN appends /tn.
...

## vault

  TN_VAULT_URL                  (unset)                       default: https://vault.tn-proto.org
                                Base URL for the cloud vault (auth, sealed blobs, projects).
...
```

`--format env` emits a paste-able `TN_FOO=value` block (secrets
present); `--format json` is for programmatic use.

#### tn show profiles

Print the profile catalog and its encrypts / signs / chains / flush /
sink matrix.

```bash
usage: tn show profiles [-h] [--format {human,json}]
```

```bash
PYTHONPATH=python python -m tn.cli show profiles
```

```
NAME          ENCRYPTS  SIGNS  CHAINS  FLUSH     SINK
------------  --------  -----  ------  --------  --------------
transaction*  yes       yes    yes     fsync     file_rotating
audit         yes       yes    yes     buffered  file_rotating
secure_log    yes       yes    no      buffered  file_rotating
telemetry     yes       no     no      async     file_rotating
stdout        yes       no     no      async     stdout

* = catalog default (used when tn.init() is called with no profile=).

transaction: Grants, revokes, payments, agent actions, security events. ...
audit: Normal business events where reconstruction matters ...
secure_log: Sensitive application logs where signing matters more than sequence. ...
telemetry: Fast-as-stdlib-logger profile. ...
stdout: Dev-friendly default. ...
```

### tn seal

Attest one envelope per stdin JSON line (public-only; emits ndjson).
Each input line carries a 32-byte `seed_b64`, the envelope scalars, and
optional `public_fields`. No ceremony required, and the wire bytes interop
byte-for-byte with `tn-js seal`.

```bash
usage: tn seal [-h]
```

```bash
echo '{"seed_b64":"MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=","event_type":"order.created","level":"info","sequence":1,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","timestamp":"2026-06-08T12:00:00Z","event_id":"11111111-1111-4111-8111-111111111111","public_fields":{"amount":4999}}' \
  | PYTHONPATH=python python -m tn.cli seal
```

```json
{"device_identity":"did:key:z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i","timestamp":"2026-06-08T12:00:00Z","event_id":"11111111-1111-4111-8111-111111111111","event_type":"order.created","level":"info","sequence":1,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","row_hash":"sha256:35ec577f92f6dd457353fb370aaf7fb30dc3f2f9e638646fb566f3f0c24c13f9","signature":"tqLmrcRRgICGVkNQkrICqtY-8rIMpK_bL6RLzCvzXoy9PyirMM9e56r9uUIAfAY7rcGzlmKDKr94JRuO57qMDA","amount":4999}
```

A missing required field exits 2 with e.g. `tn seal: missing field seed_b64`.

### tn verify

Verify envelope ndjson read from stdin (public-only; one result line per
input). Pairs with `tn seal`.

```bash
usage: tn verify [-h]
```

```bash
# pipe seal's output straight into verify:
echo '{"seed_b64":"MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=","event_type":"order.created","level":"info","sequence":1,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","timestamp":"2026-06-08T12:00:00Z","event_id":"11111111-1111-4111-8111-111111111111","public_fields":{"amount":4999}}' \
  | PYTHONPATH=python python -m tn.cli seal \
  | PYTHONPATH=python python -m tn.cli verify
```

```json
{"ok": true, "did": "did:key:z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i", "event_type": "order.created", "event_id": "11111111-1111-4111-8111-111111111111", "row_hash": "sha256:35ec577f92f6dd457353fb370aaf7fb30dc3f2f9e638646fb566f3f0c24c13f9", "sequence": 1}
```

### tn canonical

Echo the canonical UTF-8 bytes of each stdin JSON line (the row_hash
preimage parity tool).

```bash
usage: tn canonical [-h]
```

```bash
echo '{"b": 2, "a": 1}' | PYTHONPATH=python python -m tn.cli canonical
```

```json
{"a":1,"b":2}
```

Keys are sorted and whitespace stripped, matching the canonicalisation
used inside `row_hash`.

### tn info

Emit one attested log entry from the command line.

```bash
usage: tn info [-h] [--yaml YAML] [--event EVENT] [--level LEVEL]
               [--field FIELD]
```

```bash
PYTHONPATH=python python -m tn.cli info --yaml .tn/demo/tn.yaml \
  --event order.created --field order_id=o_123 --field amount=4999
```

```
15:25:45.728 INFO   seq=1  order.created
info: emitted event_type='order.created' level='info' fields=2
```

`--field k=v` is repeatable. `--level` routes the four standard levels to
`tn.<level>` (e.g. `--level warning` -> `tn.warning(...)`); any other
string flows through `tn.log` verbatim, so `--level audit` maps to
`tn.log('order.created', level='audit', ...)`, NOT `tn.info`. A
`--level warning` example:

```bash
PYTHONPATH=python python -m tn.cli info --yaml .tn/demo/tn.yaml \
  --event auth.failed --level warning --field who=alice
```

```
15:25:46.866 WARNING  seq=1  auth.failed
info: emitted event_type='auth.failed' level='warning' fields=1
```

**Code equivalent:** `tn.info("order.created", order_id="o_123", amount=4999)`
(or `tn.warning(...)` for another standard level, or
`tn.log("order.created", level="audit", ...)` for a custom one).

### tn compile

Compile keystore reader kits into a `.tnpkg`.

```bash
usage: tn compile [-h] [--keystore KEYSTORE] [--out OUT] [--kit KIT]
                  [--label LABEL] [--full]
```

```bash
PYTHONPATH=python python -m tn.cli compile \
  --keystore .tn/demo/keys --out ./compiled.tnpkg --kit default
```

```json
{"ok": true, "out": "C:\\codex\\tn\\tn_proto_doctmp\\cli_demo\\compiled.tnpkg", "kits": ["default.btn.mykit"], "kind": "readers-only", "label": null}
```

`--kit` is repeatable (default: every group). `--label` is persisted into
the manifest. `--full` bundles private key material too (the
`full_keystore` kind).

### tn vault

Emit attested `vault.link` / `vault.unlink` events to the admin log.
These record the link state locally; they do not themselves contact a
vault, so they run offline.

```bash
usage: tn vault [-h] {link,unlink} ...
```

#### tn vault link

```bash
usage: tn vault link [-h] [--yaml YAML] vault_did project_id
```

```bash
PYTHONPATH=python python -m tn.cli vault link \
  did:web:vault.example.org proj_demo123 --yaml .tn/demo/tn.yaml
```

```json
{"ok": true, "verb": "vault.linked", "event_id": "019ea7d8-faf4-70b1-b85b-6b4a19e45441", "row_hash": "sha256:92030c5cce5649d3b51529117230d6c61105fd9db61c4a4647611b96a4200080", "vault_did": "did:web:vault.example.org", "project_id": "proj_demo123"}
```

**Code equivalent:** `tn.vault.link(...)`.

#### tn vault unlink

```bash
usage: tn vault unlink [-h] [--reason REASON] [--yaml YAML]
                       vault_did project_id
```

```bash
PYTHONPATH=python python -m tn.cli vault unlink \
  did:web:vault.example.org proj_demo123 --reason "rotating vaults" \
  --yaml .tn/demo/tn.yaml
```

```json
{"ok": true, "verb": "vault.unlinked", "event_id": "019ea7d8-ff61-7401-8c0b-eb6f9cbdd673", "row_hash": "sha256:7b5469ba121b8ef33ed8ff7bdde331373a68854ac7e25026adda73345797a9b7", "vault_did": "did:web:vault.example.org", "project_id": "proj_demo123"}
```

**Code equivalent:** `tn.vault.unlink(...)`.

#### Reading vault events back

Vault link state lives in the admin log. Read it with `tn.read(log="admin")`;
the alias resolves the ceremony's configured admin-log path, so it works in
every layout. Do not hardcode an admin-log filename.

```python
import tn

tn.init("demo")
tn.vault.link("did:web:vault.example.org", "proj_demo123")
tn.vault.unlink("did:web:vault.example.org", "proj_demo123")

for entry in tn.read(log="admin"):
    if entry.event_type.startswith("tn.vault."):
        print(entry.event_type, entry.fields.get("vault_identity"), entry.fields.get("project_id"))
```

```text
tn.vault.linked did:web:vault.example.org proj_demo123
tn.vault.unlinked did:web:vault.example.org proj_demo123
```
