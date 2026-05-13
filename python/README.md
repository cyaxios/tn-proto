# tn-protocol

**TN. The agent transaction protocol.**

*Every action, a TransactioN.*

A library that lets a process write a signed, encrypted, append-only
log entry per business event, and lets the right readers verify,
decrypt, or be cut off from it later. Two cryptographic modes (`btn`,
an NNL subset-difference broadcast tree, and `jwe`, per-recipient
envelope) speak the same on-disk format.

```bash
pip install tn-protocol
```

A `tn` CLI is included. Native acceleration via the Rust `tn_core`
extension is automatic when available, with the same Python surface
either way.

## Hello, TN

The smallest useful program. The first run mints a ceremony at
`./.tn/default/`. Nothing to configure.

```python
import tn

tn.init()
tn.info("order.created", order_id="A100", amount=4999)
tn.warning("order.flagged", order_id="A100", reason="hold")

for entry in tn.read():
    print(entry.level, entry.event_type, entry.fields)
```

Output:

```
22:45:56 INFO     seq=1  tn.ceremony.init
22:45:56 INFO     seq=1  tn.group.added
22:45:56 INFO     seq=2  tn.group.added
22:45:56 INFO     seq=1  order.created
22:45:56 WARNING  seq=1  order.flagged
info order.created {'amount': 4999, 'order_id': 'A100'}
warning order.flagged {'order_id': 'A100', 'reason': 'hold'}
```

The first five lines are the default stdout handler echoing every
emit. The last two come from `tn.read`. The three `tn.*` lines are
protocol admin events (ceremony lifecycle); they go to a separate
admin log and are filtered out of `tn.read` by default.

Set `TN_NO_STDOUT=1` to silence the stdout handler.

No explicit flush. The SDK drains on interpreter exit.

## The five verbs

| verb | what it does |
|---|---|
| `tn.init(...)` | resolve or create a ceremony, bind the runtime |
| `tn.info / .warning / .error / .debug / .log` | one signed, encrypted envelope per call |
| `tn.read(...)` | iterate decoded entries |
| `tn.watch(...)` | tail the log live (async iterator) |
| `tn.absorb / tn.export` | install or produce a `.tnpkg` bundle |

## Reading: this run, all runs, admin

`tn.read()` defaults to entries written by *this* process's runtime.
That keeps a fresh `python hello.py` clean (no entries from yesterday
appearing as if from this run). To see across runs, pass
`all_runs=True`:

```python
import tn
tn.init()

# This run, main log only.
for e in tn.read():
    print(e.level, e.event_type, e.fields)
# (empty in a fresh process; nothing was emitted yet this run)

# All runs, main log.
for e in tn.read(all_runs=True):
    print(e.level, e.event_type, e.fields)
# info order.created {'amount': 4999, 'order_id': 'A100'}
# warning order.flagged {'order_id': 'A100', 'reason': 'hold'}

# Admin log (ceremony lifecycle), addressed explicitly by name.
for e in tn.read(log="admin", all_runs=True):
    print(e.level, e.event_type)
# info tn.ceremony.init
# info tn.group.added
# info tn.group.added
```

The default surface (`tn.read()` / `tn.watch()` with no `log=`) is
the main user log only. Admin envelopes (`tn.*`) live in a separate
log; address them by name when you want them. `log=` also accepts a
template (see Templated paths below).

## Vault and dashboard

Fresh ceremonies are minted linked to the cyaxios vault by default.
Inspect:

```python
import tn
tn.init()
cfg = tn.current_config()
print(cfg.mode)              # linked
print(cfg.linked_vault)      # https://vault.tn-proto.org
print(cfg.linked_project_id) # None  (empty until claimed)
print(cfg.is_linked())       # True
```

On-disk yaml ceremony block:

```yaml
ceremony:
  id: local_696951e4
  mode: linked
  linked_vault: https://vault.tn-proto.org
  linked_project_id: ''
  sync_logs: false
  cipher: btn
  sign: true
```

**Nothing reaches the network until an explicit vault verb fires.** A
linked-by-default ceremony is safe even on a machine that never sees
the vault.

To engage the vault:

```bash
tn wallet status        # is this machine linked, to what
tn wallet link          # claim a project on the vault
tn wallet restore       # pull every ceremony from the vault
```

To skip auto-link on init in interactive contexts (notebooks
auto-fire by default, scripts only when asked):

```python
tn.init(link=False)            # never auto-fire (yaml stays linked-shaped)
```

```bash
TN_NO_LINK=1                   # env-level hard kill switch
```

For a truly air-gapped ceremony, edit the yaml after init and set
`ceremony.mode: local` (and remove `linked_vault`).

The dashboard at `vault.tn-proto.org` lets a publisher invite a
reader by email, watch absorb status, and trigger rotations.
Everything the dashboard does is backed by the same `.tnpkg` format
that `tn.export` and `tn.absorb` produce locally.

## Groups

A group is a cipher domain. Every event you write lands in one or
more groups based on field routing in the yaml. Each group has its
own publisher state and its own reader list. Readers of group
`payments` can decrypt payments events, and only those.

Fresh ceremonies start with two groups:

- `default`: everything you emit without explicit routing
- `tn.agents`: reserved, used by the protocol for agent-policy events

Add more in `tn.yaml`:

```yaml
groups:
  default:
    cipher: btn
  payments:
    cipher: btn
    fields: [order_id, amount, card_last4]
  audits:
    cipher: jwe
    fields: [reviewer_did, decision]
```

A single `tn.info(...)` call can fan an event into N groups, each
encrypted under that group's readers only.

## Readers

A reader of a group can decrypt that group's entries. As the
publisher you grant read access by minting a kit for the reader's
DID. The reader installs the kit (or a `.tnpkg` bundle that contains
it) and from then on `tn.read` returns decoded entries on their
machine.

Python:

```python
import tn
tn.init()
result = tn.admin.add_recipient(
    group="default",
    recipient_did="did:key:z6MkAliceExamplePublicKey",
    out_path="./alice.btn.mykit",
)
print(result.leaf_index, result.kit_path)
# 1 alice.btn.mykit
```

The call writes a `.btn.mykit` file and emits a `tn.recipient.added`
admin event.

CLI, one-shot mint plus `.tnpkg` bundle ready to hand off:

```
$ tn add_recipient default alice
[tn add_recipient] wrote /your/cwd/alice.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:zLabel-alice
```

The CLI form synthesises a `did:key:zLabel-<name>` for friendly
labels, mints the kit, and wraps it as a `.tnpkg` in one step.

Revoke a reader when you need to:

```python
tn.admin.revoke_recipient(group="default", leaf_index=1)
```

For `btn` groups the broadcast tree handles thousands of readers
with sub-millisecond encrypt. Revocation is selective: the revoked
kit stops decrypting, every other reader keeps working without
rekeying.

## Bundles

A `.tnpkg` is a signed zip containing a manifest and body files.

Producer:

```python
tn.export("alice.tnpkg",
          kind="kit_bundle",
          to_did="did:key:z6MkAlice...",
          seal_for_recipient=True)
```

`seal_for_recipient=True` wraps the body under a per-export key
that only the named DID can unwrap, so a vault or CDN can host the
bundle without being able to read its contents.

Reader:

```python
import tn

# tn.absorb needs an existing ceremony to install into. Run tn.init()
# first; absorb merges the kit material into your current ceremony.
tn.init()
receipt = tn.absorb("./alice.tnpkg")
print(receipt.kind, receipt.accepted_count, receipt.deduped_count)
# kit_bundle 1 0
```

## Rotation

`tn rotate` writes a new generation of group keys and emits one
per-recipient `.tnpkg` artifact for surviving readers. The CLI runs
unattended:

```
$ tn rotate
[tn rotate] rotated 1 group(s); emitted 1 .tnpkg artifact(s) into
            /your/cwd/rotated_20260513T224809Z
             default: epoch=1
             -> did_key_zLabel-alice.tnpkg
```

Distribute the per-recipient files (vault push, CI artifact, email,
your choice). Each reader runs `tn absorb` on theirs.

## Templated paths

Both the admin log address (`admin_log_location` in the yaml) and
the main log address (`logs.path` plus the matching `handlers[].path`
entry) accept six tokens: `{event_type}`, `{event_class}`, `{date}`,
`{yaml_dir}`, `{ceremony_id}`, `{did}`.

```yaml
logs:
  path: "./logs/{event_class}/{date}.ndjson"
handlers:
  - kind: file.rotating
    name: main
    path: "./logs/{event_class}/{date}.ndjson"   # same template
```

Each emit lands in its rendered file:

```
$ ls .tn/default/logs/
audit/    order/    payment/
$ ls .tn/default/logs/order/
2026-05-13.ndjson
```

Read it back as a single stream:

```python
for entry in tn.read(log="./logs/{event_class}/{date}.ndjson",
                     all_runs=True):
    print(entry.event_type)
# audit.review
# order.created
# order.shipped
# payment.captured
```

Unknown tokens fail at `tn.init()` time, not at first emit.

## Scoped lifecycle

For test code or anything that wants a TN context bounded by a
code block instead of the global init:

```python
with tn.session() as s:
    s.log("order.created", order_id="A100")
    s.log("order.shipped", order_id="A100")
# block exit: session's ephemeral ceremony is torn down,
# the global runtime (if any) is restored
```

`tn.session()` creates an isolated tmpdir ceremony for the duration
of the block. The handle's verbs (`s.info`, `s.read`, etc.) match
the module-level ones. Used for tests and short-lived processes
that don't want to leave a `./.tn/` on disk.

For the long-running-process case, just `tn.init()` once at startup;
the global runtime stays for the life of the interpreter and drains
on exit.

## Cross-language

| binding | install | use case |
|---|---|---|
| Python | `pip install tn-protocol` | reference, CLI, services |
| TypeScript / Node | `@tn/sdk` (npm) | Node services, build tools |
| Browser (WASM) | bundled via `tn-proto-web` | in-browser verify and decrypt |

Every binding reads byte-identical envelopes. A row written by
Python can be decoded in the browser, and vice versa. Cross-language
parity tests run on every PR.

## CLI

`tn --help` lists every verb. Common ones:

```bash
tn init ./project              # provision identity + ceremony
tn add_recipient default alice # mint a kit for 'alice', wrap as .tnpkg
tn rotate                      # rotate every non-internal group;
                               # emit one per-recipient .tnpkg artifact
tn absorb ./alice.tnpkg        # install someone's bundle
tn read                        # decoded entries to stdout
tn read --all-runs             # include entries from prior process runs
python -m tn.watch ./tn.yaml   # follow the log live (jsonl to stdout)
tn streams                     # list ceremonies under .tn/
tn validate                    # validate the project's config tree
tn wallet restore              # pull every ceremony from the vault
```

Non-interactive by default. Safe in CI and containers. A TTY enables
prompts where they are useful.

## Troubleshooting

| symptom | likely cause |
|---|---|
| `KeystoreConflict: state for group X has diverged on disk` | Another process mutated the same ceremony's state. Re-run the admin verb; it picks up the fresh state and re-applies. |
| `tn.watch` shows no `tn.*` events | By design. Pass `log="admin"`. |
| `tn.read()` returns nothing in a fresh process | Default filters to this process's run_id. Pass `all_runs=True`. |
| `tn: no ceremony found` when running `tn.absorb` | `tn.absorb` merges INTO an existing ceremony. Run `tn.init()` first. |
| Wheel install fails on an exotic platform | Source build needs Rust >= 1.85 (`rustup install stable`). |

## Where to next

- Source, issues, plans: <https://github.com/cyaxios/tn-proto>
- TypeScript SDK: <https://github.com/cyaxios/tn-proto/tree/main/ts-sdk>
- Browser and vault: <https://github.com/cyaxios/tn-proto-web>

License: Apache-2.0
