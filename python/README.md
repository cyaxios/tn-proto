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
| `tn.info / .warning / .error / .debug` | one signed, encrypted envelope per call at that level; short-circuits below the active threshold |
| `tn.log(event_type, *, level="", **fields)` | severity-less emit (default `level=""`). Pass `level=` to stamp a custom level (`"trace"`, `"audit"`, foreign-logger spellings). Always emits regardless of threshold. Distinct from the four named verbs — not an alias. |
| `tn.read(...)` | iterate decoded entries |
| `tn.watch(...)` | tail the log live (async iterator) |
| `tn.absorb / tn.export` | install or produce a `.tnpkg` bundle |

### `tn.log` vs the level verbs

```python
tn.info("user.signed_in", user="alice")   # level="info", threshold-aware
tn.log("user.signed_in", user="alice")    # level="",     always emits
tn.log("scan.tick", level="trace",
       phase="discovery")                  # level="trace" (custom), always emits
```

Reach for `tn.log` when you need a level outside `debug` / `info` /
`warning` / `error`, or when you want an event that survives the
level-threshold filter regardless of what `tn.set_level` is set to.

## Reading: all runs, this run, admin

`tn.read()` defaults to **every entry on disk** (`all_runs=True`).
A fresh `python hello.py` reading an existing `.tn/` log will surface
yesterday's events. To restrict to entries written by *this* process's
runtime, pass `all_runs=False`:

```python
import tn
tn.init()

# All entries on the main log (default).
for e in tn.read():
    print(e.level, e.event_type, e.fields)
# info order.created {'amount': 4999, 'order_id': 'A100'}
# warning order.flagged {'order_id': 'A100', 'reason': 'hold'}

# Restrict to entries emitted by this process run.
for e in tn.read(all_runs=False):
    print(e.level, e.event_type, e.fields)
# (empty in a fresh process; nothing was emitted yet this run)

# Admin log (ceremony lifecycle), addressed explicitly by name.
for e in tn.read(log="admin"):
    print(e.level, e.event_type)
# info tn.ceremony.init
# info tn.group.added
# info tn.group.added
```

The `all_runs=True` default was chosen in 0.4.1a3 so that
`tn read` (CLI) and `tn.read()` (Python) match the operator
expectation of "show me what's in this log file." Set
`all_runs=False` explicitly to scope a read to the current run.

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

## Project identity and named streams

When you call `tn.init('billing')` against an empty project, you'll
see TWO directories appear on disk:

```
.tn/
├── default/          ← project identity anchor (auto-created)
│   ├── keys/
│   ├── tn.yaml
│   └── ...
└── billing/          ← the stream you asked for
    ├── logs/billing.ndjson
    ├── tn.yaml       ← carries `extends: ../default/tn.yaml`
    └── ...
```

This is by design (DX review #14). Named ceremonies are **streams**
layered on a shared project identity:

- The project's device DID + signing key live exactly once, at
  `.tn/default/keys/`. All entries from any stream attest under
  that same publisher.
- Each named stream's `tn.yaml` carries `extends:
  ../default/tn.yaml`. The loader pulls identity, keystore, groups,
  and recipients from default at config-load time. Streams own
  their **logs**, **admin log**, **chain state**, and
  **per-stream handlers** — not identity.
- Editing default's groups affects all streams in that project. No
  drift, no manual sync.

If you want a **truly standalone ceremony** at an arbitrary path
(no `.tn/default/`, no shared identity), use the explicit
`yaml_path=` form:

```python
tn.init(yaml_path="./my-custom-yaml.yaml", cipher="btn")
```

That mints a fresh self-contained ceremony at the given path with
its own DID + keystore + no `extends` reference.

## Profiles — pick the trade-off, not the knobs

`tn.init(profile=...)` selects a curated bundle of evidence and
performance trade-offs. Profiles are SDK-fixed (not user-composable);
pick the closest match and the runtime applies the bundle. The
catalog has five entries today:

| Profile | encrypts | signs | chains | flush | default_sink | use for |
|--|--|--|--|--|--|--|
| `transaction` | yes | yes | yes | fsync | file_rotating | grants, revokes, payments, agent actions, security events |
| `audit` | yes | yes | yes | buffered | file_rotating | normal business events; same evidence as transaction, weaker durability |
| `secure_log` | yes | yes | no | buffered | file_rotating | sensitive app logs where signing matters more than sequence |
| `telemetry` | yes | no | no | async | stdout | high-volume traces / metrics; near-zero overhead vs `logging.Logger` |
| `stdout` | yes | no | no | async | stdout | dev / notebook scratchpad — `print()` shape with encryption still on |

Encryption is **always on** — that's the protocol floor. The other
four axes (signs, chains, flush, default_sink) vary by profile.

### Examples — one per profile

```python
import tn

# transaction — the default. Grants, payments, anything you'd want
# to audit later.
tn.init(profile="transaction")        # same as tn.init()
tn.info("payment.completed", user="alice", amount=4999, currency="USD")

# audit — buffered writes for higher throughput on normal events.
tn.init(profile="audit")
tn.info("order.viewed", order_id="A100", viewer="bob")

# secure_log — signed but no chain. Use when chain coordination
# costs more than per-row sequence is worth.
tn.init(profile="secure_log")
tn.info("session.opened", session_id="s12", actor="alice")

# telemetry — unsigned, async, stdout-only. Near-zero overhead.
# No on-disk log file: `tn.read()` for this ceremony returns empty.
tn.init(profile="telemetry")
tn.info("page.viewed", path="/dashboard", latency_ms=87)

# stdout — dev-friendly default. Same evidence shape as telemetry
# but framed as "the logger you reach for in a notebook."
tn.init(profile="stdout")
tn.info("debug.note", message="trying something out", attempt=1)
```

### What's wired in `0.4.2a2`

| Axis | Wired? | Where |
|--|--|--|
| `signs` | yes | `ceremony.sign` in yaml; Rust runtime emits empty signature when False |
| `default_sink` | yes | Default-ceremony and per-stream yamls drop `file.rotating` for stdout-sink profiles |
| `chains` | **no — runtime gap** | Rust runtime always chains. `secure_log` / `telemetry` / `stdout` still emit `prev_hash` + `sequence`. Tracked in DX_FIXES.md profile-audit section. |
| `flush` | **no — runtime gap** | Handler dicts don't carry flush policy. The catalog's per-profile flush bit (`fsync` / `buffered` / `async`) is documentation-only today. |

The two gaps need Rust runtime work in `crypto/tn-core/`; both are
captured as xfailed tests in `tests/test_profile_full_matrix.py` so
they flip green automatically once the runtime grows the matching
switches.

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
| `tn.read()` shows entries from previous runs | The default is `all_runs=True` (every entry on disk). Pass `all_runs=False` to restrict to this process's run. |
| `tn: no ceremony found` when running `tn.absorb` | `tn.absorb` merges INTO an existing ceremony. Run `tn.init()` first. |
| Wheel install fails on an exotic platform | Source build needs Rust >= 1.85 (`rustup install stable`). |

## Where to next

- Source, issues, plans: <https://github.com/cyaxios/tn-proto>
- TypeScript SDK: <https://github.com/cyaxios/tn-proto/tree/main/ts-sdk>
- Browser and vault: <https://github.com/cyaxios/tn-proto-web>

License: Apache-2.0
