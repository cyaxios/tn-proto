# TN-Proto

[![PyPI](https://img.shields.io/pypi/v/tn-proto?style=flat-square&color=orange&label=pypi)](https://pypi.org/project/tn-proto/)
[![npm](https://img.shields.io/npm/v/@cyaxios/tn-proto?style=flat-square&color=cb3837&label=npm)](https://www.npmjs.com/package/@cyaxios/tn-proto)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-green.svg?style=flat-square)](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/README.md#license)

**TN-Proto carries encrypted data, authenticated provenance, and use contracts through an application's work.** Three controls have separate jobs:

| Control | What it establishes |
| --- | --- |
| Group encryption | A reader can decrypt the groups covered by its key capabilities. Different readers can open different groups of one publication. |
| Object signature | The verified signing identity authenticated the publication's signed content, including its encrypted groups and carried governance. |
| Application admission | The receiving application accepts the writer, complete contract set, requested use, and selected groups before opening business data. |

The Python governed API follows `create → receive → compute → release`. Applications can also call governed receipt `unseal` and governed release `seal`. Working objects retain contributing source identities and accumulated contracts when released as new signed publications. A signature establishes authenticity; the application's evaluator decides whether a use is acceptable. TN does not interpret policy prose automatically or control a program after it has obtained plaintext.

## Install the Python governed SDK

```bash
python -m pip install "tn-proto==2026.9.13b1"
```

Python **3.10 or newer**, with wheels for **Linux x86-64** and **Windows x64**. These wheels include the native Rust implementation, so their installation does not require a Rust toolchain. This is a beta release of the Python governed application API. See the [release notes](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/CHANGELOG.md) and [complete Python guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/GOVERNED_PYTHON_API.md).

Node and browser packages have their own interfaces and release schedules. Their event-stream and sealed-object interoperability does not imply that this Python governed lifecycle is available in those runtimes.

## Create, unseal, compute, and seal

This complete example creates an invoice, admits its use, calculates a total, and publishes the result. Setup checks an exact writer and contract; the release decision also checks the calculation.

```python
import tn

POLICY = """## invoice
### instruction
Calculate the total of the supplied amounts.
### use_for
Internal accounting and reporting.
### do_not_use_for
External distribution.
### consequences
Reject an unapproved use.
### on_violation_or_error
Stop and request review.
"""

with tn.Session(POLICY) as session:
    policy = session.policy("invoice")

    def accepted(context):
        return (
            context.writer == session.did
            and len(context.policies) == 1
            and context.policies[0].matches_contract(policy)
        )

    def releasable(context):
        values = context.data.groups["default"]
        return accepted(context) and values["total"] == sum(values["amounts"])

    session.configure_receive(
        use=tn.UseContext("invoice-app", "accounting", "read"),
        object_type="invoice", groups=["default"], decide=accepted,
    )
    session.configure_release(
        use=tn.UseContext("invoice-app", "reporting", "publish"),
        to="internal-report", object_type="invoice", decide=releasable,
    )
    work = session.workflow(receive="accounting", release="reporting")

    invoice = session.create({"amounts": [20, 15]}, policy)
    data = work.unseal(invoice)                 # also work.receive(invoice)
    data.set("total", sum(data.get("amounts")))
    result = work.seal(data)                    # also work.release(data)
    result.write("invoice.tn")
    print(data.get("total"))                    # 35
```

`create` returns a working object with an initial signed snapshot. Receipt accepts that publication; edits remain local until release signs a new version. `write` saves the exact signed bytes. The destination named in release is decision context: the application still chooses its file, queue, HTTP client, or object store for delivery.

The [bank/vendor example](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/bank_vendor.py) shows separate identities, separate group grants, and selective business access. The [hello example](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/governed_hello.py) isolates a minimal configured receive operation.

## The fifteen object verbs

| Verb | Python call | Result |
| --- | --- | --- |
| create | `session.create(fields, policy, group="default")` | Initial signed publication and mutable `DataObject`. |
| receive | `work.receive(source, selection=None)` | Verify, admit the configured use, and open selected business groups. |
| inspect | `data.inspect()` or `publication.inspect()` | Detached working state, or the authenticated envelope with encrypted blocks. |
| get | `data.get(name=None, group=None)` | Read an opened field or complete opened group. |
| set | `data.set(name, value, group=None)` | Change a field; `name=None` replaces the group's fields. |
| select | `data.select(groups, fields=None)` | Retain groups and optional field projections atomically. |
| include | `data.include(other)` | Add contributing sources and contracts without copying business fields. |
| attach | `work.attach(data, policy)` | Add an authorized contract while retaining existing contracts. |
| release | `work.release(data, decide=None)` | Evaluate and sign the current state. An extra decision must also approve. |
| read | `tn.GovernedObject.read(path_or_binary_stream)` | Read and verify an exact publication. |
| write | `publication.write(path_or_binary_stream)` | Store the exact publication bytes. |
| forward | `publication.forward()` | Return those bytes for application transport. |
| verify | `session.verify(wire)` | Verify a publication without opening business data. |
| accept | `view.accept(use=use, groups=groups, decide=rule)` | Bind the verified object, reader, complete use, and selected groups. |
| open | `session.open(admitted, groups)` | Open groups allowed by that admission and the reader's capabilities. |

Obtain `view` with `session.governance(publication)`. `group=None` uses the working object's primary group. Transport methods on a working object refuse pending edits; release first. Reading or verifying authenticates bytes but does not grant a requested use. See the [full signatures and semantics](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/GOVERNED_PYTHON_API.md#object-operations).

### Seal and unseal

| Call | Meaning |
| --- | --- |
| `session.unseal(source, purpose="accounting")` | Governed `session.receive`, including configured admission. |
| `work.unseal(source, selection=None)` | Governed `work.receive` under its bound input rules. |
| `data.seal(purpose="reporting")` | Governed `data.release` with its session's output rules. |
| `work.seal(data, decide=None)` | Governed `work.release`, including configured and optional request decisions. |
| `session.seal(draft)` | Originate a `GovernedDraft` as a signed publication. |
| Module-level `tn.seal(...)` / `tn.unseal(...)` | The independent sealed-object API. `tn.unseal` verifies and decrypts available groups; it does **not** run governed use admission. |

## Configure an application

A `Session` owns its identity, policy, and key capabilities independently. `tn.Session(policy_text)` creates fresh in-memory material for examples and tests. A deployed service loads persisted material with `tn.Session.from_config("service.yaml")` or composes providers. Closing one session does not close another.

| Provider | Responsibility | Included implementation |
| --- | --- | --- |
| Identity | Resolve an application to its signing identity. | `LocalIdentity`, `FileKeyStore` |
| Keys | Supply the group's assigned reader and publisher capabilities. | `LocalKeys`, `FileKeyStore` |
| Governance | Select policies and input/output rules; evaluate receive, attach, and release. | `PolicyDirectory` |
| Catalog | Resolve an admitted dataset edition and its exact source publication. | `EditionCatalog` |
| Registers | Optionally retain signed creation/release metadata. | `FileRegisters` |

The [provider examples](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/providers/README.md) show complete composition with `Providers`, `PolicyRequest`, `WorkflowRequest`, `InputRule`, and `WorkflowPolicy`. The [Python guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/GOVERNED_PYTHON_API.md#providers) explains the interfaces. Workflow bindings capture configuration; their evaluators run again for each receive, attachment, and release.

### Persist keys across processes

```python
from tn.providers import FileKeyStore

# Provision once in the service's private storage.
store = FileKeyStore.create(
    "private/service-keys.json", "invoice-app", ["default"], cipher="btn"
)
# On subsequent starts, load the same identity and capabilities.
store = FileKeyStore.open("private/service-keys.json")
identity = store.resolve("invoice-app")
```

The store supplies both identity and keys to `Providers(store, store, governance, ...)`. Supported choices are `btn`, `jwe`, and `hibe`; the [separate-process examples](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/persistent_keys/README.md) include setup, policy configuration, publication, and reading. `FileKeyStore` retains secret key material **without encrypting the file at rest**. Protect it with the service's storage permissions. Creation refuses to overwrite an existing store; opening does not generate replacement keys.

### Keep optional object registers

```python
registers = tn.ObjectRegisters(
    creation="created.jsonl", release="released.jsonl"
)
session = tn.Session.from_config("service.yaml", registers=registers)
```

Registers record signed object metadata separately from transport. Passing an empty `tn.ObjectRegisters()` disables both; omitting the setting uses the native register environment configuration. Register failure is exposed through `data.register_error`, and the signed publication remains available. A register is not an application's transactional outbox or a receipt from the destination.

## Apply the API to enterprise patterns

Use `receive` at a trust or use boundary, retain every contributing publication with `include`, and evaluate the result at `release`. The application still supplies computation, transaction boundaries, authorization rules, and recovery state.

| Application pattern | TN operation and application responsibility |
| --- | --- |
| Gateway or client-specific view | Admit the audience's use; select permitted groups/fields; approve the output. |
| Request/reply, outbox, and publish/subscribe | Retain the exact signed result and correlation identity; retry delivery with `forward`; handle duplicates transactionally. |
| Pipeline or aggregation | Admit each input; perform the calculation; `include` all contributors; check completeness before release. |
| Dataset product or reusable cache | Bind the requested edition and complete use to the exact source; reevaluate each use. |
| Tenant repository, durable workflow, or migration | Retain accepted source/version identities and checkpoints; recover committed outputs instead of silently recomputing them. |

The [fifteen executable enterprise patterns](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/enterprise/README.md), [application-pattern guidance](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/GOVERNED_PYTHON_API.md#application-patterns), [dataset/catalog example](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/providers/catalog.py), and [bank/vendor example](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/examples/bank_vendor.py) connect these decisions to executable API calls. OPA, dataframe libraries, and model-serving adapters are separate integrations; installing `tn-proto` does not install or configure them.

The ICISSP experiment used a separate artifact pinned to SDK commit `c83a46a57310fcaccc832e50d6dbd75bd477b5b5`. Its benchmark results and artifact-specific test counts are not performance or suite-size claims for this release. The [paper reproducibility review](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/PAPER_REPRODUCIBILITY.md) records the evidence and remaining manuscript corrections.

## BTN recipient covers

BTN encrypts a group's body once and wraps its content key for the eligible subset cover. This release compresses uninterrupted paths in that cover using the existing subset-difference labels and reader keys. For a height-eight tree, one revoked leaf now needs one difference entry: ciphertext is `m + 132` bytes for an `m`-byte payload, compared with `m + 114` without revocation. The earlier uncompressed walker used eight entries and `m + 545` bytes for that case. The change saves 413 bytes of wrapping overhead; it is not a measured eightfold runtime improvement.

For a nonempty set of `r` revoked leaves in the height-eight tree, the compressed cover has at most `min(2r - 1, 256 - r)` entries. The wire format and 1,881-byte height-eight reader kits are unchanged, and retained earlier ciphertexts remain readable with their applicable keys. The separately pinned ICISSP results describe the earlier walker. See [cover construction, byte counts, and compatibility tests](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/BTN_COVER.md).

## Event streams use the same protocol

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

**TypeScript / Node** — event-stream interface:
```ts
import * as tn from "@cyaxios/tn-proto";

await tn.init();
tn.info("order.created", { order_id: "A100", amount: 4999 });
for (const entry of tn.read()) console.log(entry.level, entry.event_type, entry.fields);
await tn.close();
```

Set `TN_NO_STDOUT=1` to silence the stdout echo. In Python the SDK drains on interpreter exit (`tn.flush_and_close()` to force it); in Node always `await tn.close()` on shutdown.

## Event-stream verification

With the default signed, chained profile, readers can verify the content and predecessor links of observed entries. Verification authenticates the signing key; the application decides which writers to trust. Detecting a missing suffix requires an independently known expected head. Encryption protects fields assigned to encrypted groups; configured public metadata and equality tokens remain visible.

## Event-stream verbs

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

`tn.read(verify=True)` (Node: `tn.read({ verify: true })`) checks signatures and predecessor links under the reader configuration and raises on a verification failure. Select a signed, chained profile when these checks are required.

## Event-stream CLI

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

Share scoped reader capabilities through recipient packages. Keep signing keys and publisher authority private:

- **Identity (DID).** Every device has its own identity - a public `did:key:z6Mk…` derived from its Ed25519 key. Signing keys are private credentials; encrypted recovery bundles can retain them for restoration.
- **Groups.** Events land in named groups (default: `default`); each group is its own encrypted domain with its own reader list. A `payments` grant supplies access to the covered `payments` group; other group access requires its own capabilities.
- **Reader kits.** To let someone read a group, you mint a kit addressed to their DID and send it. They absorb it and can decrypt the group generations covered by that kit.
- **BTN revocation.** Future publications under the updated publisher state exclude the revoked reader. Existing publications and retained plaintext remain accessible under the earlier capabilities. Other ciphers use their own grant and rotation operations.

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

Or hand-edit the `groups:` and `fields:` blocks in `tn.yaml` (see [Configuration](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/python/README.md#configuration-tnyaml)); the SDK picks up the change in the same process.

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

The optional vault at `vault.tn-proto.org` stores encrypted recovery material for the event-stream runtime. The recovery secret controls access to that backup. Protect both the local keystore and the recovery phrase.

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
    │ .tn/<project>/logs/   ->  excluded from key backup   │
    └────────────────────────────────────────────────────┘
```

- **Keys and configuration.** Automatic vault key backup excludes application `.ndjson` logs. Application-configured transports and handlers determine where publications or logs are sent.
- **Encrypted recovery.** Retain the mnemonic recovery phrase separately from the encrypted backup. Anyone holding the recovery secret must be treated as having access to that backup.

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

## Event-stream profiles

An event-stream profile selects encryption, signing, and chaining settings:

- **Group encryption.** These profiles retain encryption for fields assigned to encrypted groups. Explicit public fields remain visible.
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
| `telemetry` | ✓ | - | - | high-volume traces / metrics; unsigned traces / metrics |
| `stdout` | ✓ | - | - | development output |

## Configuration (`tn.yaml`)

`tn.yaml` is **generated by `tn init`** (`tn-js init` in Node), and the CLI and SDK keep it in sync for you (`tn group add`, the ensure-group + vault verbs all write it). **You normally never edit it by hand - reach for a verb instead.** It is plain YAML, so you *can* hand-edit it once you know the schema, but a malformed file can break loading or field routing, so treat that as an advanced path. It is shown here in full (comments are explanatory; the emitted file has none) so you can see what the tools manage:

```yaml
ceremony:
  id: local_f2bb8224             # ceremony identifier
  mode: local                    # local | linked  (linked = backed by a vault)
  linked_vault: ''               # vault URL; empty when offline
  linked_project_id: ''          # vault-side project id; filled by `tn wallet link`
  sync_logs: false               # legacy setting; key backup excludes app logs
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

> **Every `tn.yaml` field - groups, field routing, ciphers, handlers, profiles, ceremony/link state - is documented in the [`tn.yaml` reference](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/yaml-reference.md).**

## Containers & CI

No home directory, no baking keys into an image. Set one secret - `TN_API_KEY` - and the container trades it with the vault for its keystore on first boot, then runs normally. If a keystore already exists on disk, that wins and the env var is ignored. Full guide: [running in containers and CI](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/deploy-containers.md).

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

[`tn-skills`](https://github.com/cyaxios/tn-skills) teaches your AI coding agent to use `tn-proto` correctly. It provides event-stream setup, field-routing guidance, and industry-oriented examples for coding assistants. Review generated code and policy assignments as part of the application.

Install it in Claude Code:
```text
/plugin marketplace add cyaxios/tn-skills
/plugin install tn-logging@tn-skills
```

For other AI tools, drop the repo's `AGENTS.md` into your agent. The bundled skills and industry kits are documented at <https://github.com/cyaxios/tn-skills>.

## Other runtimes

The repository contains shared protocol code and interoperability fixtures for supported event-stream and sealed-object operations. Consult each SDK for its implemented operations. The governed Python API documented above has its own release and validation surface.

| Runtime | Install |
|---|---|
| Python | `pip install tn-proto` |
| Node / TypeScript | `npm install @cyaxios/tn-proto` |
| Browser | the `@cyaxios/tn-proto/core` subpath (no Node deps) |

## Documentation

- [Getting started](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/getting-started.md) · [Python cookbook](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/cookbook-python.md) · [TypeScript cookbook](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/cookbook-typescript.md)
- [Groups, readers, bundles, rotation](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/groups-readers-rotation.md) · [JWE and HIBE key ceremonies](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/jwe-hibe-key-ceremonies.md) · [Running in containers and CI](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/deploy-containers.md)
- [Profiles](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/profiles.md) · [tn.yaml reference](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/yaml-reference.md) · [protocol spec](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/protocol.md)
- [Authentication & accounts](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/auth.md) · [Environment variables](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b1/docs/guide/environment-variables.md)

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
