# TN directory layout and ceremony registry

This document describes the on-disk layout for TN ceremonies and the
in-process registry that binds them. It is the source of truth for both
SDKs (Python and TypeScript) and any other consumer that needs to read
or write TN state.

Status: design (Python implementation in progress, TS rebuild to follow).

## Decisions locked

The following are *decided* and the rest of the doc reflects them:

1. **One project = one identity.** The project's DID, signing key,
   keystore, and recipient/group definitions live at the root of the
   project. They are not federated out to per-stream sub-units.
2. **Streams are named log-writers.** A stream is a code-level construct:
   you say `tn.init("payments")` to declare you have a stream called
   `payments`. Streams differ from each other in profile + handlers
   + log path; they share project identity.
3. **Profiles are SDK-fixed types.** See `tn._profiles` for the catalog
   (alpha; will be regression-tuned). Currently:
   `transaction`, `audit`, `secure_log`, `telemetry`. Default is
   `transaction`. Encryption is on for every profile (the floor);
   signing/chaining/durability vary per profile.
4. **YAML is a living record.** Code creates streams; the YAML records
   them. Operators edit yaml to override per-environment. Operator
   wins conflicts; conflicts surface as warnings.
5. **Handler inheritance is strict-additive.** A child stream cannot
   subtract its parent's handlers; it can only add. Emit propagates
   up the chain (like stdlib logging).
6. **No-duplicate-writes is a runtime guarantee, not a config rule.**
   Per emit, each unique resolved sink address is written at most once.
   Configs can declare overlapping handlers; the runtime collapses
   them at fanout time.
7. **`extends:`** is a reserved yaml keyword. Reserved for future use.
8. **Format is fixed.** TN protocol envelopes have a fixed shape.
   Different "formatters" are not a configurable axis. If you want
   freeform logging, use stdlib logger.
9. **Stdout default for development is provisional.** Starting with
   stdlib-style unsigned + fast (the `telemetry` profile).
   Production deploys override per-environment.
10. **CLI tooling is intentionally lean.** `tn streams` lists, `tn
    validate` checks, `tn wallet sync` does the wallet update.

## On-disk layout

A TN-enabled project keeps every ceremony under a single hidden root
directory. The default ceremony owns the project's identity (one DID,
one keystore, one set of recipient relationships); named streams are
lightweight subdirectories that share that identity:

```
.tn/
  default/                  # project root: identity + master log
    tn.yaml                 # full config: me.did, keystore.path, groups, recipients
    keys/                   # the project's device keystore (shared)
    logs/                   # default ceremony's log + master log
    admin/                  # protocol-events log
    vault/                  # vault-side state
  payments/                 # a named stream — lightweight
    tn.yaml                 # references default's keys via ../default/keys
    logs/                   # this stream's log only
    admin/                  # this stream's protocol log
  traces/
    tn.yaml
    logs/
    admin/
```

**Default holds identity. Streams are lightweight.** Stream subdirs
have only `logs/` and `admin/` — no `keys/`, no `vault/`. Each
stream's `tn.yaml` references default's keystore via a relative path
(`../default/keys`) and reuses default's `me.did`, `groups:`, and
`recipients:` blocks verbatim. This is the "one project, one
identity" property: streams cannot independently change recipients
or mint their own keys. They differ only in profile, log path, and
handler configuration.

Rules:

- `.tn/` is the only top-level directory consumers need to know about.
- Each immediate subdirectory of `.tn/` is exactly one ceremony.
- The subdirectory name is the ceremony's *registry name* — distinct
  from `ceremony.id` in the YAML, which remains the protocol-level
  identifier.
- The reserved name `default` is the ceremony bound by the bare
  module-level API (`tn.info(...)` etc.). It is treated like any other
  ceremony in every other respect.

### Why directory-per-ceremony

Each ceremony already needs `keys/`, `logs/`, `admin/`, and vault state.
Bundling them into one folder per ceremony means ceremonies are
independently zippable, restorable, and inspectable. `ls .tn/` becomes
the canonical "what ceremonies live in this project" answer.

### Migration from the legacy single-ceremony layout

Pre-multi-ceremony projects keep their state under `.tn/tn/`. On first
use of a multi-ceremony-aware SDK, the layout is migrated:

```
.tn/tn/  ->  .tn/default/
```

Migration is automatic, idempotent, and runs at most once per project.
Implementations should:

1. Detect the legacy layout (`.tn/tn/tn.yaml` exists, `.tn/default/` does
   not).
2. Rename `.tn/tn/` to `.tn/default/`.
3. Rewrite any absolute paths in `.tn/default/tn.yaml` that point inside
   `.tn/tn/` to point inside `.tn/default/`.
4. Continue normally.

If both `.tn/tn/` and `.tn/default/` already exist, the migration
aborts with a clear error — that is a state the user must resolve by
hand, since silent merge is ambiguous.

## The `tn.yaml` file

Each ceremony's config lives at `.tn/<name>/tn.yaml`. This is the
durable evidence record for the ceremony — the configuration a reviewer
or auditor reads to understand what this stream is.

The schema is unchanged from the single-ceremony era; new keys are
documented inline in `python/tn/config.py`. The relevant ceremony-scoped
fields are:

- `ceremony.id` — protocol-level identifier (separate from the
  filesystem registry name).
- `ceremony.profile` — evidence profile (see `evidence-profiles.md`).
  Forthcoming; treat as optional during the transition.
- `keystore.path` — keystore location. Default is
  `.tn/<name>/keys/` and should normally be left to the default.
- `logs.path` — log file location. Default is
  `.tn/<name>/logs/tn.ndjson`.

## The in-process registry

Each Python process maintains a registry of TN handles, keyed by
registry name:

```python
import tn

tn.init("payments", profile="transaction", yaml_path=".tn/payments/tn.yaml")
tn.init("agents",   profile="audit",       yaml_path=".tn/agents/tn.yaml")

payments = tn.use("payments")
agents   = tn.use("agents")
```

### `tn.init(name, **kwargs)` — explicit setup

`tn.init` creates or attaches to a named ceremony with explicit
configuration intent.

- Looks up `.tn/<name>/`. If it exists, attaches.
- If it does not exist, creates it using the supplied kwargs and the
  safe-defaults template (see below) for any unspecified fields.
- If the supplied kwargs conflict with an existing
  `.tn/<name>/tn.yaml`, raises `TNConfigConflict` rather than silently
  preferring one source. The on-disk YAML is the durable record; if
  your code disagrees, that is a bug, not a configuration knob.
- Returns the registered `TN` handle.

`tn.init()` (no args) is sugar for `tn.init("default")`.

### `tn.use(name)` — usage intent, get-or-create

`tn.use` returns a TN handle by registry name. It is the verb code uses
once setup is done.

- Looks up the registry; returns the handle if present.
- If absent, looks for `.tn/<name>/`; attaches if found.
- If neither registry nor disk has it, creates a fresh ceremony using
  the safe-defaults template — no kwargs, no surprises.
- Returns the registered `TN` handle.

`tn.use()` (no args) is sugar for `tn.use("default")`.

`tn.use` never raises `TNNotFound` for valid registry names. The two
remaining failure modes are:

- `TNInvalidName` — the name contains characters that are unsafe as a
  directory name (path traversal, separators, etc.).
- `TNCreateFailed` — the on-disk creation itself failed (permissions,
  full disk).

### `tn.list() -> list[str]`

Returns the registry names of all ceremonies currently bound in this
process. Cheap; backed by the in-memory registry, not a disk scan.

A future `tn.scan()` may enumerate `.tn/*/` on disk for inspection
tooling; not in scope for the initial multi-ceremony work.

### Bare module-level verbs

The bare module-level API (`tn.info`, `tn.log`, `tn.debug`, `tn.error`,
`tn.read`) routes through `tn.use("default")`. If `default` does not
exist, `tn.use("default")` auto-creates it with safe defaults — so the
onboarding "just works" experience is preserved.

## Safe defaults

When a ceremony is auto-created (either by `tn.use` of a missing name,
or by the implicit default), it is written with the most conservative
configuration that does not surprise the user. Concretely:

- Profile: `transaction` (signed, chained, durable). The most
  conservative evidence guarantee available.
- Recipients: `[<local device DID>]` only. The auto-created ceremony
  is locally readable only — no leak surface.
- Keystore: shared with the process default keystore. Avoids
  fragmenting device identity across ceremonies.
- Groups: a single `default` private group. No PII or auth groups
  pre-declared.
- Cipher: `btn`.

The point of these defaults is that auto-creation is *safe* and
*visible*: the directory `.tn/<name>/` shows up on disk, the YAML is
inspectable, and nothing leaks because there are no recipients other
than the local device. If a downstream change ever relaxes one of
these defaults, that is an explicit decision and should land with a
documented rationale.

The defaults live as a constant in `tn._defaults.SAFE_DEFAULTS_YAML`
with inline comments explaining the *why* of each choice.

## Process scope vs disk scope

Some resources are per-process, some are per-ceremony. Implementations
should treat the boundary as:

| Resource              | Scope         | Notes                              |
|-----------------------|---------------|------------------------------------|
| device DID, keystore  | per-process   | one identity, many ceremonies      |
| ceremony id, chain    | per-ceremony  | written under `.tn/<name>/`        |
| recipients, groups    | per-ceremony  | written under `.tn/<name>/tn.yaml` |
| handler instances     | per-ceremony  | file handles must not be shared    |
| vault binding         | per-ceremony  | each ceremony names its own vault  |
| run_id                | per-process   | stamped on every emit              |

Sharing the keystore across ceremonies is intentional — fragmenting
device identity per-ceremony is almost always a bug. Override only with
deliberate cause.

## Per-process behavior of init / use

- `tn.init(name, ...)` called twice in the same process with the same
  name: returns the same `TN` instance both times (registry is the
  single source of truth).
- `tn.init(name, ...)` called in process A while process B has a TN
  bound to the same `.tn/<name>/`: each process holds its own handle;
  on-disk state is shared. Multi-process write coordination is a
  separate concern (file locking, sequence reconciliation) and is not
  fixed by this refactor.
- `tn.init(name, profile=A)` followed later by `tn.init(name,
  profile=B)`: raises `TNConfigConflict`. Profile is part of the
  evidence contract and not mutable through reinit.

## Tnpkg, vault, and wallet flows

The Python TN class exposes per-ceremony tnpkg/vault/wallet methods
that operate on the named ceremony's state without binding the
default singleton:

```python
producer = tn.init("publisher")
consumer = tn.init("subscriber")

# Mint a kit for the consumer and bundle into a .tnpkg
out = producer.bundle_for_recipient(
    recipient_did=consumer.cfg.device.did,
    out_path="for-subscriber.tnpkg",
)

# Consumer absorbs the bundle into its keystore
consumer.absorb(out)

# Vault binding is per-ceremony
producer.vault_link(client)
producer.vault_sync(client)

# Vault push/pull use the named ceremony's state
producer.vault_push_snapshot(client)
consumer.vault_pull_inbox(client)
```

### Active-ceremony binding

Several internal Python paths (notably `admin.add_recipient` for `btn`
ceremonies, which routes through the dispatch runtime) still assume a
process-level active ceremony. To support per-ceremony tnpkg/vault
ops without rebuilding all of that machinery, each per-ceremony verb
calls `TN._activate()` first, which binds the module-level singleton
to that ceremony's yaml.

The contract this sprint ships with: tnpkg/vault verbs are *serial*
across ceremonies — whichever TN you most recently called such a
verb on is the active ceremony for the singleton-bound verbs (live
emit, etc.). Calling `payments.bundle_for_recipient(...)` after
having operated on `agents` flushes the agents runtime and binds
payments. The next sprint replaces this with per-instance dispatch.

### TN class methods (Python)

| Method                                  | Operates on              | Notes |
|-----------------------------------------|--------------------------|-------|
| `tn.cfg`                                | self.yaml_path           | Lazy-loaded LoadedConfig; `default` defers to singleton's cfg |
| `tn.export(path, kind=..., **kw)`       | self.cfg                 | Wraps `tn.export.export` |
| `tn.absorb(source, **kw)`               | self.cfg                 | Wraps `tn.absorb.absorb` |
| `tn.bundle_for_recipient(did, path)`    | self.cfg                 | Mints kits + bundles |
| `tn.vault_link(client, **kw)`           | self.cfg                 | Wraps `wallet.link_ceremony` |
| `tn.vault_sync(client)`                 | self.cfg                 | Wraps `wallet.sync_ceremony` |
| `tn.vault_push_snapshot(client, **kw)`  | self.cfg                 | Wraps `handlers.vault_push.push_snapshot` |
| `tn.vault_pull_inbox(client, **kw)`     | self.cfg                 | Wraps `handlers.vault_pull.pull_inbox` |
| `tn.info / log / debug / warning / error` | (singleton)              | Default only; named raises `MultiCeremonyEmitNotImplemented` |
| `tn.read(...)`                          | (singleton)              | Default only; named raises `MultiCeremonyEmitNotImplemented` |

### Per-ceremony bundling

Each ceremony's vault/wallet bundle is a separate `.tnpkg` produced
by that ceremony's verbs. The whole-`.tn/` tree is not a single unit
of backup; consumers needing all-ceremony bundling can iterate the
registry.

The dashboard JS layer (`zip_io.js`, `snapshot_builder.js`,
`tnpkg_builder.js`, `kit_deliverer.js`) is already string-/memory-
based and ceremony-agnostic at the file level — it accepts
`ceremonyId` as a parameter rather than reading it from disk. No
changes to dashboard JS are required for the multi-ceremony layout;
it will continue to work as long as the producing/consuming ceremony
is identified at the call site.

### TypeScript SDK

The TS SDK gets two additive entry points for multi-ceremony work:

```ts
import { Tn } from "tn-proto";

// Open a ceremony at .tn/<name>/tn.yaml. Reserved name "default"
// resolves the multi-ceremony default. The yaml must already
// exist on disk; create it via the Python SDK or via a future
// tnpkg restore.
const payments = await Tn.openCeremony("payments");

// Enumerate ceremonies on disk under .tn/.
const names = Tn.listCeremonies();   // → ["agents", "default", "payments"]
```

`Tn.init()` (no args) also picks up `./.tn/default/tn.yaml` from the
discovery chain, so a project that has migrated to the multi-ceremony
layout works without code changes.

The TS-side tnpkg/vault flows (`compileKitBundle`, `vault_push`,
`vault_pull`) already accept explicit `yamlPath` / `keystoreDir` /
`config` parameters — they were per-ceremony from the start, just
without an explicit registry. Combined with `Tn.openCeremony`, the
multi-ceremony shape works end-to-end on the TS side already.

### Now wired

- **`extends:` is implemented in the config loader.** A child yaml
  with `extends: ../parent/tn.yaml` pulls in the parent's identity,
  groups, recipients, and (for handlers) handler list (additive,
  deduped by name). Stream yamls are minimal — they declare only
  what's stream-specific (profile, log path, own handlers).
  Identity / groups / recipients live at the project root only.
  Editing default's groups/recipients propagates to all streams
  automatically — no drift, no manual sync.
- **Live emit on non-default streams works.** `payments.info(...)`
  activates the named ceremony's runtime (binds the singleton to
  its yaml) and writes attested entries through the configured
  handlers. Operations across streams are serial — the singleton
  rebinds to whichever stream most recently emitted. Foundationally
  correct; per-instance dispatch (true parallel) is the next
  sprint's work.
- **Address-level runtime dedup.** Each emit tracks the set of
  `resolved_address()` strings already written; subsequent handlers
  resolving to the same address are skipped. File handlers dedup
  by absolute resolved path; stdout dedups by a `<stdout>` /
  `<stream:id>` sentinel. Other handler kinds opt out (return
  `None`) until they implement the API.

### Still deferred

- **`resolved_address()` on non-file/stdout handlers.** Otel,
  Kafka, Delta, S3, vault.push/pull, fs.scan/drop, zenoh: each
  needs its own implementation. Adding them is mechanical but
  per-handler. For now, those handlers always fire (no dedup).
- **Auto-create on the TS side.** `Tn.openCeremony` requires the
  yaml to exist; create via Python SDK first. Auto-create on TS
  lands when the TS rebuild stabilizes.
- **Per-instance dispatch.** Today multi-stream emit is serial via
  singleton activation. True per-instance dispatch (no shared
  module-level runtime) is the headline work for the next sprint.

## TypeScript SDK note

This document is the layout contract for the TypeScript SDK rebuild.
The TS rebuild should:

- Read the `.tn/<name>/` layout described above.
- Honor the `default` reservation.
- Implement the same `init` / `use` / `list` shape against the same
  registry semantics, with whatever idiomatic TypeScript adjustments
  are appropriate (e.g. `Tn.init(name, opts)` returning a `Tn`
  instance).
- Apply the same migration rule for legacy `.tn/tn/` projects.

The current `tn_proto_web/tn.yaml` at the project root is a transitional
placement; the TS rebuild should decide whether to migrate to
`.tn/default/tn.yaml` or formally exempt the web project as a special
case.
