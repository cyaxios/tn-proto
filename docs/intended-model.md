# TN Intended Model

This document records the intended product and protocol model agreed during
the SDK cleanup discussion. It is not a claim that the current Python, TS,
Rust, or WASM code already behaves this way. Treat it as the target model to
audit against.

The current source of truth for existing behavior is still the code. The file
lists at the end identify the Python files that currently matter most, plus
the TS/Rust/WASM files that should be checked for parity.

## Product Shape

TN should feel like a normal logging library first.

Users should be able to write:

```python
import tn

tn.init("payroll")
tn.info("job.started", {"id": 1})

api = tn.use("api")
api.info("request.done", {"status": 200})
```

and get secure defaults underneath:

- signed/chained evidence by default
- private-by-default field protection
- local logs
- project key/config management
- vault backup/sync by default, unless explicitly disabled
- normal logging conveniences: named streams, handlers, stdout/file/Kafka
  sinks, simple init/use behavior

The user should not need to understand ceremonies, package frames, recipient
wraps, or BTN internals to write logs.

## Terms

### Project

A Project is the user-facing local unit of work.

It has:

- a human name, such as `payroll`
- one root TN identity/config
- its own key material and local keyring/capability set
- its own `.tn/<project>/` state
- optional vault attachment
- one or more streams

`tn.init("payroll")` means:

> Create or open the local Project named `payroll`, and bind it as current.

`tn.init()` with no name means:

> Create or open the Project named after the current directory basename.

`project=` must mean project selection, not metadata stamping:

```python
tn.init("payroll")
tn.init(project="payroll")
```

These should be equivalent.

### Stream

A Stream is a named log channel inside a Project.

It has:

- its own stream overlay config
- its own log sink configuration
- possibly its own profile/sign/chain settings
- normally its own log/admin file names

It does not normally have:

- its own root identity
- its own vault project
- its own independent project name
- its own independent keyring

`tn.use("api")` means:

> Create or open stream `api` inside the current Project, and return a handle.

`tn.use("api", project="payroll")` means:

> Create or open stream `api` inside Project `payroll` without necessarily
> changing the current module-level Project.

Stream handles are cached by Project and stream, not by stream name alone.

### Default Stream

`default` is the reserved default stream name inside every Project.

`default` is not forbidden as a Project name. This is valid:

```text
.tn/default/
  streams/default.yaml
```

The path distinguishes Project name from stream name.

Module-level calls write to the current Project's default stream:

```python
tn.init("payroll")
tn.info("job.started", {})
```

Named handles write to their bound stream:

```python
api = tn.use("api")
api.info("request.done", {})
```

### Vault Project

A Vault Project is the remote account-owned backup/sync container for one
local Project.

The intended simple model is:

```text
one local Project <-> one active Vault Project
```

The local Project name and vault project display name may start the same, but
the durable remote identifier is the vault project id.

Local Project metadata should be able to represent:

- local Project name
- vault URL/backend
- linked vault project id
- autosync state

Absorb may fill empty vault metadata only when the package is authoritative
for the Project root identity. Absorb must not overwrite non-empty local vault
metadata.

### Ceremony

Ceremony is a protocol/runtime concept, not the main user-facing unit. It may
remain in YAML and code where it identifies signing/chaining/runtime state, but
it should not carry every product concept.

Project, stream, and vault metadata should be distinct concepts even if older
code currently stores many of these fields under `ceremony`.

## Directory Layout

Target layout:

```text
<workspace>/
  .tn/
    <project>/
      tn.yaml
      keys/
      streams/
        default.yaml
        api.yaml
        audit.yaml
      logs/
        default.ndjson
        api.ndjson
        audit.ndjson
        <templated-event-file>.ndjson
      admin/
        default.ndjson
        api.ndjson
      vault/
        state.json
        claim_url.txt
        pending/
        sent/
        received/
          absorbed/
          failed/
        conflicts/
```

Rules:

- `.tn/<project>/tn.yaml` is the Project root config/state.
- `.tn/<project>/streams/default.yaml` is the reserved default stream overlay.
- stream overlays may be blank or minimal initially.
- file logs live under `.tn/<project>/logs/`.
- admin files live under `.tn/<project>/admin/`.
- vault/package state lives under `.tn/<project>/vault/`.
- stream outputs may also be stdout, Kafka, or other handlers; such streams
  may not create a log file.
- templated event-id file names fit under `logs/`.

Names for Projects and streams should use the same conservative filesystem
rule:

```text
[a-zA-Z0-9_][a-zA-Z0-9_-]*
```

Reject path separators, leading dots, empty names, and other ambiguous names.

## Init And Use

### `tn.init`

```python
tn.init()
```

Uses the current directory basename as the Project name.

```python
tn.init("payroll")
tn.init(project="payroll")
```

Create/open Project `payroll` and bind it as current.

Calling `tn.init("billing")` after `tn.init("payroll")` switches the current
Project for module-level calls. Existing handles remain bound to their original
Project/stream.

### `tn.use`

```python
tn.use("api")
```

Create/open stream `api` in the current Project.

If no Project is initialized, infer the Project from the current directory
basename, create/open it, then create/open the stream.

```python
tn.use("api", project="payroll")
```

Create/open stream `api` in Project `payroll`, without necessarily changing
the current Project.

Python and TS now expose this as the first public transition path:
`tn.use("api", project="payroll")` and
`Tn.use("api", { project: "payroll" })`.

## Profiles

Profile controls behavior such as signing, chaining, and default sink.

Profiles are creation-time defaults:

- `profile=` is honored when creating a Project or stream.
- once the Project/stream YAML exists, YAML wins.
- later calls with a conflicting profile should warn and keep logging.
- profile mismatch should not be a hard error; the product principle is
  "log no matter what."

Warning text should be actionable. It should tell the user which YAML is in
effect and how to silence the warning or create a new stream with a different
profile.

## YAML Model

Project root YAML is Project-level config/state.

Stream YAML files are small overlays.

Root YAML should own:

- Project name/version
- root protocol/ceremony id
- default profile/sign/chain behavior
- device identity
- keystore path
- groups and recipients
- field routing
- default handlers
- vault attachment metadata when vault is enabled

Stream overlays should own:

- stream name
- stream profile/sign/chain overrides if any
- stream log/admin paths
- stream handler overrides
- reference/extends relationship to the Project root YAML

Multiple ciphers in one Project must be possible. Do not assume the whole
Project has one cipher forever. Cipher policy belongs closer to groups and
capability surfaces:

```yaml
groups:
  default:
    policy: private
    cipher: btn
  browser_share:
    policy: private
    cipher: jwe
```

Top-level/default cipher may exist as a compatibility default, but group-level
cipher must be treated as authoritative where present.

## Absorb

Absorb is additive capability intake into the current Project.

It means:

> Verify this `.tnpkg`, then add any usable keys, kits, contacts, log
> snapshots, project state, or readable capabilities into the target Project.

Absorb must not:

- replace the current Project
- replace the root identity of an existing Project
- change the local Project name
- overwrite non-empty vault linkage
- silently switch vault attachment
- behave like destructive import/restore

Absorb may:

- add capabilities to the Project keyring
- merge package state additively
- fill empty metadata when the package is authoritative
- auto-create the target Project if it does not exist

If the target Project does not exist:

- a root-authoritative project package, currently `project_seed`, may establish
  the new Project root identity/config
- a reader kit/capability bundle must not silently become the Project root
- for non-root-authoritative packages, mint a local root identity and add the
  package as capability

Vault metadata adoption:

- if local vault metadata is empty, absorb may adopt package vault metadata
  only when the package is signed by/chains to the Project/root identity
- if local vault metadata is non-empty, never overwrite it
- conflicting package metadata should produce a receipt/conflict record
- if valid vault metadata is adopted, enable autosync and add the vault sync
  handler; the handler sleeps until link/auth state is usable

Public `import` is confusing and should not be part of the main model.
Official `.tnpkg` handling should be absorb-oriented and additive. Disaster
recovery or manual replacement can remain an explicit advanced path, but it
should not blur the meaning of absorb.

## Vault And Wallet

Vault is the storage/sync backend. It may be hosted, local, browser-backed, or
enterprise.

Wallet is the user/account/key control plane and CLI surface.

Preferred CLI selector:

```bash
tn wallet link --project payroll
tn wallet sync --project payroll
tn wallet status --project payroll
tn absorb package.tnpkg --project payroll
```

If `--project` is omitted, infer the current directory basename.

`--yaml` may remain as an expert/compat override, but should not be the common
surface. Passing both `--project` and `--yaml` should be rejected to avoid
ambiguity.

### Vault Defaults

New Project creation defaults to vault enabled unless explicitly disabled:

```python
tn.init("payroll")
```

should create vault config and a vault sync handler.

```python
tn.init("payroll", vault=False)
```

means:

- no initial vault backup
- no pending claim
- no vault link attempt
- no vault config block
- no vault sync handler
- local-only Project

No vault block means vault is off for that Project. Vault must be explicitly
represented as on when enabled, even though the init default is to turn it on.

### Link

```bash
tn wallet link --project payroll
```

means:

> Attach local Project `payroll` to a Vault Project.

It should:

- create/reuse the remote Vault Project
- fill local vault metadata
- perform the initial backup if this is a new link
- add/enable `vault.sync`
- not imply full resync when already linked

### Sync

```bash
tn wallet sync --project payroll
```

means:

> Synchronize local Project `payroll` with its linked Vault Project.

It should:

- push local Project/control packages
- pull remote `.tnpkg` packages
- verify packages
- automatically absorb pulled packages additively
- preserve existing local vault metadata
- report accepted/skipped/conflicted packages

Push and pull are implementation directions inside sync. They may exist as
lower-level/internal diagnostics, but they are not the primary user model.

### Autosync

Linked Projects get a `vault.sync` handler by default.

Default interval:

```yaml
vault:
  enabled: true
  autosync: true
  sync_interval_seconds: 600
```

The handler should:

- run the same conceptual sync as `tn wallet sync --project ...`
- push/pull `.tnpkg`
- auto-absorb inbound packages additively
- never upload application logs
- sleep quietly until link/auth state is usable
- rate-limit warnings so CI and production logs are not noisy
- keep logging operational if vault sync fails

Autosync is not hidden global magic. It runs through the explicit
handler/runtime component.

## Vault Backup Boundary

The vault communication unit is `.tnpkg`.

Vault should exchange packages, not arbitrary raw file sync.

Include in Project backup packages:

- Project root YAML
- stream overlay YAML
- keys/kits/capabilities needed for Project recovery/sync
- vault sync metadata needed for continuity
- admin/control state needed to understand the Project
- package inbox/outbox metadata as needed

Exclude:

- application log files
- rotated application logs
- stdout history
- Kafka/external sink history
- raw stream output history

Application logs are user-emitted event streams from calls such as:

```python
tn.info(...)
tn.use("api").info(...)
```

Application logs are not vault-backed.

Admin/control files may be included for now if needed. The long-term target is
to store derived/signed project-state snapshots rather than raw admin logs.

## Manifest And Wire Components

The `.tnpkg` package is a ZIP container with:

```text
manifest.json
body/...
```

Manifest behavior and package wire details should be shared across SDKs rather
than reimplemented independently.

Current Python-derived manifest fields of interest:

- `kind`
- `version`
- `publisher_identity`
- `recipient_identity`
- `ceremony_id`
- `as_of`
- `scope`
- `clock`
- `event_count`
- `head_row_hash`
- `state`
- `manifest_signature_b64`

Known package kinds currently observed in Python include:

- `admin_log_snapshot`
- `offer`
- `enrolment`
- `recipient_invite`
- `kit_bundle`
- `full_keystore`
- `contact_update`
- `identity_seed`
- `project_seed`

The manifest signature is over canonical manifest bytes with
`manifest_signature_b64` removed. The signature algorithm is Ed25519 and the
encoded signature uses standard base64 with padding.

Current package body rules to preserve/audit:

- packages are ZIP containers
- `manifest.json` is the root metadata file
- body members live under `body/`
- `project_seed` currently carries a project/root-state backup shape:
  - `body/tn.yaml`
  - `body/keys/local.private`
  - `body/keys/local.public`
  - `body/keys/index_master.key`
  - `body/keys/<group>.btn.mykit`
  - `body/keys/<group>.btn.state`
- `identity_seed` is a bootstrap identity/capability package
- `kit_bundle` carries recipient capability/key material
- admin/control state should move toward derived signed snapshots, even if raw
  admin/control files are included during migration

Sealed body behavior currently observed:

- sealed package bodies use `body/encrypted.bin`
- encrypted body frame is `nonce[12] || AES-GCM(ciphertext+tag)`
- plaintext is a ZIP of the original body files
- manifest state records body encryption metadata such as cipher suite, nonce
  length, frame name, and ciphertext hash

Recipient wrap behavior currently observed:

- recipient body keys are wrapped for recipient identities
- Ed25519 DID material is converted to X25519 where needed
- ECDH + HKDF-SHA256 derives wrapping material
- AES-GCM wraps the body encryption key
- wrap AAD is bound to canonical manifest content with signature/wrap fields
  excluded

BTN/Rust wire components currently observed:

- top-level BTN wire header has magic/version/kind bytes
- ciphertext and reader-kit wire records have explicit binary layouts
- publisher id, epoch, cover entries, nonces, lengths, and body bytes are
  binary protocol fields
- these layouts must be shared-core governed; they should not drift between
  Python, TS, Rust, and WASM

Protocol-sensitive components that should move into or be governed by shared
core:

- known manifest kinds
- manifest schema
- canonical manifest bytes
- manifest signature verification
- body file enumeration
- sealed body frame detection and verification
- recipient wrap format
- package body layouts
- `project_seed`/project-state backup body shape
- `identity_seed` body shape
- `kit_bundle` body shape
- directory layout planning
- YAML normalization/validation rules
- name validation
- BTN wire primitives

The shared core should be usable from:

- Python
- Node TS
- browser JS
- Rust
- WASM/browser extension/vault UI surfaces

Rust/WASM is the natural place for the protocol core, with Python and TS
retaining ergonomic logging APIs, filesystem/browser adapters, handlers, and
HTTP clients.

## Current Python Files Of Interest

These files currently define or strongly influence the behavior above.

Project/init/use/layout:

- `python/tn/_multi.py`
- `python/tn/_layout.py`
- `python/tn/_defaults.py`
- `python/tn/_profiles.py`
- `python/tn/_handle.py`
- `python/tn/__init__.py`
- `python/tn/_autoinit.py`
- `python/tn/cli.py`

YAML/config:

- `python/tn/config.py`
- `python/tn/conventions.py`
- `python/tn/handlers/registry.py`
- `python/tn/_log_targets.py`

Logging/envelope/wire semantics:

- `python/tn/logger.py`
- `python/tn/chain.py`
- `python/tn/canonical.py`
- `python/tn/signing.py`
- `python/tn/cipher.py`
- `python/tn/btn_keystore.py`
- `python/tn/indexing.py`

Manifest and `.tnpkg`:

- `python/tn/tnpkg.py`
- `python/tn/export.py`
- `python/tn/absorb.py`
- `python/tn/pkg.py`
- `python/tn/_pkg_impl.py`
- `python/tn/packaging.py`
- `python/tn/recipient_seal.py`
- `python/tn/sealing.py`

Vault/wallet/sync:

- `python/tn/wallet.py`
- `python/tn/vault_client.py`
- `python/tn/vault.py`
- `python/tn/_vault_impl.py`
- `python/tn/sync_state.py`
- `python/tn/claim.py`
- `python/tn/bootstrap.py`
- `python/tn/wallet_restore.py`
- `python/tn/wallet_restore_loopback.py`
- `python/tn/wallet_restore_passphrase.py`
- `python/tn/handlers/vault_sync.py`
- `python/tn/handlers/vault_push.py`
- `python/tn/handlers/vault_pull.py`

Admin/control state:

- `python/tn/admin/__init__.py`
- `python/tn/admin/log.py`
- `python/tn/admin/cache.py`
- `python/tn/reconcile.py`

Tests that are likely relevant when auditing:

- `python/tests/test_multi_ceremony.py`
- `python/tests/test_use_multi_ceremony.py`
- `python/tests/test_ensure_group_stream_layout.py`
- `python/tests/test_project_shape_round_trip.py`
- `python/tests/test_project_seed.py`
- `python/tests/test_tnpkg_interop.py`
- `python/tests/test_export_absorb.py`
- `python/tests/test_absorb.py`
- `python/tests/test_vault_sync_handler.py`
- `python/tests/test_vault_push_handler.py`
- `python/tests/test_vault_pull_handler.py`
- `python/tests/test_vault_push_pull_e2e.py`
- `python/tests/test_cli_sync_pull.py`
- `python/tests/test_cli_warm_attach.py`
- `python/tests/test_cli_init_non_tty.py`

## TS/JS Files To Audit For Parity

Project/init/use/layout:

- `ts-sdk/src/tn.ts`
- `ts-sdk/src/multi.ts`
- `ts-sdk/src/profiles.ts`
- `ts-sdk/src/runtime/config.ts`
- `ts-sdk/src/runtime/node_runtime.ts`
- `ts-sdk/src/browser/tn.ts`
- `ts-sdk/src/browser/runtime.ts`
- `ts-sdk/src/browser/create_fresh.ts`
- `ts-sdk/src/browser/create_from_seed.ts`

Manifest and `.tnpkg`:

- `ts-sdk/src/core/tnpkg.ts`
- `ts-sdk/src/core/body_encryption.ts`
- `ts-sdk/src/core/recipient_seal.ts`
- `ts-sdk/src/pkg/index.ts`
- `ts-sdk/src/compile.ts`
- `ts-sdk/src/runtime/absorb_bootstrap.ts`
- `ts-sdk/src/runtime/bootstrap_api_key.ts`

Logging/envelope/wire semantics:

- `ts-sdk/src/core/envelope.ts`
- `ts-sdk/src/core/chain.ts`
- `ts-sdk/src/core/signing.ts`
- `ts-sdk/src/core/types.ts`
- `ts-sdk/src/read_as_recipient.ts`

Vault/wallet/sync:

- `ts-sdk/src/wallet/index.ts`
- `ts-sdk/src/wallet/restore.ts`
- `ts-sdk/src/wallet/restore_loopback.ts`
- `ts-sdk/src/vault/client.ts`
- `ts-sdk/src/vault/index.ts`
- `ts-sdk/src/vault/url.ts`
- `ts-sdk/src/handlers/init_upload.ts`
- `ts-sdk/src/handlers/vault_push.ts`
- `ts-sdk/src/handlers/vault_pull.ts`
- `ts-sdk/src/handlers/registry.ts`

Browser/vault-related surfaces:

- `ts-sdk/src/index.browser.ts`
- `ts-sdk/src/browser/console_handler.ts`
- `ts-sdk/src/browser/http_handler.ts`
- `ts-sdk/src/runtime/storage_localstorage.ts`
- `ts-sdk/src/runtime/storage_memory.ts`
- `ts-sdk/src/runtime/storage_node.ts`
- `ts-sdk/src/runtime/wasm_shim.ts`

Tests likely relevant:

- `ts-sdk/test/tn_multi_ceremony.test.ts`
- `ts-sdk/test/tnpkg_export_absorb.test.ts`
- `ts-sdk/test/tnpkg_interop.test.ts`
- `ts-sdk/test/identity_project_seed.test.ts`
- `ts-sdk/test/wallet_link.test.ts`
- `ts-sdk/test/wallet_restore.test.ts`
- `ts-sdk/test/handlers_vault_push.test.ts`
- `ts-sdk/test/handlers_vault_pull.test.ts`
- `ts-sdk/test/init_upload.test.ts`
- `ts-sdk/test/config_env_vars.test.ts`
- `ts-sdk/test/extends_loader.test.ts`
- `ts-sdk/test/ensure_group_stream_layout.test.ts`

## Rust/WASM Files To Audit For Parity

BTN/wire primitives:

- `crypto/tn-btn/src/wire.rs`
- `crypto/tn-btn/src/ciphertext.rs`
- `crypto/tn-btn/src/publisher.rs`
- `crypto/tn-btn/src/reader.rs`
- `crypto/tn-btn/src/rotate.rs`
- `crypto/tn-btn/src/config.rs`
- `crypto/tn-btn/src/crypto/aead.rs`
- `crypto/tn-btn/src/crypto/kw.rs`

Core runtime/config/manifest:

- `crypto/tn-core/src/config.rs`
- `crypto/tn-core/src/runtime.rs`
- `crypto/tn-core/src/envelope.rs`
- `crypto/tn-core/src/chain.rs`
- `crypto/tn-core/src/signing.rs`
- `crypto/tn-core/src/tnpkg.rs`
- `crypto/tn-core/src/read_as_recipient.rs`
- `crypto/tn-core/src/path_template.rs`
- `crypto/tn-core/src/storage.rs`

Admin/control state:

- `crypto/tn-core/src/admin_catalog.rs`
- `crypto/tn-core/src/admin_cache.rs`
- `crypto/tn-core/src/admin_reduce.rs`

Handlers/vault:

- `crypto/tn-core/src/handlers/mod.rs`
- `crypto/tn-core/src/handlers/vault_push.rs`
- `crypto/tn-core/src/handlers/vault_pull.rs`
- `crypto/tn-core/src/handlers/fs_drop.rs`
- `crypto/tn-core/src/handlers/stdout.rs`

Python bindings:

- `crypto/tn-core-py/src/lib.rs`
- `crypto/tn-core-py/src/admin.rs`
- `crypto/tn-btn-py/src/lib.rs`
- `crypto/tn-btn-py/src/pipeline.rs`

WASM/browser:

- `crypto/tn-wasm/src/lib.rs`
- `crypto/tn-wasm/src/runtime.rs`
- `crypto/tn-wasm/src/storage.rs`
- `crypto/tn-wasm/src/handlers.rs`

Tests likely relevant:

- `crypto/tn-core/tests/tnpkg_export_absorb.rs`
- `crypto/tn-core/tests/tnpkg_interop.rs`
- `crypto/tn-core/tests/config_parse.rs`
- `crypto/tn-core/tests/extends_loader.rs`
- `crypto/tn-core/tests/runtime_init.rs`
- `crypto/tn-core/tests/runtime_emit.rs`
- `crypto/tn-core/tests/handlers_vault_push.rs`
- `crypto/tn-core/tests/handlers_vault_pull.rs`
- `crypto/tn-core/tests/event_id_template.rs`
- `crypto/tn-core/tests/envelope_golden.rs`
- `crypto/tn-core/tests/chain_golden.rs`
- `crypto/tn-core/tests/canonical_golden.rs`
- `crypto/tn-core/tests/signing_golden.rs`

## Known Drift To Audit First

These are not final bug reports; they are high-risk areas already observed in
source review.

1. Current Python CLI `tn init <project>` and Python/TS library `use(name)`
   do not yet share the clean Project/stream layout model.
2. Current layout has streams as siblings of `.tn/default` in several paths;
   target layout nests stream overlays under `.tn/<project>/streams/`.
3. Current `project=` in Python is partly metadata stamping; target model says
   it selects the Project.
4. Current wallet raw file sync uploads `tn.yaml` and key files individually;
   target model says vault communication is `.tnpkg`.
5. Current wallet sync pull stages packages and tells the user to absorb
   manually; target model says normal sync auto-absorbs additively.
6. Current code has `tn import`/restore surfaces that conflict with
   absorb-only semantics.
7. Current YAML merge/extends behavior differs across Python, TS, and Rust.
8. Current manifest kind lists have drifted across Python, TS, and Rust.
9. Current vault push/pull handlers are close to package-based sync, but need
   to be rationalized under a single conceptual `vault.sync`.
10. Current optional raw log sync behavior conflicts with the rule that
    application logs are not backed up.

## Cleanup Direction

The cleanup should not start by deleting code blindly.

Recommended order:

1. Lock this intended model.
2. Build a source-derived audit matrix against Python, TS, Rust, and WASM.
3. Add or update parity tests for manifest, `.tnpkg`, layout planning, YAML
   normalization, and vault sync semantics.
4. Extract shared protocol-sensitive logic into Rust/WASM core:
   manifest, package layout, body encryption, recipient wraps, directory
   planning, name validation, YAML normalization, and BTN wire.
5. Keep SDKs responsible for ergonomic APIs, handlers, local filesystem or
   browser storage adapters, and vault HTTP clients.
6. Remove/rename legacy surfaces only after tests prove the intended model.
