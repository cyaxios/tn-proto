# Protocol Core Unification Matrix

This matrix turns `docs/intended-model.md` into an execution plan for the
cross-language cleanup workstream.

Goal:

> Every protocol-sensitive surface has one intended contract, fixtures, and
> parity tests across Python, TS/JS, Rust, and WASM before implementation is
> surgically replaced.

Status labels:

- `target-only`: intended model is defined, current code does not match yet
- `partial`: some current code matches, but behavior is split or drifting
- `python-reference`: Python currently has the closest behavior
- `rust-reference`: Rust/BTN currently owns the protocol primitive
- `unknown`: needs source audit before action

## Workstream Order

1. Manifest
2. `.tnpkg` package layout
3. Body encryption and recipient wraps
4. BTN wire primitives
5. Directory layout planner
6. YAML normalization
7. Absorb semantics
8. Vault package sync
9. Public verbs

Each work item should produce:

- coder-friendly mini-spec
- golden fixtures
- Python tests
- TS/JS tests
- Rust/WASM tests where applicable
- compatibility notes
- migration notes

## Matrix

| Surface | Intended Contract | Python Files | TS/JS Files | Rust/WASM Files | Current Status | First Action |
| --- | --- | --- | --- | --- | --- | --- |
| Manifest kind catalog | One shared list of valid package kinds, including `project_seed` and `identity_seed`; unknown kinds fail consistently or are explicitly extension-safe. | `python/tn/tnpkg.py`, `python/tn/export.py`, `python/tn/absorb.py` | `ts-sdk/src/core/tnpkg.ts`, `ts-sdk/src/pkg/index.ts`, `ts-sdk/src/runtime/absorb_bootstrap.ts` | `crypto/tn-core/src/tnpkg.rs` | partial | Write `docs/spec-next/manifest.md` with exact kind list and compatibility rule. Add a fixture that fails if any language omits a kind. |
| Manifest schema | Shared field names, required/optional rules, types, and normalized JSON shape. | `python/tn/tnpkg.py` | `ts-sdk/src/core/tnpkg.ts` | `crypto/tn-core/src/tnpkg.rs` | python-reference | Build schema fixtures for minimal/complete manifests for each package kind. |
| Manifest canonical bytes | Signing bytes are canonical manifest JSON with `manifest_signature_b64` removed. Key order, separators, base64, and null/absent behavior are fixed. | `python/tn/tnpkg.py`, `python/tn/canonical.py`, `python/tn/signing.py` | `ts-sdk/src/core/tnpkg.ts`, `ts-sdk/src/core/signing.ts` | `crypto/tn-core/src/tnpkg.rs`, `crypto/tn-core/src/signing.rs` | partial | Add cross-language canonical byte golden files. Require Python, TS, and Rust to produce identical bytes. |
| Manifest signatures | Ed25519 over canonical manifest bytes; standard base64 with padding; verify before package body trust. | `python/tn/tnpkg.py`, `python/tn/signing.py`, `python/tn/absorb.py` | `ts-sdk/src/core/tnpkg.ts`, `ts-sdk/src/core/signing.ts`, `ts-sdk/src/runtime/absorb_bootstrap.ts` | `crypto/tn-core/src/tnpkg.rs`, `crypto/tn-core/src/signing.rs` | partial | Add fixtures: Python signs/TS verifies/Rust verifies; TS signs/Python verifies/Rust verifies. |
| `.tnpkg` container | ZIP package with root `manifest.json` and `body/...`; no app logs; deterministic enough for verification even if ZIP byte order differs. | `python/tn/export.py`, `python/tn/absorb.py`, `python/tn/pkg.py`, `python/tn/_pkg_impl.py`, `python/tn/packaging.py` | `ts-sdk/src/core/tnpkg.ts`, `ts-sdk/src/pkg/index.ts`, `ts-sdk/src/compile.ts`, `ts-sdk/src/runtime/absorb_bootstrap.ts` | `crypto/tn-core/src/tnpkg.rs` | in progress | Scope documented in `docs/spec-next/tnpkg.md`; Python/TS/Rust high-level readers/writers now reject non-`body/...` package members. Need sealed body and malformed package fixtures next. |
| Project backup package body | Backup package includes Project control/state needed for recovery/sync, excluding application logs. It may include admin/control files during migration. | `python/tn/export.py`, `python/tn/absorb.py`, `python/tn/wallet.py`, `python/tn/handlers/vault_push.py` | `ts-sdk/src/runtime/node_runtime.ts`, `ts-sdk/src/runtime/absorb_bootstrap.ts`, `ts-sdk/src/wallet/index.ts`, `ts-sdk/src/handlers/vault_push.ts` | `crypto/tn-core/src/runtime_export.rs`, `crypto/tn-core/src/tnpkg.rs`, `crypto/tn-core/src/handlers/vault_push.rs` | in progress | Scope documented in `docs/spec-next/project-backup.md`; Python project_seed and wallet file sync now assert no app logs. TS `NodeRuntime.exportPkg(project_seed)` now produces the nested project body and excludes app logs. Rust exports assert admin/full-keystore package bodies exclude application logs; Rust `project_seed` producer is implemented (`crypto/tn-core/src/runtime_export.rs`). |
| Application log exclusion | User-emitted stream logs are never vault-backed: no `logs/*.ndjson`, no rotated app logs, no stdout/Kafka/external sink history. | `python/tn/wallet.py`, `python/tn/handlers/vault_push.py`, `python/tn/handlers/vault_sync.py` | `ts-sdk/src/runtime/node_runtime.ts`, `ts-sdk/src/handlers/vault_push.ts`, `ts-sdk/src/handlers/vault_pull.ts`, `ts-sdk/src/wallet/index.ts` | `crypto/tn-core/src/runtime_export.rs`, `crypto/tn-core/src/handlers/vault_push.rs`, `crypto/tn-core/src/handlers/vault_pull.rs` | in progress | Python wallet file sync excludes app logs even if legacy `sync_logs: true` is present. TS project_seed export excludes live and rotated application logs. Rust admin snapshot/full-keystore exports exclude app log content and files. Remaining work is unified `vault.sync` package flow. |
| Admin/control state backup | Raw admin files may be included during migration; long-term target is derived/signed state snapshots, not raw admin `.ndjson`. | `python/tn/admin/log.py`, `python/tn/admin/cache.py`, `python/tn/export.py`, `python/tn/handlers/vault_push.py` | `ts-sdk/src/admin/log.ts`, `ts-sdk/src/admin/cache.ts`, `ts-sdk/src/handlers/vault_push.ts` | `crypto/tn-core/src/admin_cache.rs`, `crypto/tn-core/src/admin_reduce.rs`, `crypto/tn-core/src/admin_catalog.rs` | partial | Document phase 1 include rule and phase 2 derived snapshot target. |
| Sealed body frame | `body/encrypted.bin` uses nonce plus AES-GCM ciphertext/tag over canonical STORED-ZIP body; manifest state records frame metadata and ciphertext hash. | `python/tn/recipient_seal.py`, `python/tn/export.py`, `python/tn/absorb.py`, `python/tn/sealing.py` | `ts-sdk/src/core/body_encryption.ts`, `ts-sdk/src/core/recipient_seal.ts` | `crypto/tn-core/src/body_encryption.rs` | in progress | Scope documented in `docs/spec-next/body-encryption.md`; shared vector locks canonical plaintext ZIP and AES-GCM blob across Python/TS/Rust. Need package-level sealed kit fixtures next. |
| Recipient wraps | Recipient wraps bind a body encryption key to recipient identity using ECDH/HKDF/AES-GCM and manifest-bound AAD. | `python/tn/recipient_seal.py` | `ts-sdk/src/core/recipient_seal.ts` | candidate shared core missing (consolidation deferred) | parity (py+ts) | Done at parity bar: shared golden vector `tests/fixtures/recipient_wraps/vector.json` + cross-language unseal/round-trip/outsider/lift tests (`python/tests/test_recipient_wrap_contract.py`, `ts-sdk/test/recipient_seal.test.ts`, now in the run set) + `docs/spec-next/recipient-wraps.md`. Rust/WASM ownership is consolidation, out of parity scope. |
| BTN wire | Binary BTN ciphertext and reader-kit layouts are fixed; no SDK reinterprets them independently. | `python/tn/cipher.py`, `python/tn/btn_keystore.py` | `ts-sdk/src/runtime/wasm_shim.ts`, `ts-sdk/src/core/types.ts` | `crypto/tn-btn/src/wire.rs`, `crypto/tn-btn/src/ciphertext.rs`, `crypto/tn-btn/src/publisher.rs`, `crypto/tn-btn/src/reader.rs`, `crypto/tn-wasm/src/lib.rs` | rust-reference | Treat `crypto/tn-btn/src/wire.rs` as source; expose parser/serializer tests through Python and TS/WASM. |
| Directory layout planner | Pure shared planner decides `.tn/<project>/...`, stream overlays, logs/admin/vault dirs. SDKs execute filesystem writes. | `python/tn/_layout.py`, `python/tn/_multi.py`, `python/tn/cli.py`, `python/tn/conventions.py` | `ts-sdk/src/multi.ts`, `ts-sdk/src/tn.ts`, `ts-sdk/src/runtime/config.ts` | candidate in `crypto/tn-core/src/config.rs` or new module | target-only | Write planner API: `plan_init`, `plan_use`, `plan_absorb`, `plan_wallet`. Add path fixtures. |
| Project vs stream semantics | `init` selects Project; `use` selects stream in current Project; handles cached by project+stream. | `python/tn/_multi.py`, `python/tn/_handle.py`, `python/tn/__init__.py`, `python/tn/cli.py` | `ts-sdk/src/tn.ts`, `ts-sdk/src/multi.ts` | `crypto/tn-core/src/runtime.rs` | in progress | TS already cached by `(projectDir, name)`. Python registry now keys handles by project root plus stream name and has a regression test for two Projects both using `api`. Remaining work: public `project=` spelling and target physical layout. |
| Default stream | `default` is reserved as stream name inside each Project, but may be used as a Project name. | `python/tn/_defaults.py`, `python/tn/_multi.py` | `ts-sdk/src/multi.ts`, `ts-sdk/src/tn.ts` | none | target-only | Add name validation fixtures distinguishing project name from stream name. |
| Name validation | Project and stream names use `[a-zA-Z0-9_][a-zA-Z0-9_-]*`; reject separators, empty, leading dots, ambiguous path names. | `python/tn/_layout.py` | `ts-sdk/src/multi.ts`, `ts-sdk/src/tn.ts` | candidate shared planner | partial | Move validation into shared planner/core; keep SDK wrappers thin. |
| YAML root model | Root YAML is Project-level; stream YAMLs are small overlays. Project, ceremony, and vault concepts remain distinguishable. | `python/tn/config.py`, `python/tn/_multi.py`, `python/tn/cli.py` | `ts-sdk/src/runtime/config.ts`, `ts-sdk/src/multi.ts` | `crypto/tn-core/src/config.rs` | target-only | Draft `docs/spec-next/yaml-model.md` with root/stream overlay examples. |
| YAML extends/merge | Shared semantics for stream overlay extending Project root; handler, public field, vault, and group merge behavior identical across languages. | `python/tn/config.py` | `ts-sdk/src/runtime/config.ts` | `crypto/tn-core/src/config.rs` | in progress | Python handler replacement semantics are now documented in `docs/spec-next/yaml-model.md` and matched in TS/Rust tests. Broader project/vault YAML fields still need fixtures. |
| YAML public fields | Default public fields plus user additions behave identically across SDKs. | `python/tn/config.py` | `ts-sdk/src/runtime/config.ts` | `crypto/tn-core/src/config.rs` | partial | Add fixture for minimal YAML and YAML with one extra public field. |
| YAML vault block | Vault is explicitly on when present/enabled; no vault block means off. Init default creates it unless `vault=False`; absorb-created Project only adopts it from authoritative package. | `python/tn/config.py`, `python/tn/cli.py`, `python/tn/sync_state.py` | `ts-sdk/src/runtime/config.ts`, `ts-sdk/src/wallet/index.ts` | `crypto/tn-core/src/config.rs` | in progress | Block fields are specified in `docs/spec-next/yaml-model.md`. Python/TS/Rust now parse the project-level block, default `sync_interval_seconds` to `600`, bridge legacy `ceremony.linked_*` only when no block exists, and suppress legacy fields when `vault.enabled=false`. Python/TS fresh init and wallet link/unlink now emit/update the block. Python/TS project_seed absorb now fills empty vault URL/project id from root-authoritative packages without overwriting non-empty local values. Python wallet sync now uses the normalized vault view and continues excluding app logs. Next: TS wallet sync remains deferred; autosync interval scheduling still needs a shared contract. |
| Profile immutability | Profile is creation-time. Existing YAML wins; code-supplied mismatch warns, does not fail logging. | `python/tn/_profiles.py`, `python/tn/_multi.py`, `python/tn/config.py` | `ts-sdk/src/profiles.ts`, `ts-sdk/src/multi.ts` | `crypto/tn-core/src/config.rs`, `crypto/tn-core/src/runtime.rs` | parity (py+ts) | Done at parity bar: behavioral contract specified in `docs/spec-next/profiles.md` (known mismatch warns + on-disk wins; unknown profile raises; shared operator-authority warning text) with matching tests `python/tests/test_multi_ceremony.py::TestConflictPolicy` and `ts-sdk/test/profile_conflict.test.ts`. |
| Absorb additive behavior | Absorb adds capabilities/state only; never destructive import/restore; may auto-create Project. | `python/tn/absorb.py`, `python/tn/_pkg_impl.py`, `python/tn/pkg.py`, `python/tn/cli.py` | `ts-sdk/src/runtime/absorb_bootstrap.ts`, `ts-sdk/src/pkg/index.ts`, `ts-sdk/src/tn.ts` | `crypto/tn-core/src/tnpkg.rs` | documented | `AbsorbReceipt` fields + additive/conflict semantics documented in `docs/spec-next/absorb.md`; receipt covered by `python/tests/test_absorb.py` + `ts-sdk/test/absorb_replaced_kit_paths.test.ts`. Remaining nicety: a cross-language AbsorbReceipt-shape golden. |
| Root authority on absorb | Missing Project can be established by root-authoritative project package; kit bundle cannot become root. | `python/tn/absorb.py`, `python/tn/export.py` | `ts-sdk/src/runtime/absorb_bootstrap.ts` | `crypto/tn-core/src/tnpkg.rs` | documented + py/ts tests | Rule specified in `docs/spec-next/absorb.md` (self-addressed tamper guard; project_seed/identity_seed establish root; kit_bundle mints fresh root + installs as capability). Covered by `python/tests/test_project_seed.py`, `ts-sdk/test/identity_project_seed.test.ts`, `crypto/tn-core/tests/tnpkg_export_absorb.rs`. |
| Vault metadata adoption | Absorb fills empty vault metadata only from root-authoritative package; never overwrites non-empty local metadata. | `python/tn/absorb.py`, `python/tn/sync_state.py`, `python/tn/config.py` | `ts-sdk/src/runtime/absorb_bootstrap.ts`, `ts-sdk/src/wallet/index.ts` | `crypto/tn-core/src/tnpkg.rs` | parity (py+ts) | Done at parity bar: shared golden `tests/fixtures/absorb/vault_adoption_cases.json` (empty-fill / non-overwrite / `enabled:false`-block / partial-fill / no-block) + cross-language tests (`python/tests/test_absorb_vault_adoption_contract.py`, `ts-sdk/test/absorb_vault_adoption_contract.test.ts`) + `docs/spec-next/absorb.md`. |
| Wallet link | `wallet link --project X` attaches Project to Vault Project, initial backs up if new, adds `vault.sync`, does not imply full resync if already linked. | `python/tn/cli.py`, `python/tn/wallet.py`, `python/tn/vault_client.py` | `ts-sdk/src/wallet/index.ts`, `ts-sdk/src/vault/client.ts` | not primary | partial | Add `--project` flow and define idempotent linked behavior. |
| Wallet sync | `wallet sync --project X` push/pulls `.tnpkg` and auto-absorbs inbound packages additively. | `python/tn/cli.py`, `python/tn/wallet.py`, `python/tn/handlers/vault_sync.py`, `python/tn/handlers/vault_push.py`, `python/tn/handlers/vault_pull.py` | `ts-sdk/src/wallet/index.ts`, `ts-sdk/src/handlers/vault_push.ts`, `ts-sdk/src/handlers/vault_pull.ts` | `crypto/tn-core/src/handlers/vault_push.rs`, `crypto/tn-core/src/handlers/vault_pull.rs` | partial | Replace raw file sync path with package sync path. Keep stage-only as debug option if needed. |
| Vault sync handler | Linked Projects get `vault.sync` by default, interval 600s, sleeps quietly until link/auth ready, rate-limits warnings. | `python/tn/handlers/vault_sync.py`, `python/tn/handlers/registry.py`, `python/tn/cli.py` | `ts-sdk/src/handlers/registry.ts`, possible new `vault_sync.ts` | `crypto/tn-core/src/handlers/mod.rs`, `crypto/tn-core/src/handlers/vault_push.rs`, `crypto/tn-core/src/handlers/vault_pull.rs` | partial | Make one conceptual handler contract; lower-level push/pull become implementation details. |
| Local vault state dir | Package staging/cache/sync state lives under `.tn/<project>/vault/`. | `python/tn/sync_state.py`, `python/tn/conventions.py`, `python/tn/handlers/vault_push.py`, `python/tn/handlers/vault_pull.py` | `ts-sdk/src/runtime/storage_node.ts`, `ts-sdk/src/handlers/vault_pull.ts`, `ts-sdk/src/handlers/vault_push.ts` | `crypto/tn-core/src/storage.rs` | target-only | Define local directory names and lifecycle: pending/sent/received/absorbed/failed/conflicts. |
| Import/restore surface | Public package handling should be absorb-oriented and additive; destructive restore/import must be explicit advanced flow, not the main path. | `python/tn/cli.py`, `python/tn/wallet_restore.py`, `python/tn/absorb.py` | `ts-sdk/src/wallet/restore.ts`, `ts-sdk/src/tn.ts` | not primary | partial | Mark current `tn import` and restore flows as compatibility/advanced in docs; plan deprecation or rename later. |
| Browser/vault compatibility | Browser JS and extension surfaces use the same manifest/package/shared-core rules as Node/Python. | not browser-specific | `ts-sdk/src/index.browser.ts`, `ts-sdk/src/browser/tn.ts`, `extensions/tn-decrypt/*` | `crypto/tn-wasm/src/*` | unknown | Audit browser package read/absorb/decrypt paths after manifest and package fixtures exist. |

## First Slice: Manifest

Do not start by changing init/use/layout. Start with the smallest durable
protocol surface.

Deliverables:

1. `docs/spec-next/manifest.md`
2. fixtures:
   - minimal unsigned manifest per kind
   - complete signed `project_seed`
   - complete signed `kit_bundle`
   - manifest with unknown kind
   - manifest with extra field
   - tampered signature case
3. golden canonical bytes:
   - JSON text
   - UTF-8 bytes as hex
   - signature input hash if useful
4. tests:
   - Python canonicalizes every fixture
   - TS canonicalizes every fixture
   - Rust canonicalizes every fixture
   - all outputs are byte-identical
   - Python-signed manifests verify in TS/Rust
   - TS-signed manifests verify in Python/Rust
   - Rust-signed manifests verify in Python/TS

Expected code movement after tests:

- Rust owns manifest schema/canonicalization/signature verification where
  practical.
- Python and TS keep ergonomic wrappers and IO.
- Package read/write still stays in place until the next slice.

## Second Slice: `.tnpkg`

Deliverables:

1. `docs/spec-next/tnpkg.md`
2. fixture packages:
   - unsealed `kit_bundle`
   - sealed `kit_bundle`
   - project backup package excluding app logs
   - package with unexpected root member
   - package with app log member that must be rejected/excluded
3. tests:
   - inspect package without mutating state
   - enumerate body members identically
   - verify manifest before body trust
   - reject malformed packages consistently

Expected code movement:

- shared package reader/index model
- shared sealed body frame parser
- SDK-specific filesystem/storage adapters remain outside core

## Third Slice: Layout And YAML

Directory planning should be pure data, not filesystem mutation.

Candidate API:

```text
plan_init(cwd, project?, vault_enabled?, profile?) -> LayoutPlan
plan_use(cwd, current_project?, stream, project?, profile?) -> LayoutPlan
plan_absorb(cwd, project?, package_authority) -> LayoutPlan
plan_wallet(cwd, project?, yaml?) -> LayoutPlan
```

YAML boundary:

```text
SDK parses YAML -> JSON-like value
shared core validates/normalizes -> normalized config
```

This avoids making browser/Node/Python/Rust argue about YAML parser behavior
while still sharing the protocol decisions.

## Fourth Slice: Verbs

Only after manifest, package, layout, and YAML are pinned:

- `tn.init`
- `tn.use`
- `tn.absorb`
- `tn wallet link`
- `tn wallet sync`
- `vault.sync`

Each verb should be specified as state transitions:

```text
given filesystem/config/package state
when verb runs
then files/config/package receipts/handler state are produced
```

No verb should be replaced in only one SDK without parity tests for the others.

## Open Questions To Resolve During Audit

1. Exact name and compatibility story for `project_seed` versus a future
   `project_snapshot`.
2. Whether raw admin files remain in backup packages during phase 1, and the
   exact derived state snapshot shape for phase 2.
3. Exact `vault.sync` handler YAML shape.
4. Whether `wallet sync --stage-only` remains as a debug/inspection mode.
5. Exact warning text and warning rate limits for sleeping or failing vault
   sync.
6. Whether old `.tn/default` and `.tn/<stream>` sibling layouts are migrated
   automatically or only read compatibly.
