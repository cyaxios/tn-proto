# tn-proto Rust SDK Reference

Temporary working docs for the in-repo Rust SDK. This file is meant to be a
high-signal map of what the library currently exposes while the public API is
still settling.

The package name is `tn-proto`. The Rust import path is `tn_proto`.

```toml
[dependencies]
tn-proto = { path = "../tn-proto/rust-sdk" }
```

For vault HTTP support:

```toml
[dependencies]
tn-proto = { path = "../tn-proto/rust-sdk", features = ["http"] }
```

```rust
use tn_proto::{ReadOptions, Tn};
```

## Feature Flags

- `fs`: enabled by default; filesystem-backed `tn-core` runtime.
- `http`: enables blocking vault HTTP APIs through `reqwest`.
- `watch`: enables synchronous native file notification support.
- `async`: reserved for future async watch support.
- `cli`: builds the small `tn-proto` binary and enables `http`.

## Main Handle

The central type is `Tn`, which wraps one loaded TN ceremony/runtime.

Project creation and loading:

- `Tn::init(path)`: open an existing `tn.yaml`.
- `Tn::init_with_options(path, TnInitOptions)`: open an existing ceremony with init flags.
- `Tn::init_project(name)`: create or open `.tn/<name>/tn.yaml` in the current workspace.
- `Tn::init_project_with_options(name, TnProjectOptions)`: project init with explicit directory, profile, device seed, or init options.
- `Tn::init_project_with_vault_claim(name, client)`: with `http`, create/open a project and upload an encrypted pending vault claim.
- `Tn::init_project_with_vault_claim_options(name, client, options)`: same, with explicit project and upload options.
- `Tn::ephemeral()`: create a temporary BTN-backed ceremony for tests and examples.
- `Tn::close()`: flush/close the underlying runtime.

Project options:

- `TnProjectOptions::project_dir`: workspace directory that owns `.tn/<project>/`.
- `TnProjectOptions::device_private_bytes`: explicit 32-byte Ed25519 project device seed.
- `TnProjectOptions::profile`: one of `transaction`, `audit`, `secure_log`, `telemetry`, `stdout`.
- `TnProjectOptions::init`: lower-level init flags.

Profiles:

- `TnProfile::Transaction`
- `TnProfile::Audit`
- `TnProfile::SecureLog`
- `TnProfile::Telemetry`
- `TnProfile::Stdout`
- `TnProfile::from_name(name)`
- `TnProfile::as_str()`

Runtime views:

- `tn.config()`: returns `ConfigView`.
- `tn.did()`: active device DID.
- `tn.yaml_path()`: active `tn.yaml`.
- `tn.log_path()`: active log path.

## Emit And Read

Emit helpers:

- `tn.log(event_type, fields)`
- `tn.debug(event_type, fields)`
- `tn.info(event_type, fields)`
- `tn.warning(event_type, fields)`
- `tn.error(event_type, fields)`
- `tn.emit(level, event_type, fields)`

All field payloads must serialize to a JSON object. The return type is
`EmitReceipt`.

Read helpers:

- `tn.read(ReadOptions)`: returns `Vec<Entry>`.
- `ReadOptions::all_runs`: include all rows rather than only this process run.
- `ReadOptions::verify`: include verification metadata.

`Entry` is the stable Rust-facing read wrapper:

- `entry.get(key)`
- `entry.event_type()`
- `entry.event_id()`
- `entry.sequence()`
- `entry.timestamp()`
- `entry.level()`
- `entry.device_identity()`
- `entry.row_hash()`
- `entry.prev_hash()`
- `entry.validity()`
- `entry.into_value()`

## Admin Namespace

Access with `tn.admin()`.

Group and recipient helpers:

- `ensure_group(group, fields)`: create or update a BTN group and route fields into it.
- `add_recipient(group, recipient_did, out_kit_path)`: mint a reader kit for a DID.
- `revoke_recipient(group, leaf_index)`: revoke a reader by BTN leaf index.
- `recipients(group, include_revoked)`: list recipient state.
- `revoked_count(group)`: count revoked recipients in publisher state.
- `state(group)`: replay and materialize admin state.

Return types:

- `EnsureGroupResult`
- `AddRecipientResult`
- `RevokeRecipientResult`
- `RecipientEntry`

## Package Namespace

Access with `tn.pkg()`.

Export helpers:

- `export_admin_snapshot(path)`: governance/admin state snapshot.
- `export_kit_bundle(path, options)`: package existing local reader kits.
- `bundle_for_recipient(recipient_did, path, options)`: mint recipient-specific kits and package them.
  Set `BundleForRecipientOptions::seal_for_recipient = true` to encrypt the
  package body and wrap the body key for the recipient. Sealing requires a real
  Ed25519 `did:key:z...` recipient DID; placeholder/keyless DIDs are rejected.
  Recipients whose local device identity matches the wrap can absorb the sealed
  bundle with `absorb_path` / `absorb_bytes`.
- `export_group_keys(path, options)`: wallet-sync compatible group-key package.
- `export_project_seed(path, to_did, consent)`: secret project seed package.
- `export_identity_seed(path, to_did, consent)`: secret identity seed package.
- `export_full_keystore(path, options, consent)`: secret full keystore package.
- `export(path, ExportOptions)`: lower-level package export.
- `compile_enrolment(CompileEnrolmentOptions)`: compile a recipient handoff package for one group.
- `offer(OfferOptions)`: compile the handoff package and emit `tn.offer.compiled`.

`compile_enrolment` and `offer` follow the current TypeScript public SDK flow:
they produce signed `kit_bundle` packages narrowed to the recipient/group,
rather than the older Python JWE-only `body/package.json` enrolment shape. Use
`export(path, ExportOptions)` for low-level `offer` or `enrolment` manifest
experiments.

Absorb and inspection:

- `absorb_path(path)`
- `absorb_bytes(bytes)`
- `inspect_path(path)`
- `inspect_bytes(bytes)`
- `package_json_path(path)`
- `package_json_bytes(bytes)`

Contact update:

- `contact_update_path(path)`
- `contact_update_bytes(bytes)`
- `apply_contact_update_path(path)`
- `apply_contact_update_bytes(bytes)`
- `ContactUpdateBody::from_json(value)`

Important package types:

- `PackageInfo`
- `PackageManifest`
- `PackageCategory`
- `PackageSignatureStatus`
- `PackageJsonPayload`
- `AbsorbReceipt`
- `AbsorbStatus`
- `AbsorbReceiptExt`
- `SecretExportConsent`
- `BundleForRecipientOptions`: `groups`, `seal_for_recipient`
- `BundleForRecipientResult`
- `CompileEnrolmentOptions`
- `CompiledPackage`
- `OfferOptions`
- `OfferReceipt`

Secret exports require `SecretExportConsent::acknowledge()`.

## Inbox / Recipient Invites

Access with `tn.inbox()`.

Local invite helpers:

- `list_local(dir)`: list `tn-invite-*.zip` files.
- `inspect_path(path)`
- `inspect_bytes(bytes)`
- `accept_path(path)`
- `accept_bytes(bytes)`
- `mint_invite_path(recipient_did, out_path, MintInvitationOptions)`

Free functions:

- `list_local_invites(dir)`
- `inspect_invitation_path(path)`
- `inspect_invitation_bytes(bytes)`

Invite types:

- `InvitationManifest`
- `InvitationInfo`
- `InvitationKitHash`
- `InvitationAcceptResult`
- `MintInvitationOptions`
- `MintInvitationResult`

Rust invite zips are shaped to match Python and TypeScript:
`manifest.json` plus an inner `<group>.btn.mykit` reader kit.

## Watch Namespace

Access with `tn.polling_watch(options)` or the compatibility
`tn.watch(options)` helper.

The current watcher is synchronous and polling/read-backed. It is not a native
filesystem notification watcher.

Options and helpers:

- `WatchOptions::default()`
- `PollingWatchOptions::default()`
- `WatchOptions::event_type`
- `WatchOptions::event_type_prefix`
- `WatchOptions::start`
- `WatchOptions::poll_interval`
- `WatchOptions::read`
- `WatchStart::Beginning`
- `WatchStart::Latest`
- `tn.polling_watch(options)`
- `watch.poll()`
- `watch.wait_for_entries(timeout)`
- `watch.into_iter_until_idle(idle_timeout)`

If `event_type` and `event_type_prefix` are both set, both filters must match.

With the `watch` feature enabled, use
`tn.native_watch(NativeWatchOptions::default())` for a synchronous
`notify`-backed watcher. It wakes on native file events, then decrypts and
filters entries through the same read-backed path as `PollingWatch`.

## Identity

Identity helpers manage the machine-global or caller-supplied identity used by
project creation and vault account flows.

Core functions and types:

- `Identity::load(path)`
- `Identity::save(path, IdentitySaveOptions)`
- `Identity::load_or_mint(path)`
- `Identity::from_private_bytes(bytes)`
- `Identity::from_mnemonic(phrase)`
- `Identity::to_mnemonic(word_count)`
- `Identity::vault_wrap_key()`
- `IdentitySaveOptions`
- `IdentityPrefs`
- `default_identity_dir()`
- `default_identity_path()`

## Account Namespace

Access with `tn.account()`.

Local account state:

- `status()`
- `whoami()`
- `status_with_store(store)`
- `logout()`
- `logout_with_store(store)`
- `use_vault(vault_url)`
- `use_vault_at(identity_path, vault_url)`

HTTP connect-code support, behind `http`:

- `connect_code_http(code, AccountConnectOptions)`

Important types:

- `AccountStatus`
- `AccountState`
- `AccountVerdict`
- `AccountUseVaultResult`
- `AccountLogoutResult`
- `AccountIdentityMetadata`
- `AccountConnectOptions`
- `AccountConnectResult`
- `ResolvedSigningIdentity`
- `SigningIdentityTier`

## Credential Store

Credential stores hold cached account AWKs and related local secrets.

Functions and types:

- `CredentialStore`
- `FileCredentialStore`
- `default_credential_store()`
- `load_cached_account_awk(store, account_id)`
- `cache_account_awk_with_client(client, store, account_id, passphrase, credential_id)` with `http`
- `awk_key_name(account_id)`

## Vault Namespace

Access with `tn.vault()`.

Local link-state:

- `link(vault_identity, project_id)`
- `connect(VaultConnectOptions)`
- `connect_with_client(client, VaultClientConnectOptions)`
- `unlink(vault_identity, project_id, reason)`
- `set_link_state(state, SetLinkStateOptions)`
- `link_state()`

Project/body helpers:

- `project_identity()`
- `collect_body()`
- `install_body(body, VaultInstallBodyOptions)`

Pending claim onboarding, behind `http`:

- `init_upload_http(client, VaultInitUploadOptions)`
- `Tn::init_project_with_vault_claim(project, client)`
- `Tn::init_project_with_vault_claim_options(project, client, options)`

HTTP project connection, behind `http`:

- `connect_http(identity, VaultHttpConnectOptions)`
- `push_body_with_http_client(client, VaultPushBodyOptions)`
- `push_body_with_awk_http_client(client, VaultPushWithAwkOptions)`
- `push_body_with_passphrase_http_client(client, passphrase, VaultPushWithPassphraseOptions)`
- `push_body_with_cached_awk(client, store, VaultPushWithCachedAwkOptions)`
- `restore_body_with_awk_http_client(client, VaultRestoreWithAwkOptions)`
- `restore_body_with_passphrase_http_client(client, passphrase, VaultRestoreWithPassphraseOptions)`
- `restore_body_with_cached_awk_http_client(client, store, VaultRestoreWithCachedAwkOptions)`
- `restore_and_install_body_with_awk_http_client(client, restore_options, install_options)`
- `restore_and_install_body_with_passphrase_http_client(client, passphrase, restore_options, install_options)`
- `restore_and_install_body_with_cached_awk_http_client(client, store, restore_options, install_options)`

Vault HTTP client, behind `http`:

- `VaultHttpProjectClient::new(base_url)`
- `VaultHttpProjectClient::with_options(options)`
- `VaultHttpProjectClient::for_identity(identity, options)`
- `set_bearer_token(token)`
- `authenticate_identity(identity)`
- `create_project(name, ceremony_id)`
- `list_projects()`
- `get_project(project_id)`
- `delete_project(project_id)`
- `restore_manifest(project_id)`
- `list_files(project_id)`
- `upload_sealed(project_id, file_name, bytes, content_type)`
- `download_sealed(project_id, file_name)`
- `delete_file(project_id, file_name)`
- `derive_awk_from_passphrase(account_id, passphrase, credential_id)`
- `get_credential_wrap(account_id, credential_id)`
- `get_wrapped_key(account_id, project_id)`
- `put_wrapped_key(account_id, project_id, wrapped)`
- `get_encrypted_blob(account_id, project_id)`
- `put_encrypted_blob_account(account_id, project_id, encrypted)`
- `list_account_inbox()`
- `download_account_inbox_package(from_did, ceremony_id, ts)`
- `post_inbox_snapshot(did, ceremony_id, name, package)`
- `post_pending_claim(package_bytes, project_name, publisher_did)`

Vault crypto helpers:

- `VaultAwk`
- `VaultBek`
- `VaultWrappedBek`
- `VaultCredentialWrap`
- `VaultCredentialKdfParams`
- `VaultBodyPlaintext`
- `derive_awk_from_material`
- `derive_bek_from_material`
- `derive_credential_key_pbkdf2`
- `wrap_bek_under_awk`
- `wrap_bek_under_awk_with_nonce`
- `unwrap_bek_from_awk`
- `encrypt_vault_body`
- `encrypt_vault_body_with_nonce`
- `decrypt_vault_body`
- `install_vault_body`

Vault constants:

- `VAULT_AWK_WRAP_AAD`
- `VAULT_BEK_WRAP_AAD`
- `VAULT_BODY_CIPHER_SUITE`
- `VAULT_BODY_FRAME`
- `VAULT_MIN_PBKDF2_ITERATIONS`

## Wallet Namespace

Access with `tn.wallet()`.

Local paths and state:

- `wallet_paths(yaml_path)`
- `stem_dir(yaml_path)`
- `inbox_dir(yaml_path)`
- `wallet_sync_state_path(yaml_path)`
- `wallet_is_account_bound(yaml_path)`
- `safe_path_segment(segment)`
- `tn.wallet().paths()`
- `tn.wallet().inbox_dir()`
- `tn.wallet().is_account_bound()`

Local staging:

- `absorb_staged_packages()`

HTTP wallet sync, behind `http`:

- `stage_account_inbox(client, WalletStageInboxOptions)`
- `pull_and_absorb(client, WalletStageInboxOptions)`
- `push_body_with_cached_awk(client, store, VaultPushWithCachedAwkOptions)`
- `publish_group_keys(client, WalletPublishGroupKeysOptions)`
- `sync_with_cached_awk(client, store, WalletSyncOptions)`

Important wallet types:

- `WalletPaths`
- `WalletStageInboxOptions`
- `WalletStageInboxResult`
- `WalletPullAbsorbResult`
- `WalletPublishGroupKeysOptions`
- `WalletPublishGroupKeysResult`
- `WalletSyncOptions`
- `WalletSyncResult`

## Errors

All public fallible SDK APIs use:

- `tn_proto::Result<T>`
- `tn_proto::Error`

The error enum wraps protocol/runtime failures, IO, JSON/YAML parsing, zip
errors, invalid arguments, verification failures, and vault HTTP failures.

## Examples

Run from the repository root:

```bash
cargo run -p tn-proto --example hello
cargo run -p tn-proto --example read
cargo run -p tn-proto --example admin_group
cargo run -p tn-proto --example revocation
cargo run -p tn-proto --example package
cargo run -p tn-proto --example invite
cargo run -p tn-proto --example watch
cargo run -p tn-proto --features http --example vault_claim
cargo run -p tn-proto --features http --example vault_passphrase
```

`vault_claim` targets `https://vault.tn-proto.org` by default and prints a
secret claim URL. Treat that URL like a password.

## CLI Preview

The optional `cli` feature builds a small developer/user binary around the SDK.
Current commands:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- init payments
cargo run -p tn-proto --features cli --bin tn-proto -- claim-link payments
cargo run -p tn-proto --features cli --bin tn-proto -- read --yaml .tn/payments/tn.yaml --all-runs
cargo run -p tn-proto --features cli --bin tn-proto -- read --yaml .tn/payments/tn.yaml --verify --pretty
cargo run -p tn-proto --features cli --bin tn-proto -- verify --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- show --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- watch --yaml .tn/payments/tn.yaml --event-type-prefix payment.
cargo run -p tn-proto --features cli --bin tn-proto -- inbox list --dir .
cargo run -p tn-proto --features cli --bin tn-proto -- inbox inspect ./tn-invite-example.zip
cargo run -p tn-proto --features cli --bin tn-proto -- inbox accept ./tn-invite-example.zip --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- inbox mint did:key:zRecipient ./tn-invite-recipient.zip --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- pkg inspect ./package.tnpkg --entries
cargo run -p tn-proto --features cli --bin tn-proto -- pkg absorb ./package.tnpkg --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- pkg compile-enrolment --yaml .tn/payments/tn.yaml --recipient did:key:zRecipient --group default --out ./enrolment.tnpkg
cargo run -p tn-proto --features cli --bin tn-proto -- pkg offer --yaml .tn/payments/tn.yaml --peer did:key:zRecipient --group default --out ./offer.tnpkg
cargo run -p tn-proto --features cli --bin tn-proto -- pkg export admin-snapshot --yaml .tn/payments/tn.yaml --out ./admin-snapshot.tnpkg
cargo run -p tn-proto --features cli --bin tn-proto -- pkg export bundle-for-recipient --yaml .tn/payments/tn.yaml --recipient did:key:zRecipient --out ./reader-bundle.tnpkg --seal-for-recipient
cargo run -p tn-proto --features cli --bin tn-proto -- pkg export recipient-handoff --yaml .tn/payments/tn.yaml --recipient did:key:zRecipient --out-dir ./handoff --group default --seal-for-recipient
cargo run -p tn-proto --features cli --bin tn-proto -- group list --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- group recipients payments --yaml .tn/payments/tn.yaml --include-revoked
cargo run -p tn-proto --features cli --bin tn-proto -- group add payments --yaml .tn/payments/tn.yaml --fields order_id,amount
cargo run -p tn-proto --features cli --bin tn-proto -- group add-recipient payments did:key:zRecipient --yaml .tn/payments/tn.yaml --out ./recipient.btn.mykit
cargo run -p tn-proto --features cli --bin tn-proto -- group revoke-recipient payments 1 --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- auth connect-code tn_connect_... --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- auth status --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- auth whoami --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- auth logout --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- vault connect --yaml .tn/payments/tn.yaml --project-id proj_...
cargo run -p tn-proto --features cli --bin tn-proto -- vault unlink --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet status --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet sync --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet restore --yaml .tn/payments/tn.yaml --target-dir ./restored-payments
cargo run -p tn-proto --features cli --bin tn-proto -- wallet unlink --yaml .tn/payments/tn.yaml
```

`init`:

- Creates or opens `.tn/<project>/tn.yaml`.
- Prints the project name, yaml path, and device DID.
- Supports `--project-dir <dir>`.

`claim-link`:

- Creates or opens the project.
- Uploads an encrypted pending claim to the vault.
- Prints the claim URL and expiry.
- Defaults to `https://vault.tn-proto.org`.
- Supports `--vault <url>`, `TN_VAULT_URL`, and `--project-dir <dir>`.

Treat claim URLs as secrets because the `#k=` fragment contains the decryption
key for the pending backup.

`read`:

- Reads decrypted entries from an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Defaults to this process run only, matching the SDK's default read behavior.
- Supports `--all-runs`, `--verify`, and `--pretty`.
- Prints compact newline-delimited JSON by default.

`verify`:

- Reads all runs from an existing ceremony with verification enabled.
- Requires `--yaml <path-to-tn.yaml>`.
- Prints the yaml path, entry count, invalid count, and overall validity.
- Exits with a non-zero status if signature, row hash, or chain verification
  fails for any entry.

`show`:

- Prints local ceremony diagnostics without making network calls.
- Requires `--yaml <path-to-tn.yaml>`.
- Includes yaml/log paths, DID, entry count, configured groups, local account
  binding, vault link-state, and wallet paths.

`watch`:

- Prints entries as they become visible.
- Requires `--yaml <path-to-tn.yaml>`.
- Uses the polling watcher by default.
- Supports `--from-beginning`, `--event-type`, `--event-type-prefix`,
  `--limit`, `--timeout-ms`, `--verify`, and `--pretty`.
- Supports `--native` when the CLI is built with `--features cli,watch`.

`inbox list`:

- Lists `tn-invite-*.zip` files in a directory.
- Defaults to the current directory.
- Supports `--dir <dir>`.

`inbox inspect`:

- Inspects a `tn-invite-*.zip` without accepting it.
- Requires an invite zip path.
- Validates the zip shape, parses `manifest.json`, identifies the inner kit,
  and verifies `kit_sha256` when present.
- Prints group, sender, project, leaf index, kit entry, kit byte count, actual
  kit hash, hash verification status, created timestamp, provenance, and note.

`inbox accept`:

- Accepts a `tn-invite-*.zip` into an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Prints group, sender label, leaf index when present, installed kit path,
  backup path when a previous kit was replaced, and absorbed timestamp.

`inbox mint`:

- Mints a recipient invitation zip.
- Requires `<recipient>` and `<out.zip>` positionals.
- Requires `--yaml <path-to-tn.yaml>` for the publisher ceremony.
- Supports `--group <name>`, `--from-email <label>`,
  `--project-name <name>`, `--note <text>`, and
  `--invitation-id <id>`.
- Reads current YAML vault link-state to include linked project id when present.
- Prints invite path, recipient DID, group, sender label, leaf index, kit hash,
  inner kit name, and byte size.

`pkg inspect`:

- Inspects a `.tnpkg` without absorbing it.
- Requires a package path.
- Supports `--entries` to print every package body entry name.
- Prints kind, category, signature/verified status, publisher, recipient,
  ceremony id, body entry count, reader-key flag, and secret-material flag.

`pkg absorb`:

- Absorbs a `.tnpkg` into an existing ceremony.
- Requires a package path and `--yaml <path-to-tn.yaml>`.
- Prints package kind, high-level status, legacy status/reason, accepted and
  deduped counts, no-op flag, conflict count, and replaced kit paths.
- Malformed or unsupported packages are reported through the receipt status
  rather than treated as process errors when the SDK can parse a receipt.

`pkg compile-enrolment`:

- Writes a signed recipient handoff `kit_bundle` for one group.
- Requires `--yaml <path-to-tn.yaml>`, `--recipient <did>`, and
  `--out <file.tnpkg>`.
- Supports `--group <name>` and `--seal-for-recipient`.
- Prints package path, source YAML, recipient DID, groups, kind, verification
  status, sealed flag, manifest/package hashes, reader-key flag, and
  secret-material flag.

`pkg offer`:

- Writes the same handoff package as `pkg compile-enrolment`.
- Emits `tn.offer.compiled` to the local log for dashboard/wallet tracking.
- Requires `--yaml <path-to-tn.yaml>`, `--peer <did>`, and
  `--out <file.tnpkg>`.
- Supports `--group <name>` and `--seal-for-recipient`.
- Prints package path, source YAML, peer DID, group, status, kind,
  verification status, sealed flag, package hash, reader-key flag, and
  secret-material flag.

`pkg export admin-snapshot`:

- Exports a governance/admin snapshot package.
- Requires `--yaml <path-to-tn.yaml>` and `--out <file.tnpkg>`.
- Does not include secret key material.
- Prints package path, source YAML, kind, verification status, body entry
  count, and secret-material flag.

`pkg export bundle-for-recipient`:

- Mints recipient-specific reader kits and exports them as a `kit_bundle`.
- Requires `--yaml <path-to-tn.yaml>`, `--recipient <did>`, and
  `--out <file.tnpkg>`.
- Supports comma-separated or repeated `--group <name>` filters.
- Supports `--seal-for-recipient` to encrypt the bundle body and wrap the
  body key for the recipient DID.
- Does not include admin snapshot state; send an admin snapshot separately
  when the recipient needs governance state too.
- Prints package path, source YAML, recipient DID, groups, kind, verification
  status, body entry count, sealed flag, reader-key flag, and
  secret-material flag.

`pkg export recipient-handoff`:

- Writes both handoff files a recipient normally needs:
  `admin-snapshot.tnpkg` and `reader-bundle.tnpkg`.
- Requires `--yaml <path-to-tn.yaml>`, `--recipient <did>`, and
  `--out-dir <dir>`.
- Supports comma-separated or repeated `--group <name>` filters for the reader
  bundle.
- Supports `--seal-for-recipient` for the reader bundle.
- Prints both package paths, verification status, secret-material status, and
  the files to send.

Recipient handoff workflow:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- group add payments --yaml .tn/payments/tn.yaml --fields order_id,amount
cargo run -p tn-proto --features cli --bin tn-proto -- pkg offer --yaml .tn/payments/tn.yaml --peer did:key:zRecipient --out ./offer.tnpkg --group payments --seal-for-recipient
cargo run -p tn-proto --features cli --bin tn-proto -- pkg export recipient-handoff --yaml .tn/payments/tn.yaml --recipient did:key:zRecipient --out-dir ./handoff --group payments --seal-for-recipient
cargo run -p tn-proto --features cli --bin tn-proto -- pkg absorb ./handoff/admin-snapshot.tnpkg --yaml .tn/recipient/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- pkg absorb ./handoff/reader-bundle.tnpkg --yaml .tn/recipient/tn.yaml
```

`group list`:

- Lists groups declared in an existing ceremony config.
- Requires `--yaml <path-to-tn.yaml>`.
- Prints the source YAML, group count, and one `group: <name>` line per group.

`group recipients`:

- Lists recipient leaves for a group by replaying admin events.
- Requires `<group>` and `--yaml <path-to-tn.yaml>`.
- Supports `--include-revoked`.
- Prints source YAML, group name, recipient count, leaf index, recipient DID,
  and revoked status.

`group add`:

- Creates or updates a BTN group in an existing ceremony.
- Requires `<name>` and `--yaml <path-to-tn.yaml>`.
- Supports comma-separated or repeated `--fields <name>` values for routing
  private fields into the group.
- Prints group name, source YAML, created/changed flags, routed fields, and
  cipher family.
- Reloads the ceremony internally so future emits use the new routing and key
  material.

`group add-recipient`:

- Mints a raw `.btn.mykit` reader kit for an existing group.
- Requires `<group>`, `<recipient-did>`, `--yaml <path-to-tn.yaml>`, and
  `--out <file.btn.mykit>`.
- Advances the publisher reader state and writes the kit file.
- Prints group name, recipient DID, leaf index, kit path, and source YAML.
- Use `inbox mint` or `pkg export bundle-for-recipient` when the goal is a
  shareable recipient handoff rather than a raw reader-kit file.

`group revoke-recipient`:

- Revokes a reader leaf from an existing group.
- Requires `<group>`, `<leaf-index>`, and `--yaml <path-to-tn.yaml>`.
- Persists the updated publisher reader state.
- Prints group name, leaf index, source YAML, and revoked status.

`auth connect-code`:

- Redeems a vault account connect code for an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Defaults to `https://vault.tn-proto.org`.
- Supports `--vault <url>`, `TN_VAULT_URL`, `--identity-path <identity.json>`,
  and `--machine-identity-path <identity.json>`.
- Prints account id, DID, signing tier, signing source, and project echo fields
  when the vault returns them.

`auth status` / `auth whoami`:

- Shows local account binding state for an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Prints DID, account id or not-bound marker, account-bound flag, cached-key
  flag, verdict, verdict message, local vault state, and linked vault/project
  fields when present.

`auth logout`:

- Clears local account binding for an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Removes pending-claim state.
- Deletes the cached account AWK for the previously bound account when present.
- Prints previous account id, cached-key deletion status, and resulting local
  account verdict.

`vault connect`:

- Links an existing local ceremony to a known vault project id.
- Requires `--yaml <path-to-tn.yaml>` and `--project-id <id>`.
- Defaults to `https://vault.tn-proto.org`.
- Supports `--vault <url>`, `TN_VAULT_URL`, `--project-name <name>`, and
  `--no-audit-event`.
- Updates local YAML link-state and optionally records a local
  `tn.vault.linked` audit event.
- Does not create or discover the remote vault project.

`vault unlink`:

- Clears local vault link-state for an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Infers the vault URL and project id from current YAML link-state when present.
- Supports explicit `--vault <url>` and `--project-id <id>` overrides.
- Supports `--reason <text>` and `--no-audit-event`.
- Updates local YAML back to `Local` mode and disables vault autosync state.

`wallet status`:

- Shows local wallet/account/vault diagnostics for an existing ceremony.
- Requires `--yaml <path-to-tn.yaml>`.
- Prints active yaml path, wallet root, wallet inbox path, wallet sync-state
  path, account binding, cached-key status, local wallet account-bound state,
  vault link-state, vault enabled/autosync flags, and linked vault/project
  fields when present.

`wallet sync`:

- Pulls account inbox packages, absorbs staged packages, publishes group-key
  snapshots, and pushes the encrypted project body.
- Requires `--yaml <path-to-tn.yaml>`.
- Defaults to `https://vault.tn-proto.org`.
- Supports `--vault <url>`, `TN_VAULT_URL`, `--pull-only`, `--push-only`,
  `--drain-queue`, `--identity-path`, `--account-id`, `--project-id`,
  repeated or comma-separated `--group`, `--passphrase`,
  `TN_VAULT_PASSPHRASE`, `--credential-id`, and `TN_VAULT_CREDENTIAL_ID`.
- Prints staged/absorbed/rejected counts, push status, account state, published
  groups, and non-fatal warnings.

`wallet restore`:

- Downloads, decrypts, and installs an encrypted vault project body.
- Requires `--yaml <path-to-tn.yaml>` for local account/link-state context.
- Requires `--target-dir <dir>` for restored `tn.yaml` and `keys/`.
- Defaults to `https://vault.tn-proto.org`.
- Supports `--vault <url>`, `TN_VAULT_URL`, `--account-id`, `--project-id`,
  `--passphrase`, `TN_VAULT_PASSPHRASE`, `--credential-id`,
  `TN_VAULT_CREDENTIAL_ID`, and `--overwrite`.
- Uses cached account AWK when available, or derives/caches it through the
  passphrase fallback.
- Refuses to overwrite different existing files unless `--overwrite` is set.
- Prints restored project id, target dir, restored yaml path, keys dir, and
  write/dedupe/skip counts.

`wallet unlink`:

- Wallet-oriented alias for `vault unlink`.
- Requires `--yaml <path-to-tn.yaml>`.
- Supports `--vault <url>`, `--project-id <id>`, `--reason <text>`, and
  `--no-audit-event`.
- Clears the same local vault link-state.

## Current Limits

- The crate is still developed in-repo and is not published to crates.io.
- `http` APIs are blocking.
- Polling watch is read-backed.
- Native file notification support is available behind the `watch` feature.
- Async watch APIs are reserved but not implemented.
- The vault claim URL flow works, but browser login/account UI is intentionally
  outside the library.
