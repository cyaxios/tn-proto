# tn-proto

Idiomatic Rust SDK for `tn-proto` attested logging.

`tn-proto` is the Rust-facing wrapper around the shared `tn-core` runtime used by
the Python and TypeScript SDKs. It provides a compact Rust API for creating TN
projects, writing signed events, reading verified entries, managing recipients,
exchanging `.tnpkg` artifacts, and syncing project bodies with a TN vault.

> Status: this crate is developed in-repo and is not published to crates.io yet.
> `Cargo.toml` currently has `publish = false` while the public API settles.

## Features

- Project lifecycle: `Tn::init_project`, `Tn::init`, `Tn::ephemeral`, `Tn::close`
- Event writing: `log`, `debug`, `info`, `warning`, `error`
- Event reading: stable `Entry` values with optional verification
- Admin: group creation/routing, recipient add/revoke, reduced admin state
- Packages: admin snapshots, reader kit bundles, guarded seed exports, absorb
  receipts and inspection
- Inbox: mint, inspect, list, and accept local `tn-invite-*.zip` recipient
  invitations
- Watch: synchronous polling watcher with filters and bounded waits
- Account: connect-code redemption and local account-bound sync state
- Vault: link-state, DID challenge auth, project create/discovery, AWK/BEK
  whole-body push and restore

## Installation

Inside this repository:

```toml
[dependencies]
tn-proto = { path = "rust-sdk" }
```

For vault HTTP support:

```toml
[dependencies]
tn-proto = { path = "rust-sdk", features = ["http"] }
```

The crate name is `tn-proto`; the Rust module path is `tn_proto`.

## Quickstart

```rust
use serde_json::json;
use tn_proto::{ReadOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init_project("payments")?;

    tn.info(
        "payment.created",
        json!({
            "order_id": "PAY-100",
            "amount": 2500,
            "currency": "USD"
        }),
    )?;

    for entry in tn.read(ReadOptions::default())? {
        println!("{} #{:?}", entry.event_type().unwrap_or("unknown"), entry.sequence());
    }

    Ok(())
}
```

`Tn::init_project("payments")` creates or reuses:

```text
.tn/identity.json
.tn/payments/
  tn.yaml
  keys/
  logs/
  admin/
  vault/
  streams/
```

The machine-global identity is compatible with the Python and TypeScript SDKs.
By default, each new project reuses that identity's device DID. Use
`device_private_bytes` only when you need to bind a ceremony to an explicit
32-byte Ed25519 seed.

To open an existing config directly:

```rust
let tn = tn_proto::Tn::init(".tn/payments/tn.yaml")?;
```

For tests or examples that should not touch a real project directory:

```rust
let tn = tn_proto::Tn::ephemeral()?;
```

## Project Options

Use `TnProjectOptions` when initializing a project with explicit settings:

```rust
use tn_proto::{Tn, TnProfile, TnProjectOptions};

let tn = Tn::init_project_with_options(
    "payments",
    TnProjectOptions {
        profile: TnProfile::Transaction,
        ..Default::default()
    },
)?;
```

Supported profiles are `transaction`, `audit`, `secure_log`, `telemetry`, and
`stdout`. When `project_dir` is supplied, Rust stores the identity at
`<project_dir>/.tn/identity.json`; otherwise it uses the standard platform
identity path.

## Reading Entries

`Tn::read` returns `Entry`, a stable SDK wrapper around the decrypted JSON row.
Use typed helpers for common envelope fields and `get` for event-specific data:

```rust
let entries = tn.read(tn_proto::ReadOptions {
    all_runs: true,
    verify: true,
})?;

for entry in entries {
    if entry.event_type() == Some("payment.created") {
        println!("{:?}", entry.get("order_id"));
    }
}
```

## Admin

Admin helpers manage groups, routing fields, recipients, and reduced admin
state.

```rust
use serde_json::json;
use tn_proto::Tn;

fn main() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;

    tn.admin().ensure_group("payments", ["order_id", "amount"])?;
    tn.info("payment.created", json!({ "order_id": "PAY-100", "amount": 2500 }))?;

    let state = tn.admin().state(None)?;
    println!("active recipients: {}", state.recipients.len());

    Ok(())
}
```

Admin changes that update `tn.yaml` reload the active runtime so later emits use
the new routing and key material.

## Packages

Packages use the `.tnpkg` format for moving TN state between projects or
devices.

### Admin Snapshot

Admin snapshots are safe to share with readers because they do not contain raw
private key material.

```rust
use tn_proto::AbsorbReceiptExt;

fn main() -> tn_proto::Result<()> {
    let producer = tn_proto::Tn::ephemeral()?;
    let path = producer.log_path().parent().unwrap().join("admin-snapshot.tnpkg");

    producer.pkg().export_admin_snapshot(&path)?;

    let consumer = tn_proto::Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&path)?;
    assert!(receipt.accepted() || receipt.no_op());

    Ok(())
}
```

### Reader Kit Bundle

Use `bundle_for_recipient` to mint fresh reader kit material for a recipient.
This packages recipient-specific kits rather than exporting the publisher's own
self-kit.

For a real recipient DID, set `seal_for_recipient: true` to encrypt the package
body and include a recipient wrap in the manifest. Keep it `false` for legacy
plaintext kit bundles or examples that use placeholder DIDs. A recipient whose
local device identity matches the wrap can absorb the sealed bundle normally.

```rust
use tn_proto::{AbsorbReceiptExt, BundleForRecipientOptions};

fn main() -> tn_proto::Result<()> {
    let producer = tn_proto::Tn::ephemeral()?;
    let path = producer.log_path().parent().unwrap().join("reader-kits.tnpkg");

    producer.pkg().bundle_for_recipient(
        "did:key:zRecipient",
        &path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: false,
        },
    )?;

    let consumer = tn_proto::Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert!(receipt.accepted());

    Ok(())
}
```

Send both a reader kit bundle and an admin snapshot when a recipient needs key
material and the current governance state.

### Enrolment And Offers

`compile_enrolment` is a convenience wrapper for the current recipient handoff
flow. It writes a signed `kit_bundle` for one recipient and group, matching the
TypeScript SDK's public `tn.pkg.compileEnrolment` behavior.

```rust
use tn_proto::CompileEnrolmentOptions;

fn main() -> tn_proto::Result<()> {
    let tn = tn_proto::Tn::ephemeral()?;
    let path = tn.log_path().parent().unwrap().join("enrolment.tnpkg");

    let compiled = tn.pkg().compile_enrolment(CompileEnrolmentOptions {
        group: "default".to_string(),
        recipient_did: "did:key:zRecipient".to_string(),
        out_path: path,
        seal_for_recipient: false,
    })?;

    println!("wrote {}", compiled.path.display());
    Ok(())
}
```

`offer` compiles the same handoff package and emits `tn.offer.compiled` to the
local log for dashboard and wallet tracking.

### Inspect Before Absorb

```rust
let info = tn.pkg().inspect_path("admin-snapshot.tnpkg")?;
assert!(info.verified());
assert!(!info.contains_secret_material());
```

### Secret Exports

Secret-bearing package exports require explicit consent:

```rust
use tn_proto::SecretExportConsent;

tn.pkg().export_project_seed(
    "project-seed.tnpkg",
    None,
    SecretExportConsent::acknowledge(),
)?;
```

Treat `full_keystore`, `project_seed`, and `identity_seed` packages as secrets.

## Recipient Invites

Recipient invites use the same local `tn-invite-*.zip` wrapper as the Python
and TypeScript SDKs. The zip contains a `manifest.json` plus one inner
`<group>.btn.mykit` reader kit. This is separate from the reserved
`recipient_invite` `.tnpkg` catalog kind.

```rust
use tn_proto::{MintInvitationOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let consumer = Tn::ephemeral()?;

    let invite = producer.log_path().parent().unwrap().join("tn-invite-peer.zip");

    producer.inbox().mint_invite_path(
        consumer.did(),
        &invite,
        MintInvitationOptions {
            from_email: Some("producer@example.test".to_string()),
            ..MintInvitationOptions::default()
        },
    )?;

    let accepted = consumer.inbox().accept_path(&invite)?;
    println!("installed {}", accepted.kit_path.display());

    Ok(())
}
```

`mint_invite_path` records Python-compatible manifest fields, including
`from_account_did`, `from_email`, `group_name`, `leaf_index`, `kit_sha256`,
`created_at`, and optional project/note metadata. Friendly labels are accepted
for local testing and use the same placeholder shape as Python:
`Frank` becomes `did:key:zLabel-Frank`. For real recipient-bound handoffs,
pass the recipient's actual `did:key:...` device DID.

`accept_path` verifies `kit_sha256`, installs the kit into the active
ceremony's keystore as `<group>.btn.mykit`, backs up an existing kit with a
`.previous.<UTC_TS>` suffix, and emits `tn.enrolment.absorbed`.

Use `inspect_path`, `inspect_bytes`, or `list_local` when an application wants
to preview or route downloaded invites before accepting them.

## Watch

The v0 watcher is synchronous, polling, and read-backed. It is useful for
small tools, tests, and bounded waits.

```rust
use std::time::Duration;
use tn_proto::{PollingWatchOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let entries = tn
        .polling_watch(PollingWatchOptions::default())?
        .into_iter_until_idle(Duration::from_millis(100))
        .collect::<tn_proto::Result<Vec<_>>>()?;

    println!("read {} entries", entries.len());
    Ok(())
}
```

`Tn::watch(WatchOptions::default())` remains available as a compatibility
alias. `PollingWatchOptions` is an alias for `WatchOptions`.

`WatchOptions::event_type` and `WatchOptions::event_type_prefix` can be used
together; when both are set, both filters must match.

This watcher calls `Tn::read` on each poll and tracks progress by the number of
entries in that read view. It is not a filesystem notification watcher, does not
tail bytes from the log file, and does not spawn a background task.

Enable the `watch` feature to use
`Tn::native_watch(NativeWatchOptions::default())`. The native watcher subscribes
to file changes with `notify`, then drains entries through the same read-backed
filtering logic as the polling watcher. It remains synchronous and does not
require an async runtime.

## Vault

Vault support is available in layers. Local link-state and audit events work
without HTTP. Networked vault operations require the `http` feature.

### Claim Link Onboarding

For first-run onboarding, Rust can mint the same cold pending-claim link used
by the Python and TypeScript SDKs. The SDK exports an AES-256-GCM encrypted
`full_keystore` package, posts it unauthenticated to `/api/v1/pending-claims`,
and returns a browser URL whose fragment carries the decryption key.

```rust
use tn_proto::{Tn, VaultHttpProjectClient};

fn main() -> tn_proto::Result<()> {
    let client = VaultHttpProjectClient::new("https://vault.example")?;

    let onboarding = Tn::init_project_with_vault_claim("payments", &client)?;

    println!("claim this project: {}", onboarding.claim.claim_url);
    Ok(())
}
```

For explicit project or upload options, use
`Tn::init_project_with_vault_claim_options`. The lower-level
`tn.vault().init_upload_http(...)` method remains available when a caller wants
to upload a claim for an already-opened project.

The claim URL is also written to `.tn/sync/claim_url.txt`, and a
`pending_claim` record is written to `.tn/sync/state.json`. Treat the full URL
as a secret: anyone holding the `#k=` fragment can decrypt and claim the
pending backup until it expires.

### Account Connect Codes

If the user already has a vault account and a connect code from the vault UI,
bind the local ceremony DID to that account:

```rust
use tn_proto::{AccountConnectOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init(".tn/payments/tn.yaml")?;

    let result = tn.account().connect_code_http(
        "tn_connect_...",
        AccountConnectOptions::new("https://vault.example"),
    )?;

    println!("connected account {}", result.account_id);
    Ok(())
}
```

This signs `SHA-256(code)`, posts the standard base64 signature to
`/api/v1/account/connect-codes/redeem`, and stamps `.tn/sync/state.json` with
`account_id` / `account_bound`. Signing identity resolution follows the
Python/TypeScript order: explicit identity path, machine-global `identity.json`,
then the ceremony `keys/local.private` fallback.

### Auth Boundary

The Rust SDK keeps browser login and device-flow UI outside the library for
now. Library APIs should stay deterministic and non-interactive: identity
mint/restore, vault selection, connect-code redemption, cached-key handling,
and vault HTTP primitives. The optional `tn-proto` CLI composes those pieces
for local onboarding and sync workflows without forcing GUI or
process-management behavior into application libraries.

### Local Link-State

```rust
use tn_proto::{Tn, VaultConnectOptions};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init_project("payments")?;

    tn.vault()
        .connect(VaultConnectOptions::new("https://vault.example", "proj_123"))?;

    let state = tn.vault().link_state()?;
    assert_eq!(state.linked_project_id.as_deref(), Some("proj_123"));

    Ok(())
}
```

`connect` updates local YAML and records a `tn.vault.linked` event by default.
It does not create a remote vault project. Use `connect_with_client` or
`connect_http` when the SDK should create or discover the project.

### HTTP Connect

Enable the `http` feature and authenticate with a TN device identity:

```rust
use tn_proto::{Tn, VaultDeviceIdentity, VaultHttpConnectOptions};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init_project("payments")?;
    let device_seed = std::fs::read(".tn/payments/keys/local.private")?;
    let identity = VaultDeviceIdentity::from_private_bytes(&device_seed)?;

    let result = tn.vault().connect_http(
        &identity,
        VaultHttpConnectOptions::new("https://vault.example"),
    )?;

    println!("linked vault project {}", result.project_id);
    Ok(())
}
```

`connect_http` performs the DID challenge flow:

1. `POST /api/v1/auth/challenge`
2. sign the nonce with the TN Ed25519 device key
3. `POST /api/v1/auth/verify`
4. create or discover the vault project
5. stamp local YAML link-state

If you already have a session token, provide it in
`VaultHttpProjectClientOptions::bearer_token` or set `TN_VAULT_SESSION_TOKEN`
or `TN_VAULT_JWT`.

### Push With Passphrase

The supported backup model is the same AWK/BEK whole-body flow used by the
Python and TypeScript SDKs:

```text
passphrase -> credential key -> account AWK -> project BEK -> encrypted body
```

To push the local project body using a vault account passphrase:

```rust
use tn_proto::{Tn, VaultHttpProjectClient, VaultPushWithPassphraseOptions};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init(".tn/payments/tn.yaml")?;
    let mut client = VaultHttpProjectClient::new("https://vault.example")?;
    client.set_bearer_token("vault-session-token");

    let result = tn.vault().push_body_with_passphrase_http_client(
        &client,
        "account passphrase",
        VaultPushWithPassphraseOptions::new(),
    )?;

    println!("pushed project {}", result.push.project_id);
    Ok(())
}
```

For an explicit credential id:

```rust
let mut options = tn_proto::VaultPushWithPassphraseOptions::new();
options.credential_id = Some("credential-id".to_string());
tn.vault()
    .push_body_with_passphrase_http_client(&client, passphrase, options)?;
```

### Push With Cached AWK

For repeat use, cache the derived account AWK once and let later pushes avoid
the account passphrase. The cache stores only the derived AWK, never the
passphrase.

```rust
use tn_proto::{
    default_credential_store, Tn, VaultHttpProjectClient,
    VaultPushWithCachedAwkOptions,
};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init(".tn/payments/tn.yaml")?;
    let mut client = VaultHttpProjectClient::new("https://vault.example")?;
    client.set_bearer_token("vault-session-token");

    let store = default_credential_store();
    let mut options = VaultPushWithCachedAwkOptions::new("vault-account-id");
    options.passphrase = Some("account passphrase".to_string());

    let result = tn
        .vault()
        .push_body_with_cached_awk_http_client(&client, &store, options)?;

    println!("pushed project {}", result.push.project_id);
    Ok(())
}
```

When `awk:vault-account-id` is already cached, the helper skips credential
fetch and passphrase derivation. When the cache is empty and `passphrase` is
provided, it derives the AWK, writes it to the credential store, and continues.

### Restore With Passphrase

Restore always writes into an explicit target directory. Different existing
files are not overwritten unless `VaultInstallBodyOptions::overwrite` is set.

```rust
use tn_proto::{
    Tn, VaultHttpProjectClient, VaultInstallBodyOptions,
    VaultRestoreWithPassphraseOptions,
};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::init(".tn/payments/tn.yaml")?;
    let mut client = VaultHttpProjectClient::new("https://vault.example")?;
    client.set_bearer_token("vault-session-token");

    let result = tn.vault().restore_and_install_body_with_passphrase_http_client(
        &client,
        "account passphrase",
        VaultRestoreWithPassphraseOptions::new(),
        VaultInstallBodyOptions::new("./restored-payments"),
    )?;

    println!("restored {}", result.install.yaml_path.display());
    Ok(())
}
```

For callers that already have an account AWK, use
`push_body_with_awk_http_client`, `restore_body_with_awk_http_client`, or
`restore_and_install_body_with_awk_http_client`.

For cached-AWK restore, use `restore_body_with_cached_awk_http_client` or
`restore_and_install_body_with_cached_awk_http_client`. These are body restore
helpers. For the higher-level account inbox pull/absorb and group-key publish
flow, use the `wallet()` namespace.

### Lower-Level Client APIs

`VaultHttpProjectClient` also exposes the underlying vault routes:

- Project lifecycle: `create_project`, `list_projects`, `get_project`,
  `delete_project`, `restore_manifest`
- Opaque sealed file routes: `list_files`, `upload_sealed`,
  `download_sealed`, `delete_file`
- AWK/BEK routes: `get_credential_wrap`, `derive_awk_from_passphrase`,
  `get_wrapped_key`, `put_wrapped_key`, `get_encrypted_blob`,
  `put_encrypted_blob_account`

## Feature Flags

- `fs` is enabled by default and activates filesystem-backed `tn-core`
- `http` enables the blocking vault HTTP client
- `watch` enables synchronous native file notification support through `notify`
- `async` is reserved for future async watch support

The `async` flag is reserved and does not add dependencies or public async APIs
yet.

## Examples

Run examples from the repository root:

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

Most examples use `Tn::ephemeral()` and do not require local setup. The vault
claim example targets `https://vault.tn-proto.org` by default and accepts
`TN_VAULT_URL` / `TN_PROJECT_NAME`. The vault passphrase example requires
`TN_VAULT_URL` and `TN_VAULT_PASSPHRASE`; it also accepts `TN_PROJECT_NAME`,
`TN_RESTORE_DIR`, `TN_VAULT_CREDENTIAL_ID`, `TN_VAULT_SESSION_TOKEN`, and
`TN_VAULT_JWT`.

## CLI Preview

The optional `cli` feature builds a small `tn-proto` binary. It currently
covers project init, vault claim-link onboarding, local invite inbox commands,
account connect-code redemption, local vault link-state, and wallet
sync/restore:

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
cargo run -p tn-proto --features cli --bin tn-proto -- auth logout --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- vault connect --yaml .tn/payments/tn.yaml --project-id proj_...
cargo run -p tn-proto --features cli --bin tn-proto -- vault unlink --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet status --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet sync --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet restore --yaml .tn/payments/tn.yaml --target-dir ./restored-payments
cargo run -p tn-proto --features cli --bin tn-proto -- wallet unlink --yaml .tn/payments/tn.yaml
```

Use `--project-dir <dir>` to choose the workspace directory. `claim-link`
targets `https://vault.tn-proto.org` by default; pass `--vault <url>` or set
`TN_VAULT_URL` to override it.

`read` prints decrypted entries as newline-delimited JSON by default. It
requires `--yaml <path-to-tn.yaml>`; pass `--all-runs` to include prior process
runs, `--verify` to include `_valid` verification flags, and `--pretty` for
formatted JSON output.

`verify` reads all runs with verification enabled, prints a compact validity
summary, and exits with a non-zero status if any entry fails signature, row hash,
or chain verification.

`show` prints local ceremony diagnostics without making network calls: yaml/log
paths, device DID, entry count, configured groups, account binding state, vault
link-state, and wallet paths.

`watch` prints entries as they become visible. It uses the polling watcher by
default, accepts `--from-beginning`, `--event-type`, `--event-type-prefix`,
`--limit`, `--timeout-ms`, `--verify`, and `--pretty`, and can use native file
notifications with `--native` when the CLI is built with `--features cli,watch`.

`inbox inspect` validates a `tn-invite-*.zip` without installing it and prints
manifest metadata plus kit-hash verification status. `inbox accept` requires an
explicit `--yaml` path so invites are installed into the intended ceremony.
`inbox mint` creates a `tn-invite-*.zip` for a recipient DID or friendly label;
it supports `--group`, `--from-email`, `--project-name`, `--note`, and
`--invitation-id`.

`pkg inspect` prints package kind, signature status, publisher/recipient,
ceremony id, body entry count, and key/secret flags. `pkg absorb` installs a
`.tnpkg` into an existing ceremony and reports accepted/deduped/no-op/rejected
receipt details. `pkg compile-enrolment` writes a signed recipient handoff
`kit_bundle` for one group. `pkg offer` writes the same handoff package and
emits `tn.offer.compiled` to the local log for tracking. `pkg export
admin-snapshot` writes a governance snapshot with no secret key material. `pkg
export bundle-for-recipient` mints recipient-specific reader kits and writes
them as a `kit_bundle`; use comma-separated or repeated `--group` flags to
limit the bundle, and `--seal-for-recipient` to encrypt it for the recipient DID.
`pkg export recipient-handoff` writes both `admin-snapshot.tnpkg` and
`reader-bundle.tnpkg` into an output directory for a recipient handoff; the
reader bundle can also be sealed with `--seal-for-recipient`.

`group list` prints the groups declared in an existing ceremony config. It
requires `--yaml <path-to-tn.yaml>`.

`group recipients` replays admin events and prints reader leaves for a group.
It requires `<group>` and `--yaml <path-to-tn.yaml>`; pass
`--include-revoked` to include revoked leaves.

`group add` creates or updates a BTN group in an existing ceremony and routes
comma-separated field names into that group. It requires `--yaml <path-to-tn.yaml>`
and supports `--fields <name,name>`; the CLI reloads the ceremony internally so
future events use the new routing immediately.

`group add-recipient` mints a raw `.btn.mykit` reader kit for an existing group.
It requires `<group>`, `<recipient-did>`, `--yaml <path-to-tn.yaml>`, and
`--out <file.btn.mykit>`, then advances the publisher reader state. For
shareable recipient onboarding, prefer `inbox mint`; for package-based
handoffs, prefer `pkg export bundle-for-recipient`.

`group revoke-recipient` revokes an existing reader leaf from a group. It
requires `<group>`, `<leaf-index>`, and `--yaml <path-to-tn.yaml>`, then
persists the updated publisher state.

`auth connect-code` requires `--yaml`; it accepts `--vault <url>` /
`TN_VAULT_URL` and optional `--identity-path <identity.json>` when a specific
signing identity should be used. `auth status` and its `auth whoami` alias
print the local account binding state for an existing ceremony. `auth logout`
clears local account binding, removes pending-claim state, and deletes the
cached account key when present.

`vault connect` links an existing local ceremony to a known vault project id.
It defaults to `https://vault.tn-proto.org`, accepts `--vault <url>` /
`TN_VAULT_URL`, `--project-id`, optional `--project-name`, and
`--no-audit-event`, and updates local YAML link-state without creating a remote
project.

`vault unlink` clears local vault link-state for an existing ceremony. It can
infer the vault URL and project id from `tn.yaml`, or accept explicit
`--vault <url>` and `--project-id <id>` overrides. It also accepts
`--reason <text>` and `--no-audit-event`.

`wallet status` prints local wallet diagnostics for an existing ceremony:
active yaml, wallet sidecar root, inbox directory, sync-state path,
account-bound state, cached-key state, and linked vault/project state.

`wallet sync` composes the account/vault sync path: pull account inbox
packages, absorb staged packages, publish group-key snapshots, and push the
encrypted project body. It defaults to `https://vault.tn-proto.org` and accepts
`--vault <url>` / `TN_VAULT_URL`, `--pull-only`, `--push-only`,
`--drain-queue`, `--account-id`, `--project-id`, repeated or comma-separated
`--group`, and passphrase fallback via `--passphrase` / `TN_VAULT_PASSPHRASE`
plus `--credential-id` / `TN_VAULT_CREDENTIAL_ID`.

`wallet restore` downloads an encrypted project body, decrypts it with a cached
or passphrase-derived account key, and installs `tn.yaml` plus `keys/` into an
explicit target directory. It defaults to `https://vault.tn-proto.org` and
accepts `--vault <url>` / `TN_VAULT_URL`, `--account-id`, `--project-id`,
`--passphrase` / `TN_VAULT_PASSPHRASE`, `--credential-id` /
`TN_VAULT_CREDENTIAL_ID`, and `--overwrite`. Without `--overwrite`, restore
refuses to replace different existing files.

`wallet unlink` is a wallet-oriented alias for `vault unlink`. It clears the
same local YAML link-state and supports the same flags.

### CLI Workflows

Create a new local project and generate a browser claim link:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- claim-link payments
```

Open the printed claim URL in the vault UI, then check the local project:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- auth status --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- wallet status --yaml .tn/payments/tn.yaml
```

Bind an existing local project to an account with a connect code:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- auth connect-code tn_connect_... --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- auth whoami --yaml .tn/payments/tn.yaml
```

Link a project to a known vault project id without creating anything remotely:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- vault connect --yaml .tn/payments/tn.yaml --project-id proj_...
```

Create a complete package handoff for a recipient:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- group add payments --yaml .tn/payments/tn.yaml --fields order_id,amount
cargo run -p tn-proto --features cli --bin tn-proto -- pkg offer --yaml .tn/payments/tn.yaml --peer did:key:zRecipient --group payments --out ./offer.tnpkg --seal-for-recipient
cargo run -p tn-proto --features cli --bin tn-proto -- pkg export recipient-handoff --yaml .tn/payments/tn.yaml --recipient did:key:zRecipient --out-dir ./handoff --group payments --seal-for-recipient
```

Send both files in `./handoff` to the recipient. On the recipient machine,
absorb the admin snapshot first, then the reader bundle:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- pkg inspect ./handoff/admin-snapshot.tnpkg --entries
cargo run -p tn-proto --features cli --bin tn-proto -- pkg absorb ./handoff/admin-snapshot.tnpkg --yaml .tn/recipient/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- pkg inspect ./handoff/reader-bundle.tnpkg --entries
cargo run -p tn-proto --features cli --bin tn-proto -- pkg absorb ./handoff/reader-bundle.tnpkg --yaml .tn/recipient/tn.yaml
```

Create a routed private group before emitting events with sensitive fields:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- group list --yaml .tn/payments/tn.yaml
cargo run -p tn-proto --features cli --bin tn-proto -- group recipients payments --yaml .tn/payments/tn.yaml --include-revoked
cargo run -p tn-proto --features cli --bin tn-proto -- group add payments --yaml .tn/payments/tn.yaml --fields order_id,amount
cargo run -p tn-proto --features cli --bin tn-proto -- group add-recipient payments did:key:zRecipient --yaml .tn/payments/tn.yaml --out ./recipient.btn.mykit
cargo run -p tn-proto --features cli --bin tn-proto -- group revoke-recipient payments 1 --yaml .tn/payments/tn.yaml
```

Inspect and absorb a package:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- pkg inspect ./reader-bundle.tnpkg --entries
cargo run -p tn-proto --features cli --bin tn-proto -- pkg absorb ./reader-bundle.tnpkg --yaml .tn/recipient/tn.yaml
```

Sync an account-bound project:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- wallet sync --yaml .tn/payments/tn.yaml --passphrase "$TN_VAULT_PASSPHRASE"
```

Restore an encrypted vault backup into a fresh directory:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- wallet restore --yaml .tn/payments/tn.yaml --target-dir ./restored-payments --account-id acct_... --project-id proj_... --passphrase "$TN_VAULT_PASSPHRASE"
```

Detach local vault link-state when a project should return to local-only mode:

```bash
cargo run -p tn-proto --features cli --bin tn-proto -- wallet unlink --yaml .tn/payments/tn.yaml --reason local_only
```

For a local dev vault or private deployment, pass `--vault <url>` on vault
commands or set `TN_VAULT_URL`.

## Development

Common checks:

```bash
cargo fmt -p tn-proto --check
cargo test -p tn-proto
cargo test -p tn-proto --features http
cargo doc -p tn-proto --no-deps
```

Python and TypeScript interop tests are present but ignored by default until
their local SDK/native-extension setup is available:

```bash
cargo test -p tn-proto --test interop_python -- --ignored
cargo test -p tn-proto --test interop_typescript -- --ignored
```

## Current Limits

- The crate is in-repo only and not published to crates.io yet
- Polling watch is read-backed; native file notifications require the `watch`
  feature
- Async watch is not implemented yet
- Vault HTTP support is currently blocking, not async
- Browser login/account UI remains outside the library; use the CLI claim-link
  and connect-code commands to bridge local projects to the hosted vault

## License

Licensed under either MIT or Apache-2.0, at your option.
