# tn-proto C# SDK

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![Core](https://img.shields.io/badge/core-shared%20Rust%20runtime-orange.svg?style=flat-square)](../crypto/tn-core)
[![Status](https://img.shields.io/badge/status-preview-yellow.svg?style=flat-square)](#status)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-green.svg?style=flat-square)](#license)

**`TnProto` for .NET writes encrypted, signed, tamper-evident records using the same tn-proto wire format as Python, TypeScript, and Rust.** It is a C# wrapper over the shared Rust core, so cryptography, canonicalization, `.tnpkg` handling, recipient sealing, and vault body encryption stay byte-compatible across languages.

## Status

The C# SDK is currently an in-repo preview. It is not published to NuGet yet.

Ready today:

- Project creation/opening under `.tn/<project>/tn.yaml`
- Emit/read/verify, canonical JSON, envelope sealing, and identity helpers
- Admin groups, reader kits, recipient revocation, and rotation
- `.tnpkg` export/absorb, recipient handoff, offers, enrolments, and invites
- Vault claim-link, account connect-code, wallet sync, and restore helpers
- API-key bootstrap for container/CI cold starts
- Firehose diagnostic client and gated CLI commands
- Preview `tn-dotnet` CLI

Preview limits:

- Native binaries are built from this repo during development.
- NuGet runtime asset packaging is not finalized.
- Watch is polling-backed.
- Browser login/account UI is outside the SDK.
- Firehose commands are diagnostic and opt-in behind `TN_FIREHOSE_ENABLED=1`.

## Installation

Use from source for now:

```powershell
git clone https://github.com/cyaxios/tn-proto.git
cd tn-proto
cargo build -p tn-core-ffi
dotnet restore csharp-sdk/TnProto.sln
dotnet build csharp-sdk/TnProto.sln
```

The .NET loader searches the repo-level Cargo `target/debug` and `target/release` directories for the native `tn_core_ffi` library.

## Quickstart

The first run creates a project under `./.tn/`.

```csharp
using TnProto;

await using var tn = await Tn.InitProjectAsync(
    "payments",
    new TnProjectOptions { ProjectDirectory = "." });

await tn.InfoAsync("order.created", new { order_id = "A100", amount = 4999 });
await tn.WarningAsync("order.flagged", new { order_id = "A100", reason = "hold" });

var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true, Verify = true });
foreach (var entry in entries)
{
    Console.WriteLine($"{entry.Level} {entry.EventType} {entry.GetString("order_id")}");
}
```

```text
info order.created A100
warning order.flagged A100
```

`ReadAsync` returns decrypted fields. The entry written to disk is sealed: private fields are encrypted to the configured reader group, signed by the device, and hash-chained for offline verification.

Open an existing project:

```csharp
await using var tn = await Tn.InitAsync(".tn/payments/tn.yaml");
```

## What You Get

**Control who can read what**

- Field values are encrypted on disk.
- Groups route fields to separate reader sets.
- Recipient kits grant access without sharing private keys.
- Revocation and rotation move future entries beyond revoked readers.

**Prove what happened**

- Entries carry Ed25519 device signatures.
- Hash chaining catches edits, deletion, and reordering.
- Verification works offline from the log and public identity.

## Everyday API

| API | What it does |
| --- | --- |
| `Tn.InitProjectAsync(name, options)` | Create/open `.tn/<name>/tn.yaml` |
| `Tn.InitAsync(yamlPath)` | Open an existing ceremony |
| `tn.InfoAsync`, `WarningAsync`, `ErrorAsync`, `DebugAsync` | Emit signed encrypted entries |
| `tn.EmitAsync(level, eventType, fields)` | Emit with a selected level |
| `tn.ReadAsync(options)` | Read decrypted entries |
| `tn.WatchAsync(options)` | Poll for newly visible entries |
| `tn.Admin.*` | Create groups, mint/revoke readers, rotate keys |
| `tn.Packages.*` | Export, inspect, seal, and absorb `.tnpkg` bundles |
| `tn.Inbox.*` | Mint, inspect, list, and accept invitation zips |
| `tn.Vault.*` | Claim-link, connect, link/unlink, push/restore encrypted body backups |
| `tn.Wallet.*` | Account-aware inbox staging, sync, prefs, and restore |
| `tn.Account.*` | Connect-code binding, status, whoami, logout |
| `TnCanonical`, `TnCrypto`, `TnIdentity` | Canonical bytes, envelope verification, identity/signature helpers |

## Groups And Reader Kits

```csharp
await tn.Admin.EnsureGroupAsync("payments", ["order_id", "amount", "card_last4"]);

var kit = await tn.Admin.AddRecipientAsync(
    "payments",
    "alice.btn.mykit",
    "did:key:zAlice");

await tn.Admin.RevokeRecipientAsync("payments", kit.LeafIndex);
```

Fields routed to `payments` are encrypted to that group. Readers absorb a kit bundle and can decrypt that group, and nothing else.

## Bundles And Invites

A `.tnpkg` is the signed zip container used for snapshots, reader kits, enrolments, and offers.

```csharp
var handoff = await tn.Packages.BundleForRecipientAsync(
    "did:key:zAlice",
    "alice-handoff.tnpkg",
    new BundleForRecipientOptions
    {
        Groups = ["payments"],
        SealForRecipient = true,
    });

var info = await tn.Packages.InspectAsync(handoff.Path);
Console.WriteLine($"{info.Kind} verified={info.Verified} sealed={info.Sealed}");

var receipt = await tn.Packages.AbsorbAsync(handoff.Path);
```

Invite zips wrap the same handoff shape in a user-facing package:

```csharp
var invite = await tn.Inbox.MintInviteAsync(
    "did:key:zAlice",
    "tn-invite-alice.zip",
    new MintInvitationOptions
    {
        Group = "payments",
        FromEmail = "sender@example.test",
        ProjectName = "payments",
    });

var accepted = await tn.Inbox.AcceptAsync("tn-invite-alice.zip");
```

## Non-Custodial Vault

The vault stores ciphertext it cannot decrypt. Your local project keys and config can be backed up, restored, and synced without giving the vault plaintext access.

Create a claim link:

```csharp
var claim = await tn.Vault.InitUploadAsync(new VaultInitUploadOptions
{
    VaultBaseUrl = "https://vault.tn-proto.org",
});

Console.WriteLine(claim.ClaimUrl);
```

Bind a local project to an account with a connect code:

```csharp
var connected = await tn.Account.ConnectCodeAsync(
    "CONNECT-CODE-FROM-VAULT",
    new AccountConnectOptions { VaultBaseUrl = "https://vault.tn-proto.org" });
```

Sync and restore:

```csharp
await tn.Wallet.SyncAsync(new WalletSyncOptions
{
    VaultBaseUrl = "https://vault.tn-proto.org",
    BearerToken = "vault-account-bearer-jwt",
    PushBody = true,
    Passphrase = "account recovery passphrase",
});

var restored = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
{
    VaultBaseUrl = "https://vault.tn-proto.org",
    BearerToken = "vault-account-bearer-jwt",
    ProjectId = "proj_...",
    TargetDirectory = "restored-project",
    Passphrase = "account recovery passphrase",
});
```

`tn_apikey_...` values are cold-start bootstrap keys for container/CI startup. They are not wallet bearer tokens.

```csharp
var bootstrap = await TnApiKeyBootstrap.BootstrapAsync(new TnApiKeyBootstrapOptions
{
    VaultBaseUrl = "https://vault.tn-proto.org",
    ApiKey = "tn_apikey_...",
    ProjectDirectory = ".",
    Project = "payments",
});
```

## CLI

Run the preview CLI from the repo root:

```powershell
dotnet run --project csharp-sdk/src/TnProto.Cli -- --help
```

| Command | What it does |
| --- | --- |
| `init` | Create/open a local project |
| `info`, `log` | Emit an entry |
| `read`, `watch` | Read or follow entries |
| `canonical`, `seal`, `verify` | Canonicalize, seal, and verify envelope JSON |
| `group`, `admin`, `rotate` | Manage groups, readers, and key rotations |
| `bundle`, `compile`, `absorb`, `invite`, `inbox` | Produce and install handoff packages |
| `vault`, `account`, `wallet`, `bootstrap` | Vault/account/bootstrap workflows |
| `streams`, `validate`, `show` | Inspect local project state |
| `firehose` | Diagnostic worker routes, gated by env |

Common flow:

```powershell
dotnet run --project csharp-sdk/src/TnProto.Cli -- init payments --dir . --json
dotnet run --project csharp-sdk/src/TnProto.Cli -- info payment.created --yaml .tn/payments/tn.yaml --fields '{"order_id":"A100","amount":4999}'
dotnet run --project csharp-sdk/src/TnProto.Cli -- read --yaml .tn/payments/tn.yaml --verify
```

Vault flow:

```powershell
dotnet run --project csharp-sdk/src/TnProto.Cli -- vault claim-link --yaml .tn/payments/tn.yaml --vault https://vault.tn-proto.org
dotnet run --project csharp-sdk/src/TnProto.Cli -- account connect CONNECT-CODE --yaml .tn/payments/tn.yaml --vault https://vault.tn-proto.org
dotnet run --project csharp-sdk/src/TnProto.Cli -- wallet status --yaml .tn/payments/tn.yaml
```

API-key bootstrap:

```powershell
$env:TN_API_KEY = "tn_apikey_..."
dotnet run --project csharp-sdk/src/TnProto.Cli -- bootstrap api-key --vault https://vault.tn-proto.org --dir . --project payments --json
```

Firehose diagnostics:

```powershell
$env:TN_FIREHOSE_ENABLED = "1"
$env:TN_FIREHOSE_URL = "https://firehose-worker.example"
$env:TN_FIREHOSE_TOKEN = "firehose-bearer-token"

dotnet run --project csharp-sdk/src/TnProto.Cli -- firehose stats acct_123
dotnet run --project csharp-sdk/src/TnProto.Cli -- firehose list acct_123 --did did:key:zReader
dotnet run --project csharp-sdk/src/TnProto.Cli -- firehose get acct_123 ceremony-1 snapshot.tnpkg --out snapshot.tnpkg
```

## Profiles

Profile selection is available through `TnProjectOptions.Profile`.

```csharp
await using var tn = await Tn.InitProjectAsync(
    "payments",
    new TnProjectOptions { Profile = TnProfile.Transaction });
```

| Profile | Encrypt | Sign | Chain | Use it for |
| --- | :---: | :---: | :---: | --- |
| `Transaction` | yes | yes | yes | grants, payments, security events |
| `Audit` | yes | yes | yes | business events with buffered throughput |
| `SecureLog` | yes | yes | no | signed logs where authorship matters |
| `Telemetry` | yes | no | no | high-volume traces and metrics |
| `Stdout` | yes | no | no | development and scratchpad flows |

## One Core, Every Language

The C# interop tests exercise emit/read, package absorb/export, invite accept, and recipient-sealed bundle flows against Python, TypeScript, and Rust.

Runtime-gated interop tests do not shell out during normal test runs. To run a slice:

```powershell
$env:TN_CSHARP_INTEROP_PYTHON = "1"
dotnet vstest csharp-sdk/tests/TnProto.Tests/bin/Debug/net8.0/TnProto.Tests.dll --Tests:PythonEmitsCSharpReads,CSharpEmitsPythonReads,CSharpAdminSnapshotPythonAbsorbs,PythonAdminSnapshotCSharpAbsorbs,CSharpInvitePythonAccepts,PythonInviteCSharpAccepts,CSharpSealedBundlePythonAbsorbs,PythonSealedBundleCSharpAbsorbs

$env:TN_CSHARP_INTEROP_RUST = "1"
dotnet vstest csharp-sdk/tests/TnProto.Tests/bin/Debug/net8.0/TnProto.Tests.dll --Tests:RustEmitsCSharpReads,CSharpEmitsRustReads,RustAdminSnapshotCSharpAbsorbs,CSharpAdminSnapshotRustAbsorbs,RustInviteCSharpAccepts,CSharpInviteRustAccepts,CSharpSealedBundleRustAbsorbs,RustSealedBundleCSharpAbsorbs
```

Set `TN_CSHARP_INTEROP_TYPESCRIPT=1` for the TypeScript slice after running `npm run build` in `ts-sdk`.

## Testing

```powershell
cargo build -p tn-core-ffi
dotnet test csharp-sdk/TnProto.sln
```

The normal suite uses temporary projects and local fake vault/firehose servers. Hosted vault behavior should still be checked manually before release because account UI, connect codes, and hosted bootstrap minting depend on the deployed vault environment.

## Project Layout

- `src/TnProto`: public C# library
- `src/TnProto.Cli`: preview CLI wrapper
- `tests/TnProto.Tests`: library tests
- `tests/TnProto.Cli.Tests`: CLI tests
- `SDK_REFERENCE.md`: temporary API reference while the SDK is in preview

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
