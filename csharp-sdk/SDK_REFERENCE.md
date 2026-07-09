# tn-proto C# SDK Reference

Temporary reference for the in-repo C# SDK preview.

The C# SDK is in early preview. The first chunks establish the .NET workspace
and a low-level native bridge over the shared Rust core:

```csharp
using TnProto;

Console.WriteLine(TnSdk.PackageName);
```

Project lifecycle:

```csharp
await using var tn = await Tn.InitProjectAsync(
    "payments",
    new TnProjectOptions
    {
        ProjectDirectory = ".",
        Profile = TnProfile.Transaction,
    });

await using var reopened = await Tn.InitAsync(tn.YamlPath);
```

Currently exposed:

- `Tn.InitAsync(yamlPath)`
- `Tn.InitProjectAsync(project, options)`
- `Tn.LogAsync(eventType, fields)`
- `Tn.InfoAsync(eventType, fields)`
- `Tn.DebugAsync(eventType, fields)`
- `Tn.WarningAsync(eventType, fields)`
- `Tn.ErrorAsync(eventType, fields)`
- `Tn.EmitAsync(level, eventType, fields)`
- `Tn.ReadAsync(options)`
- `Tn.WatchAsync(options)`
- `Tn.Admin.EnsureGroupAsync(group, fields)`
- `Tn.Admin.AddRecipientAsync(group, outKitPath, recipientDid)`
- `Tn.Admin.RevokeRecipientAsync(group, leafIndex)`
- `Tn.Admin.RecipientsAsync(group, includeRevoked)`
- `Tn.Admin.RevokedCountAsync(group)`
- `Tn.Agents.PublishAsync(markdown)`
- `Tn.Agents.Current`
- `Tn.Packages.ExportAdminSnapshotAsync(outPath)`
- `Tn.Packages.ExportKitBundleAsync(outPath, groups, toDid)`
- `Tn.Packages.BundleForRecipientAsync(recipientDid, outPath, options)`
- `Tn.Packages.ExportRecipientHandoffAsync(options)`
- `Tn.Packages.CompileEnrolmentAsync(options)`
- `Tn.Packages.OfferAsync(options)`
- `Tn.Packages.InspectAsync(sourcePath)`
- `Tn.Packages.AbsorbAsync(sourcePath)`
- `Tn.Inbox.ListLocalAsync(directory)`
- `Tn.Inbox.InspectAsync(path)`
- `Tn.Inbox.AcceptAsync(path)`
- `Tn.Inbox.MintInviteAsync(recipient, outPath, options)`
- `Tn.Vault.LinkStateAsync()`
- `Tn.Vault.SetLinkStateAsync(options)`
- `Tn.Vault.LinkAsync(vaultBaseUrl, projectId)`
- `Tn.Vault.UnlinkAsync()`
- `Tn.Vault.ConnectAsync(options)`
- `Tn.Vault.InitUploadAsync(options)`
- `Tn.Vault.PushBodyWithPassphraseAsync(options)`
- `Tn.Vault.RestoreBodyWithPassphraseAsync(options)`
- `Tn.Wallet.StatusAsync()`
- `Tn.Wallet.StageInboxAsync(options)`
- `Tn.Wallet.PullAndAbsorbAsync(options)`
- `Tn.Wallet.PullPrefsAsync(options)`
- `Tn.Wallet.PublishGroupKeysAsync(options)`
- `Tn.Wallet.SyncAsync(options)`
- `Tn.Wallet.RestoreAsync(options)`
- `Tn.Account.StateAsync()`
- `Tn.Account.StatusAsync()`
- `Tn.Account.WhoamiAsync()`
- `Tn.Account.ConnectCodeAsync(code, options)`
- `Tn.Account.LogoutAsync()`
- `Tn.ProjectYamlPath(projectDirectory, project)`
- `TnCanonical.Json(value)`
- `TnCanonical.JsonFromRaw(valueJson)`
- `TnCanonical.Bytes(value)`
- `TnCanonical.BytesFromRaw(valueJson)`
- `TnCanonical.BytesHex(value)`
- `TnCanonical.BytesHexFromRaw(valueJson)`
- `TnCrypto.SealEnvelope(input)`
- `TnCrypto.SealEnvelopeRaw(inputJson)`
- `TnCrypto.VerifyEnvelope(envelope)`
- `TnCrypto.VerifyEnvelopeRaw(envelopeJson)`
- `TnIdentity.LoadOrCreateAsync(seedPath)`
- `TnIdentity.LoadAsync(seedPath)`
- `TnIdentity.Generate()`
- `TnIdentity.FromSeed(seed)`
- `TnIdentity.FromSeedBase64(seedBase64)`
- `TnIdentity.Sign(seed, message)`
- `TnIdentity.SignBase64(seedBase64, message)`
- `TnIdentity.VerifyDid(did, message, signatureBase64)`
- `TnIdentity.FromMnemonic(words, passphrase)`
- `TnIdentity.ExportMnemonicAsync(identityPath)`
- `TnApiKey.Parse(apiKey)`
- `TnApiKey.TryParse(apiKey, out parsed)`
- `TnApiKeyBootstrap.FetchSealedBundleAsync(options)`
- `TnApiKeyBootstrap.BootstrapAsync(options)`
- `FirehoseClient.StatsAsync(tenant)`
- `FirehoseClient.ListAsync(tenant, did)`
- `FirehoseClient.GetAsync(tenant, ceremony, name, did)`
- `EnvelopeVerifyResult.Valid`
- `EnvelopeVerifyResult.Signature`
- `EnvelopeVerifyResult.Reason`
- `IdentityLoadResult.Identity`
- `IdentityLoadResult.Path`
- `IdentityLoadResult.Created`
- `DeviceIdentity.SeedBase64`
- `DeviceIdentity.PublicKeyBase64`
- `DeviceIdentity.Did`
- `DeviceIdentity.Seed`
- `DeviceIdentity.PublicKey`
- `Tn.YamlPath`
- `Tn.LogPath`
- `Tn.Did`
- `Tn.ProjectName`
- `Tn.ProjectDirectory`
- `TnProjectOptions.ProjectDirectory`
- `TnProjectOptions.Profile`
- `TnProfile.ToTnName()`
- `TnLogLevel`
- `TnLogLevel.ToTnName()`
- `ReadOptions.AllRuns`
- `ReadOptions.Verify`
- `Entry.Fields`
- `Entry.EventType`
- `Entry.Level`
- `Entry.Sequence`
- `Entry.Validity`
- `EntryValidity.Signature`
- `EntryValidity.RowHash`
- `EntryValidity.Chain`
- `EntryValidity.IsValid`
- `Entry.Get(key)`
- `Entry.GetString(key)`
- `WatchOptions.FromBeginning`
- `WatchOptions.EventType`
- `WatchOptions.EventTypePrefix`
- `WatchOptions.PollInterval`
- `PollingWatch.PollAsync()`
- `PollingWatch.WaitForEntriesAsync(timeout)`
- `AdminEnsureGroupResult.Group`
- `AdminEnsureGroupResult.Fields`
- `AdminEnsureGroupResult.Created`
- `AdminEnsureGroupResult.Changed`
- `AdminAddRecipientResult.Group`
- `AdminAddRecipientResult.RecipientDid`
- `AdminAddRecipientResult.LeafIndex`
- `AdminAddRecipientResult.KitPath`
- `AdminRevokeRecipientResult.Group`
- `AdminRevokeRecipientResult.LeafIndex`
- `AdminRecipient.LeafIndex`
- `AdminRecipient.RecipientIdentity`
- `AdminRecipient.MintedAt`
- `AdminRecipient.KitSha256`
- `AdminRecipient.Revoked`
- `AdminRecipient.RevokedAt`
- `PackageExportResult.Path`
- `PackageAbsorbReceipt.Kind`
- `PackageAbsorbReceipt.Status`
- `PackageAbsorbReceipt.AcceptedCount`
- `PackageAbsorbReceipt.DedupedCount`
- `PackageAbsorbReceipt.NoOp`
- `PackageAbsorbReceipt.ConflictCount`
- `PackageAbsorbReceipt.LegacyStatus`
- `PackageAbsorbReceipt.LegacyReason`
- `PackageAbsorbReceipt.ReplacedKitPaths`
- `BundleForRecipientOptions.Groups`
- `BundleForRecipientOptions.SealForRecipient`
- `BundleForRecipientResult.Path`
- `BundleForRecipientResult.RecipientDid`
- `BundleForRecipientResult.Groups`
- `RecipientHandoffOptions.RecipientDid`
- `RecipientHandoffOptions.OutDirectory`
- `RecipientHandoffOptions.Groups`
- `RecipientHandoffOptions.SealForRecipient`
- `RecipientHandoffResult.AdminSnapshotPath`
- `RecipientHandoffResult.ReaderBundlePath`
- `RecipientHandoffResult.RecipientDid`
- `RecipientHandoffResult.Groups`
- `RecipientHandoffResult.AdminSnapshot`
- `RecipientHandoffResult.ReaderBundle`
- `CompileEnrolmentOptions.Group`
- `CompileEnrolmentOptions.RecipientDid`
- `CompileEnrolmentOptions.OutPath`
- `CompileEnrolmentOptions.SealForRecipient`
- `CompiledPackageResult.Path`
- `CompiledPackageResult.RecipientDid`
- `CompiledPackageResult.Groups`
- `CompiledPackageResult.ManifestSha256`
- `CompiledPackageResult.PackageSha256`
- `OfferOptions.Group`
- `OfferOptions.PeerDid`
- `OfferOptions.OutPath`
- `OfferOptions.SealForRecipient`
- `OfferReceipt.Path`
- `OfferReceipt.Group`
- `OfferReceipt.PeerDid`
- `OfferReceipt.PackageSha256`
- `OfferReceipt.Status`
- `PackageInfo.Kind`
- `PackageInfo.Category`
- `PackageInfo.Scope`
- `PackageInfo.PublisherIdentity`
- `PackageInfo.RecipientIdentity`
- `PackageInfo.CeremonyId`
- `PackageInfo.EventCount`
- `PackageInfo.HeadRowHash`
- `PackageInfo.Signature`
- `PackageInfo.BodyEntryCount`
- `PackageInfo.BodyEntryNames`
- `PackageInfo.ContainsSecretMaterial`
- `PackageInfo.ContainsReaderKeys`
- `PackageInfo.HasPackageJson`
- `PackageInfo.Sealed`
- `PackageInfo.Verified`
- `PackageInfo.IsPublishedBy(did)`
- `PackageInfo.IsAddressedTo(did)`
- `PackageSignatureInfo.Status`
- `PackageSignatureInfo.Verified`
- `PackageSignatureInfo.Reason`
- `InvitationInfo.Manifest`
- `InvitationInfo.GroupName`
- `InvitationInfo.KitEntryName`
- `InvitationInfo.KitLength`
- `InvitationInfo.KitSha256Actual`
- `InvitationInfo.KitHash`
- `InvitationInfo.KitHashVerified`
- `InvitationManifest.InvitationId`
- `InvitationManifest.FromAccountDid`
- `InvitationManifest.FromEmail`
- `InvitationManifest.ProjectId`
- `InvitationManifest.ProjectName`
- `InvitationManifest.GroupName`
- `InvitationManifest.LeafIndex`
- `InvitationManifest.KitSha256`
- `InvitationManifest.EventId`
- `InvitationManifest.CreatedAt`
- `InvitationManifest.Note`
- `InvitationManifest.Provenance`
- `InvitationManifest.Raw`
- `InvitationKitHash.Status`
- `InvitationKitHash.Verified`
- `InvitationKitHash.Expected`
- `InvitationAcceptResult.Info`
- `InvitationAcceptResult.KitPath`
- `InvitationAcceptResult.BackupPath`
- `InvitationAcceptResult.AbsorbedAt`
- `InvitationAcceptResult.GroupName`
- `InvitationAcceptResult.FromEmail`
- `InvitationAcceptResult.LeafIndex`
- `MintInvitationOptions.Group`
- `MintInvitationOptions.FromEmail`
- `MintInvitationOptions.ProjectId`
- `MintInvitationOptions.ProjectName`
- `MintInvitationOptions.Note`
- `MintInvitationOptions.InvitationId`
- `MintInvitationOptions.Provenance`
- `MintInvitationResult.Path`
- `MintInvitationResult.RecipientDid`
- `MintInvitationResult.Manifest`
- `MintInvitationResult.KitEntryName`
- `MintInvitationResult.ZipLength`
- `VaultLinkStateInfo.State`
- `VaultLinkStateInfo.VaultBaseUrl`
- `VaultLinkStateInfo.ProjectId`
- `VaultLinkStateResult.State`
- `VaultLinkStateResult.VaultBaseUrl`
- `VaultLinkStateResult.ProjectId`
- `VaultConnectOptions.VaultBaseUrl`
- `VaultConnectOptions.BearerToken`
- `VaultConnectOptions.ProjectName`
- `VaultConnectOptions.HttpClient`
- `VaultConnectResult.ProjectId`
- `VaultConnectResult.ProjectName`
- `VaultConnectResult.VaultBaseUrl`
- `VaultInitUploadOptions.VaultBaseUrl`
- `VaultInitUploadOptions.ProjectName`
- `VaultInitUploadOptions.HttpClient`
- `VaultInitUploadResult.VaultBaseUrl`
- `VaultInitUploadResult.ProjectId`
- `VaultInitUploadResult.ProjectName`
- `VaultInitUploadResult.ClaimUrl`
- `VaultPushBodyWithPassphraseOptions.VaultBaseUrl`
- `VaultPushBodyWithPassphraseOptions.BearerToken`
- `VaultPushBodyWithPassphraseOptions.ProjectId`
- `VaultPushBodyWithPassphraseOptions.Passphrase`
- `VaultPushBodyWithPassphraseOptions.CredentialId`
- `VaultPushBodyResult.ProjectId`
- `VaultPushBodyResult.BodyMemberCount`
- `VaultPushBodyResult.EncryptedLength`
- `VaultPushBodyResult.WrappedKeyCreated`
- `VaultPushBodyResult.IfMatch`
- `VaultPushBodyResult.WrappedKeyResponse`
- `VaultPushBodyResult.EncryptedBlobResponse`
- `VaultRestoreBodyWithPassphraseOptions.VaultBaseUrl`
- `VaultRestoreBodyWithPassphraseOptions.BearerToken`
- `VaultRestoreBodyWithPassphraseOptions.ProjectId`
- `VaultRestoreBodyWithPassphraseOptions.Passphrase`
- `VaultRestoreBodyWithPassphraseOptions.CredentialId`
- `VaultRestoreBodyResult.ProjectId`
- `VaultRestoreBodyResult.BodyMemberCount`
- `VaultRestoreBodyResult.TotalBodyBytes`
- `VaultRestoreBodyResult.BodyMemberNames`
- `VaultRestoreBodyResult.WrappedKey`
- `VaultRestoreBodyResult.EncryptedBlobResponse`
- `WalletRestoreOptions.VaultBaseUrl`
- `WalletRestoreOptions.BearerToken`
- `WalletRestoreOptions.ProjectId`
- `WalletRestoreOptions.Passphrase`
- `WalletRestoreOptions.UseCachedAccountKey`
- `WalletRestoreOptions.AccountId`
- `WalletRestoreOptions.CredentialId`
- `WalletRestoreOptions.TargetDirectory`
- `WalletRestoreOptions.Overwrite`
- `WalletRestoreResult.ProjectId`
- `WalletRestoreResult.BodyMemberCount`
- `WalletRestoreResult.TotalBodyBytes`
- `WalletRestoreResult.BodyMemberNames`
- `WalletRestoreResult.TargetDirectory`
- `WalletRestoreResult.YamlPath`
- `WalletRestoreResult.KeysDirectory`
- `WalletRestoreResult.WrittenPaths`
- `WalletRestoreResult.DedupedPaths`
- `WalletRestoreResult.SkippedMembers`
- `WalletRestoreResult.WrappedKey`
- `WalletRestoreResult.EncryptedBlobResponse`
- `WalletPullPrefsOptions.VaultBaseUrl`
- `WalletPullPrefsOptions.BearerToken`
- `WalletPullPrefsOptions.HttpClient`
- `WalletPullPrefsResult.VaultBaseUrl`
- `WalletPullPrefsResult.DefaultNewCeremonyMode`
- `WalletPullPrefsResult.PrefsVersion`
- `WalletPullPrefsResult.StatePath`
- `AccountCredentialStore.Default()`
- `AccountCredentialStore.AwkKeyName(accountId)`
- `AccountCredentialStore.SetAccountAwkAsync(accountId, awk)`
- `AccountCredentialStore.GetAccountAwkAsync(accountId)`
- `AccountCredentialStore.DeleteAccountAwkAsync(accountId)`
- `AccountCredentialStore.SetAsync(name, value)`
- `AccountCredentialStore.GetAsync(name)`
- `AccountCredentialStore.DeleteAsync(name)`
- `AccountStatus.AccountId`
- `AccountStatus.AccountBound`
- `AccountStatus.KeyCached`
- `AccountStatus.Verdict`
- `AccountStatus.VerdictName`
- `AccountConnectOptions.VaultBaseUrl`
- `AccountConnectOptions.HttpClient`
- `AccountConnectResult.AccountId`
- `AccountConnectResult.ProjectId`
- `AccountConnectResult.ProjectName`
- `AccountLogoutResult.WasBound`
- `AccountLogoutResult.AccountId`
- `TnApiKey.Seed`
- `TnApiKey.SeedBase64`
- `TnApiKey.KeyId`
- `TnApiKey.KeyIdBytes`
- `TnApiKey.Did`
- `TnApiKeyBootstrapOptions.ApiKey`
- `TnApiKeyBootstrapOptions.VaultBaseUrl`
- `TnApiKeyBootstrapOptions.Project`
- `TnApiKeyBootstrapOptions.ProjectDirectory`
- `TnApiKeyBootstrapOptions.Profile`
- `TnApiKeyBootstrapOptions.HttpClient`
- `TnApiKeyBootstrapResult.Succeeded`
- `TnApiKeyBootstrapResult.Project`
- `TnApiKeyBootstrapResult.Receipt`
- `TnApiKeySealedBundleResult.BundleBytes`
- `TnApiKeySealedBundleResult.Kind`
- `FirehoseClientOptions.BaseUrl`
- `FirehoseClientOptions.BearerToken`
- `FirehoseClientOptions.HttpClient`

Primary API namespaces:

- `TnProto`
- `TnProto.Admin`
- `TnProto.Packages`
- `TnProto.Inbox`
- `TnProto.Account`
- `TnProto.Vault`
- `TnProto.Wallet`
- `TnProto.Firehose`

## Native Bridge Foundation

The preview now includes a low-level native bridge namespace:

```csharp
using TnProto.Native;

var version = NativeBridge.Version();
```

Currently bridged:

- native bridge version
- last native error
- open existing `tn.yaml`
- create/open project
- close/free runtime handle
- read active runtime DID
- read active runtime YAML path
- read active runtime log path
- emit an event from JSON object fields
- read decrypted flat entries as JSON
- ensure an admin group and route fields
- mint a recipient reader kit
- revoke a recipient reader leaf
- list recipients for an admin group
- count revoked recipient leaves
- export admin-log snapshot packages
- export existing reader-kit bundle packages
- mint fresh recipient reader kits into bundle packages
- export recipient handoff pairs: `admin-snapshot.tnpkg` plus `reader-bundle.tnpkg`
- compile enrolment handoff packages
- compile offer handoff packages and attest the offer in the local runtime
- inspect package metadata without absorbing or mutating local state
- absorb packages from disk
- list local `tn-invite-*.zip` files
- inspect invitation zips and verify inner kit hashes without accepting them
- accept invitation zips into the active keystore
- mint invitation zips for recipient handoff
- push encrypted project-body snapshots to a vault using passphrase-derived
  account key wrapping
- restore and decrypt vault project-body snapshots for inspection without
  installing files
- restore and install vault project-body snapshots using passphrase recovery or
  cached account key material
- read and write account-scoped credential cache entries in the shared
  `credentials.json` format
- serialize values to TN canonical JSON and canonical bytes
- verify TN envelope signatures against their device identity and row hash
- generate Ed25519 device identities and restore deterministic identities from
  32-byte seeds
- load or create raw 32-byte identity seed files
- sign message bytes with an Ed25519 seed and verify TN wire signatures against
  `did:key` identities

Build the native bridge before running native-backed C# tests:

```powershell
cargo build -p tn-core-ffi
dotnet test csharp-sdk/TnProto.sln
```

Watch APIs are v0 polling/read-backed APIs. `EventType` and
`EventTypePrefix` are conjunctive when both are set, and `PollingWatch` resets
its cursor if the visible entry count shrinks between polls.
