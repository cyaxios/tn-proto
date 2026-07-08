using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;
using TnProto.Account;
using TnProto.Native;
using TnProto.Packages;
using TnProto.Vault;

namespace TnProto.Wallet;

/// <summary>
/// High-level wallet orchestration helpers.
/// </summary>
public sealed class WalletClient
{
    private readonly Tn _tn;

    internal WalletClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// Read local wallet status without contacting the vault.
    /// </summary>
    public async Task<WalletStatus> StatusAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var account = await _tn.Account.StatusAsync(cancellationToken).ConfigureAwait(false);
        var vault = await _tn.Vault.LinkStateAsync(cancellationToken).ConfigureAwait(false);
        var pendingClaim = await ReadPendingClaimAsync(cancellationToken).ConfigureAwait(false);
        var warnings = new List<string>();

        if (vault.State == VaultLinkState.Linked && string.IsNullOrWhiteSpace(vault.LinkedProjectId))
        {
            warnings.Add("ceremony is linked but has no linked_project_id");
        }

        if (pendingClaim is { Expired: true })
        {
            warnings.Add("pending claim is expired");
        }

        var verdict = DetermineVerdict(account.AccountBound, vault, pendingClaim, warnings);
        return new WalletStatus(
            _tn.Did,
            _tn.YamlPath,
            account,
            vault,
            pendingClaim,
            warnings,
            verdict);
    }

    /// <summary>
    /// Stage authenticated account inbox packages into the local wallet inbox.
    /// </summary>
    public async Task<WalletStageInboxResult> StageInboxAsync(
        WalletStageInboxOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var account = await _tn.Account.StateAsync(cancellationToken).ConfigureAwait(false);
        if (!account.AccountBound)
        {
            return new WalletStageInboxResult([], 0, NotBound: true, Unauthorized: false);
        }

        var stageOptions = options ?? new WalletStageInboxOptions();
        var vaultBaseUrl = stageOptions.VaultBaseUrl;
        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            var link = await _tn.Vault.LinkStateAsync(cancellationToken).ConfigureAwait(false);
            vaultBaseUrl = link.LinkedVault;
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            return new WalletStageInboxResult([], 0, NotBound: true, Unauthorized: false);
        }

        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = vaultBaseUrl,
            BearerToken = stageOptions.BearerToken,
            HttpClient = stageOptions.HttpClient,
        });

        IReadOnlyList<VaultAccountInboxItem> items;
        try
        {
            items = await client.ListAccountInboxAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (VaultException ex) when (ex.StatusCode is 401 or 403)
        {
            return new WalletStageInboxResult([], 0, NotBound: false, Unauthorized: true);
        }

        var stagedPaths = new List<string>();
        var skipped = 0;
        foreach (var item in items)
        {
            if (!string.IsNullOrWhiteSpace(item.ConsumedAt))
            {
                skipped++;
                continue;
            }

            var fromDid = SafePathSegment(item.PublisherIdentity);
            var ceremonyId = SafePathSegment(item.CeremonyId);
            var timestamp = SafePathSegment(item.Timestamp);
            if (fromDid is null || ceremonyId is null || timestamp is null)
            {
                skipped++;
                continue;
            }

            var dest = Path.Combine(InboxDirectory(), fromDid, ceremonyId, $"{timestamp}.tnpkg");
            if (File.Exists(dest))
            {
                skipped++;
                continue;
            }

            var bytes = await client.DownloadAccountInboxPackageAsync(
                item.PublisherIdentity,
                item.CeremonyId,
                item.Timestamp,
                cancellationToken).ConfigureAwait(false);
            if (bytes is null)
            {
                skipped++;
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            await File.WriteAllBytesAsync(dest, bytes, cancellationToken).ConfigureAwait(false);
            stagedPaths.Add(dest);
        }

        return new WalletStageInboxResult(stagedPaths, skipped, NotBound: false, Unauthorized: false);
    }

    /// <summary>
    /// Pull authenticated account inbox packages and absorb staged package files locally.
    /// </summary>
    public async Task<WalletPullResult> PullAndAbsorbAsync(
        WalletPullOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var pullOptions = options ?? new WalletPullOptions();
        var stage = await StageInboxAsync(
            new WalletStageInboxOptions
            {
                VaultBaseUrl = pullOptions.VaultBaseUrl,
                BearerToken = pullOptions.BearerToken,
                HttpClient = pullOptions.HttpClient,
            },
            cancellationToken).ConfigureAwait(false);

        if (stage.NotBound || stage.Unauthorized)
        {
            return new WalletPullResult(stage, [], []);
        }

        var packagePaths = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        if (pullOptions.AbsorbExisting && Directory.Exists(InboxDirectory()))
        {
            foreach (var path in Directory.EnumerateFiles(InboxDirectory(), "*.tnpkg", SearchOption.AllDirectories))
            {
                packagePaths.Add(Path.GetFullPath(path));
            }
        }

        foreach (var path in stage.StagedPaths)
        {
            packagePaths.Add(Path.GetFullPath(path));
        }

        var receipts = new List<PackageAbsorbReceipt>();
        var rejectedPaths = new List<string>();
        foreach (var path in packagePaths)
        {
            try
            {
                receipts.Add(await _tn.Packages.AbsorbAsync(path, cancellationToken).ConfigureAwait(false));
            }
            catch (TnException)
            {
                rejectedPaths.Add(path);
            }
        }

        return new WalletPullResult(stage, receipts, rejectedPaths);
    }

    /// <summary>
    /// Pull account preferences from the vault and cache them in local wallet state.
    /// </summary>
    public async Task<WalletPullPrefsResult> PullPrefsAsync(
        WalletPullPrefsOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var prefsOptions = options ?? new WalletPullPrefsOptions();
        var vaultBaseUrl = prefsOptions.VaultBaseUrl;
        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            var link = await _tn.Vault.LinkStateAsync(cancellationToken).ConfigureAwait(false);
            vaultBaseUrl = link.LinkedVault;
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new TnException("wallet pull-prefs requires a vault URL or linked vault");
        }

        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = vaultBaseUrl,
            BearerToken = prefsOptions.BearerToken,
            HttpClient = prefsOptions.HttpClient,
        });
        var prefs = await client.GetAccountPrefsAsync(cancellationToken).ConfigureAwait(false);
        var state = await ReadStateJsonAsync(cancellationToken).ConfigureAwait(false);
        var statePrefs = state["prefs"] as JsonObject ?? [];
        statePrefs["default_new_ceremony_mode"] = prefs.DefaultNewCeremonyMode;
        state["prefs"] = statePrefs;
        state["prefs_version"] = prefs.PrefsVersion;
        await WriteStateJsonAsync(state, cancellationToken).ConfigureAwait(false);

        return new WalletPullPrefsResult(
            client.BaseUrl,
            prefs.DefaultNewCeremonyMode,
            prefs.PrefsVersion,
            SyncStatePath());
    }

    /// <summary>
    /// Publish local group-key material to the vault account inbox.
    /// </summary>
    public async Task<WalletPublishGroupKeysResult> PublishGroupKeysAsync(
        WalletPublishGroupKeysOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var publishOptions = options ?? new WalletPublishGroupKeysOptions();
        var vaultBaseUrl = publishOptions.VaultBaseUrl;
        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            var link = await _tn.Vault.LinkStateAsync(cancellationToken).ConfigureAwait(false);
            vaultBaseUrl = link.LinkedVault;
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new TnException("wallet group-key publish requires a vault URL or linked vault");
        }

        var packagePath = Path.Combine(
            Path.GetTempPath(),
            $"tn-group-keys-{Environment.ProcessId}-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid():N}.tnpkg");
        try
        {
            try
            {
                await _tn.Packages.ExportGroupKeysAsync(
                    packagePath,
                    publishOptions.Groups,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (TnException ex) when (ex.Message.Contains("group_keys: no btn groups", StringComparison.Ordinal))
            {
                return new WalletPublishGroupKeysResult(
                    null,
                    null,
                    publishOptions.Groups?.ToArray() ?? []);
            }

            var info = await _tn.Packages.InspectAsync(packagePath, cancellationToken).ConfigureAwait(false);
            var bytes = await File.ReadAllBytesAsync(packagePath, cancellationToken).ConfigureAwait(false);
            using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
            {
                BaseUrl = vaultBaseUrl,
                BearerToken = publishOptions.BearerToken,
                HttpClient = publishOptions.HttpClient,
            });
            var snapshot = await client.PostInboxSnapshotAsync(
                info.PublisherIdentity,
                info.CeremonyId,
                publishOptions.Timestamp ?? InboxSnapshotTimestamp(),
                bytes,
                cancellationToken).ConfigureAwait(false);

            return new WalletPublishGroupKeysResult(
                null,
                snapshot,
                publishOptions.Groups?.ToArray() ?? []);
        }
        finally
        {
            TryDelete(packagePath);
        }
    }

    /// <summary>
    /// Run a composed wallet sync pass.
    /// </summary>
    public async Task<WalletSyncResult> SyncAsync(
        WalletSyncOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var syncOptions = options ?? new WalletSyncOptions();
        WalletPullResult? pull = null;
        WalletPublishGroupKeysResult? groupKeys = null;
        VaultPushBodyResult? bodyPush = null;

        if (!syncOptions.PushOnly)
        {
            pull = await PullAndAbsorbAsync(
                new WalletPullOptions
                {
                    VaultBaseUrl = syncOptions.VaultBaseUrl,
                    BearerToken = syncOptions.BearerToken,
                    HttpClient = syncOptions.HttpClient,
                },
                cancellationToken).ConfigureAwait(false);

            if (syncOptions.PullOnly)
            {
                return new WalletSyncResult(pull, null, null);
            }

            if (syncOptions.PublishGroupKeys)
            {
                groupKeys = await PublishGroupKeysAsync(
                    new WalletPublishGroupKeysOptions
                    {
                        VaultBaseUrl = syncOptions.VaultBaseUrl,
                        BearerToken = syncOptions.BearerToken,
                        HttpClient = syncOptions.HttpClient,
                        Groups = syncOptions.Groups,
                        Timestamp = syncOptions.Timestamp,
                    },
                    cancellationToken).ConfigureAwait(false);
            }
        }

        if (syncOptions.PushBody)
        {
            bodyPush = await _tn.Vault.PushBodyWithPassphraseAsync(
                new VaultPushBodyWithPassphraseOptions
                {
                    VaultBaseUrl = syncOptions.VaultBaseUrl,
                    BearerToken = syncOptions.BearerToken,
                    ProjectId = syncOptions.ProjectId,
                    Passphrase = syncOptions.Passphrase,
                    CredentialId = syncOptions.CredentialId,
                },
                cancellationToken).ConfigureAwait(false);
        }

        return new WalletSyncResult(pull, groupKeys, bodyPush);
    }

    /// <summary>
    /// Download, decrypt, and install a vault project body into an explicit target directory.
    /// </summary>
    public async Task<WalletRestoreResult> RestoreAsync(
        WalletRestoreOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (!options.UseCachedAccountKey && string.IsNullOrWhiteSpace(options.Passphrase))
        {
            throw new ArgumentException("Passphrase must not be empty.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.TargetDirectory))
        {
            throw new ArgumentException("TargetDirectory must not be empty.", nameof(options));
        }

        var vaultBaseUrl = options.VaultBaseUrl;
        var projectId = options.ProjectId;
        if (string.IsNullOrWhiteSpace(vaultBaseUrl) || string.IsNullOrWhiteSpace(projectId))
        {
            var link = await _tn.Vault.LinkStateAsync(cancellationToken).ConfigureAwait(false);
            vaultBaseUrl = string.IsNullOrWhiteSpace(vaultBaseUrl) ? link.LinkedVault : vaultBaseUrl;
            projectId = string.IsNullOrWhiteSpace(projectId) ? link.LinkedProjectId : projectId;
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("Wallet restore requires a vault URL or linked vault.", nameof(options));
        }

        var targetDirectory = Path.GetFullPath(options.TargetDirectory);
        var resultJson = options.UseCachedAccountKey
            ? NativeBridge.VaultRestoreInstallBodyWithAwk(
                _tn.NativeHandle,
                vaultBaseUrl,
                options.BearerToken,
                projectId,
                Convert.ToBase64String(await LoadCachedAccountKeyAsync(options, cancellationToken).ConfigureAwait(false)),
                targetDirectory,
                options.Overwrite)
            : NativeBridge.VaultRestoreInstallBodyWithPassphrase(
                _tn.NativeHandle,
                vaultBaseUrl,
                options.BearerToken,
                projectId,
                options.Passphrase!,
                options.CredentialId,
                targetDirectory,
                options.Overwrite);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native wallet restore returned non-object JSON");

        return new WalletRestoreResult(
            result["project_id"]?.GetValue<string>()
                ?? throw new TnException("native wallet restore result omitted project_id"),
            result["body_member_count"]?.GetValue<int>()
                ?? throw new TnException("native wallet restore result omitted body_member_count"),
            result["total_body_bytes"]?.GetValue<ulong>()
                ?? throw new TnException("native wallet restore result omitted total_body_bytes"),
            ReadStringArray(result, "body_member_names"),
            result["target_dir"]?.GetValue<string>()
                ?? throw new TnException("native wallet restore result omitted target_dir"),
            result["yaml_path"]?.GetValue<string>()
                ?? throw new TnException("native wallet restore result omitted yaml_path"),
            result["keys_dir"]?.GetValue<string>()
                ?? throw new TnException("native wallet restore result omitted keys_dir"),
            ReadStringArray(result, "written_paths"),
            ReadStringArray(result, "deduped_paths"),
            ReadStringArray(result, "skipped_members"),
            result["wrapped_key"]?.DeepClone(),
            result["encrypted_blob_response"]?.DeepClone());
    }

    private async Task<byte[]> LoadCachedAccountKeyAsync(
        WalletRestoreOptions options,
        CancellationToken cancellationToken)
    {
        var accountId = options.AccountId;
        if (string.IsNullOrWhiteSpace(accountId))
        {
            var state = await _tn.Account.StateAsync(cancellationToken).ConfigureAwait(false);
            accountId = state.AccountId;
        }

        if (string.IsNullOrWhiteSpace(accountId))
        {
            throw new ArgumentException(
                "Wallet restore with cached account key requires AccountId or a local account binding.",
                nameof(options));
        }

        var awk = await AccountCredentialStore.Default()
            .GetAccountAwkAsync(accountId, cancellationToken)
            .ConfigureAwait(false);
        return awk ?? throw new TnException($"cached account key not found for account {accountId}");
    }

    private async Task<WalletPendingClaim?> ReadPendingClaimAsync(CancellationToken cancellationToken)
    {
        var state = await ReadStateJsonAsync(cancellationToken).ConfigureAwait(false);
        var pending = state["pending_claim"] as JsonObject;
        if (pending is null)
        {
            return null;
        }

        var vaultId = pending["vault_id"]?.GetValue<string>();
        var expiresAt = pending["expires_at"]?.GetValue<string>();
        var claimUrl = pending["claim_url"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(vaultId)
            || string.IsNullOrWhiteSpace(expiresAt)
            || string.IsNullOrWhiteSpace(claimUrl))
        {
            return null;
        }

        var expired = DateTimeOffset.TryParse(expiresAt, out var parsed)
            && parsed <= DateTimeOffset.UtcNow;
        return new WalletPendingClaim(vaultId, expiresAt, claimUrl, expired);
    }

    private async Task<JsonObject> ReadStateJsonAsync(CancellationToken cancellationToken)
    {
        var path = SyncStatePath();
        if (!File.Exists(path))
        {
            return [];
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                bufferSize: 4096,
                FileOptions.Asynchronous);
            return await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false) as JsonObject ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private async Task WriteStateJsonAsync(JsonObject state, CancellationToken cancellationToken)
    {
        var path = SyncStatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(
            path,
            state.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            cancellationToken).ConfigureAwait(false);
    }

    private string SyncStatePath()
    {
        var yamlDirectory = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("tn.yaml path has no parent directory");
        return Path.Combine(yamlDirectory, ".tn", "sync", "state.json");
    }

    private string InboxDirectory()
    {
        var yamlDirectory = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("tn.yaml path has no parent directory");
        return Path.Combine(yamlDirectory, ".tn", "inbox");
    }

    private static string? SafePathSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed is "." or "..")
        {
            return null;
        }

        var invalid = Path.GetInvalidFileNameChars();
        var chars = trimmed.Select(ch => invalid.Contains(ch) || ch is '/' or '\\' or ':' ? '_' : ch).ToArray();
        var safe = new string(chars).Trim('.');
        return string.IsNullOrWhiteSpace(safe) ? null : safe;
    }

    private static IReadOnlyList<string> ReadStringArray(JsonObject result, string propertyName)
    {
        var array = result[propertyName] as JsonArray
            ?? throw new TnException($"native wallet restore result omitted {propertyName}");
        return array.Select(item => item?.GetValue<string>() ?? string.Empty).ToArray();
    }

    private static string InboxSnapshotTimestamp()
    {
        return DateTimeOffset.UtcNow.ToString("yyyyMMdd'T'HHmmssffffff'Z'", CultureInfo.InvariantCulture);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static WalletVerdict DetermineVerdict(
        bool accountBound,
        VaultLinkStateInfo vault,
        WalletPendingClaim? pendingClaim,
        IReadOnlyCollection<string> warnings)
    {
        if (warnings.Count > 0)
        {
            return WalletVerdict.NeedsRepair;
        }

        if (vault.State == VaultLinkState.Linked && !string.IsNullOrWhiteSpace(vault.LinkedProjectId))
        {
            return WalletVerdict.Linked;
        }

        if (pendingClaim is not null)
        {
            return WalletVerdict.PendingClaim;
        }

        if (accountBound)
        {
            return WalletVerdict.AccountBound;
        }

        return WalletVerdict.LocalOnly;
    }
}
