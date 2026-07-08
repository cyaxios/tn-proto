using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using TnProto.Native;

namespace TnProto.Vault;

/// <summary>
/// Local vault link-state helpers for a TN project.
/// </summary>
public sealed class VaultClient
{
    private readonly Tn _tn;

    internal VaultClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// Read the current local vault link-state from <c>tn.yaml</c>.
    /// </summary>
    public async Task<VaultLinkStateInfo> LinkStateAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var lines = await File.ReadAllLinesAsync(_tn.YamlPath, cancellationToken).ConfigureAwait(false);
        var ceremony = ReadBlock(lines, "ceremony");
        var vault = ReadBlock(lines, "vault");
        var vaultEnabled = !vault.TryGetValue("enabled", out var enabled) || ParseBool(enabled) != false;
        var linkedVault = vaultEnabled ? NonEmpty(vault.GetValueOrDefault("url")) : null;
        linkedVault ??= vault.Count == 0 ? NonEmpty(ceremony.GetValueOrDefault("linked_vault")) : null;
        linkedVault ??= NonEmpty(ceremony.GetValueOrDefault("linked_vault"));
        var linkedProjectId = vaultEnabled ? NonEmpty(vault.GetValueOrDefault("linked_project_id")) : null;
        linkedProjectId ??= vault.Count == 0 ? NonEmpty(ceremony.GetValueOrDefault("linked_project_id")) : null;
        linkedProjectId ??= NonEmpty(ceremony.GetValueOrDefault("linked_project_id"));
        var state = string.Equals(ceremony.GetValueOrDefault("mode"), "linked", StringComparison.Ordinal)
            ? VaultLinkState.Linked
            : VaultLinkState.Local;

        return new VaultLinkStateInfo(
            state,
            _tn.YamlPath,
            linkedVault,
            linkedProjectId,
            vaultEnabled,
            ParseBool(vault.GetValueOrDefault("autosync")) ?? false,
            ParseInt(vault.GetValueOrDefault("sync_interval_seconds")));
    }

    /// <summary>
    /// Mutate local <c>tn.yaml</c> vault link-state.
    /// </summary>
    public async Task<VaultLinkStateResult> SetLinkStateAsync(
        VaultLinkState state,
        SetVaultLinkStateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var stateOptions = options ?? new SetVaultLinkStateOptions();
        if (state == VaultLinkState.Linked && string.IsNullOrWhiteSpace(stateOptions.LinkedVault))
        {
            throw new ArgumentException("Linked vault state requires a vault URL.", nameof(options));
        }

        if (state == VaultLinkState.Linked && string.IsNullOrWhiteSpace(stateOptions.LinkedProjectId))
        {
            throw new ArgumentException("Linked vault state requires a project id.", nameof(options));
        }

        var lines = (await File.ReadAllLinesAsync(_tn.YamlPath, cancellationToken).ConfigureAwait(false)).ToList();
        EnsureTopLevelBlock(lines, "ceremony");
        EnsureTopLevelBlock(lines, "vault");

        if (state == VaultLinkState.Linked)
        {
            SetBlockScalar(lines, "ceremony", "mode", state.ToTnName());
            SetBlockScalar(lines, "ceremony", "linked_vault", stateOptions.LinkedVault!);
            SetBlockScalar(lines, "ceremony", "linked_project_id", stateOptions.LinkedProjectId!);
            SetBlockScalar(lines, "vault", "enabled", "true");
            SetBlockScalar(lines, "vault", "url", stateOptions.LinkedVault!);
            SetBlockScalar(lines, "vault", "linked_project_id", stateOptions.LinkedProjectId!);
            SetBlockScalar(lines, "vault", "autosync", "true");
            EnsureBlockScalar(lines, "vault", "sync_interval_seconds", "600");
        }
        else
        {
            SetBlockScalar(lines, "ceremony", "mode", state.ToTnName());
            SetBlockScalar(lines, "ceremony", "linked_vault", "");
            SetBlockScalar(lines, "ceremony", "linked_project_id", "");
            SetBlockScalar(lines, "vault", "enabled", "false");
            SetBlockScalar(lines, "vault", "url", "");
            SetBlockScalar(lines, "vault", "linked_project_id", "");
            SetBlockScalar(lines, "vault", "autosync", "false");
            EnsureBlockScalar(lines, "vault", "sync_interval_seconds", "600");
        }

        await File.WriteAllLinesAsync(_tn.YamlPath, lines, cancellationToken).ConfigureAwait(false);
        return new VaultLinkStateResult(
            state,
            _tn.YamlPath,
            state == VaultLinkState.Linked ? stateOptions.LinkedVault : null,
            state == VaultLinkState.Linked ? stateOptions.LinkedProjectId : null);
    }

    /// <summary>
    /// Mark this local project as linked to a vault project.
    /// </summary>
    public Task<VaultLinkStateResult> LinkAsync(
        string vault,
        string projectId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(vault))
        {
            throw new ArgumentException("Vault URL must not be empty.", nameof(vault));
        }

        if (string.IsNullOrWhiteSpace(projectId))
        {
            throw new ArgumentException("Project id must not be empty.", nameof(projectId));
        }

        return SetLinkStateAsync(
            VaultLinkState.Linked,
            new SetVaultLinkStateOptions
            {
                LinkedVault = vault.TrimEnd('/'),
                LinkedProjectId = projectId,
            },
            cancellationToken);
    }

    /// <summary>
    /// Mark this local project as no longer linked to a vault project.
    /// </summary>
    public Task<VaultLinkStateResult> UnlinkAsync(CancellationToken cancellationToken = default)
    {
        return SetLinkStateAsync(VaultLinkState.Local, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Create or discover a vault project, then persist local link-state.
    /// </summary>
    public async Task<VaultConnectResult> ConnectAsync(
        VaultConnectOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(options.VaultBaseUrl))
        {
            throw new ArgumentException("Vault base URL must not be empty.", nameof(options));
        }

        var before = await LinkStateAsync(cancellationToken).ConfigureAwait(false);
        var projectName = string.IsNullOrWhiteSpace(options.ProjectName)
            ? _tn.ProjectName ?? ReadProjectName() ?? "tn-project"
            : options.ProjectName.Trim();
        var ceremonyId = ReadCeremonyId();
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = options.VaultBaseUrl,
            BearerToken = options.BearerToken,
            HttpClient = options.HttpClient,
        });
        if (string.IsNullOrWhiteSpace(options.BearerToken) && options.AutoAuthenticate)
        {
            var seed = await File.ReadAllBytesAsync(LocalPrivateKeyPath(), cancellationToken).ConfigureAwait(false);
            await client.AuthenticateAsync(_tn.Did, seed, cancellationToken).ConfigureAwait(false);
        }

        var project = await client.EnsureProjectAsync(projectName, ceremonyId, cancellationToken)
            .ConfigureAwait(false);
        await LinkAsync(client.BaseUrl, project.Id, cancellationToken).ConfigureAwait(false);
        var after = await LinkStateAsync(cancellationToken).ConfigureAwait(false);
        var newlyLinked = before.State != VaultLinkState.Linked
            || !string.Equals(before.LinkedVault, client.BaseUrl, StringComparison.Ordinal)
            || !string.Equals(before.LinkedProjectId, project.Id, StringComparison.Ordinal);

        return new VaultConnectResult(client.BaseUrl, project, after, newlyLinked);
    }

    /// <summary>
    /// Build an encrypted full-keystore package, post it to pending claims, and return a browser claim URL.
    /// </summary>
    public async Task<VaultInitUploadResult> InitUploadAsync(
        VaultInitUploadOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(options.VaultBaseUrl))
        {
            throw new ArgumentException("Vault base URL must not be empty.", nameof(options));
        }

        if (options.ReusePendingClaim)
        {
            var existing = await ReadPendingClaimAsync(cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                return existing with { Reused = true };
            }
        }

        var bek = RandomNumberGenerator.GetBytes(32);
        var passwordBase64Url = Base64UrlNoPadding(bek);
        var tempPath = Path.Combine(
            Path.GetTempPath(),
            $"tn-init-upload-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid():N}.tnpkg");
        try
        {
            var groupsJson = options.Groups is null || options.Groups.Count == 0
                ? null
                : JsonSerializer.Serialize(options.Groups);
            NativeBridge.PackageExportEncryptedFullKeystore(
                _tn.NativeHandle,
                tempPath,
                groupsJson,
                Convert.ToBase64String(bek));
            var body = await File.ReadAllBytesAsync(tempPath, cancellationToken).ConfigureAwait(false);
            using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
            {
                BaseUrl = options.VaultBaseUrl,
                HttpClient = options.HttpClient,
            });
            var projectName = string.IsNullOrWhiteSpace(options.ProjectName)
                ? _tn.ProjectName ?? ReadProjectName()
                : options.ProjectName.Trim();
            var (vaultId, expiresAt) = await client.PostPendingClaimAsync(
                body,
                projectName,
                _tn.Did,
                cancellationToken).ConfigureAwait(false);
            var claimUrl = $"{client.BaseUrl}/claim/{vaultId}#k={passwordBase64Url}";
            var result = new VaultInitUploadResult(
                vaultId,
                expiresAt,
                claimUrl,
                passwordBase64Url,
                Reused: false);
            await PersistPendingClaimSurfacesAsync(result, cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    /// <summary>
    /// Push the local project body to the vault using a passphrase-derived account wrap key.
    /// </summary>
    public async Task<VaultPushBodyResult> PushBodyWithPassphraseAsync(
        VaultPushBodyWithPassphraseOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(options.Passphrase))
        {
            throw new ArgumentException("Passphrase must not be empty.", nameof(options));
        }

        var vaultBaseUrl = options.VaultBaseUrl;
        var projectId = options.ProjectId;
        if (string.IsNullOrWhiteSpace(vaultBaseUrl) || string.IsNullOrWhiteSpace(projectId))
        {
            var link = await LinkStateAsync(cancellationToken).ConfigureAwait(false);
            vaultBaseUrl = string.IsNullOrWhiteSpace(vaultBaseUrl) ? link.LinkedVault : vaultBaseUrl;
            projectId = string.IsNullOrWhiteSpace(projectId) ? link.LinkedProjectId : projectId;
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("Vault body push requires a vault URL or linked vault.", nameof(options));
        }

        var resultJson = NativeBridge.VaultPushBodyWithPassphrase(
            _tn.NativeHandle,
            vaultBaseUrl,
            options.BearerToken,
            projectId,
            options.Passphrase,
            options.CredentialId);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native vault push-body returned non-object JSON");

        return new VaultPushBodyResult(
            result["project_id"]?.GetValue<string>()
                ?? throw new TnException("native vault push-body result omitted project_id"),
            result["body_member_count"]?.GetValue<int>()
                ?? throw new TnException("native vault push-body result omitted body_member_count"),
            result["encrypted_len"]?.GetValue<int>()
                ?? throw new TnException("native vault push-body result omitted encrypted_len"),
            result["wrapped_key_created"]?.GetValue<bool>()
                ?? throw new TnException("native vault push-body result omitted wrapped_key_created"),
            result["if_match"]?.GetValue<string>()
                ?? throw new TnException("native vault push-body result omitted if_match"),
            result["wrapped_key_response"]?.DeepClone(),
            result["encrypted_blob_response"]?.DeepClone());
    }

    /// <summary>
    /// Restore and decrypt the project body from the vault without installing files.
    /// </summary>
    public async Task<VaultRestoreBodyResult> RestoreBodyWithPassphraseAsync(
        VaultRestoreBodyWithPassphraseOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(options.Passphrase))
        {
            throw new ArgumentException("Passphrase must not be empty.", nameof(options));
        }

        var vaultBaseUrl = options.VaultBaseUrl;
        var projectId = options.ProjectId;
        if (string.IsNullOrWhiteSpace(vaultBaseUrl) || string.IsNullOrWhiteSpace(projectId))
        {
            var link = await LinkStateAsync(cancellationToken).ConfigureAwait(false);
            vaultBaseUrl = string.IsNullOrWhiteSpace(vaultBaseUrl) ? link.LinkedVault : vaultBaseUrl;
            projectId = string.IsNullOrWhiteSpace(projectId) ? link.LinkedProjectId : projectId;
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("Vault body restore requires a vault URL or linked vault.", nameof(options));
        }

        var resultJson = NativeBridge.VaultRestoreBodyWithPassphrase(
            _tn.NativeHandle,
            vaultBaseUrl,
            options.BearerToken,
            projectId,
            options.Passphrase,
            options.CredentialId);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native vault restore-body returned non-object JSON");
        var bodyMemberNames = result["body_member_names"] as JsonArray
            ?? throw new TnException("native vault restore-body result omitted body_member_names");

        return new VaultRestoreBodyResult(
            result["project_id"]?.GetValue<string>()
                ?? throw new TnException("native vault restore-body result omitted project_id"),
            result["body_member_count"]?.GetValue<int>()
                ?? throw new TnException("native vault restore-body result omitted body_member_count"),
            result["total_body_bytes"]?.GetValue<ulong>()
                ?? throw new TnException("native vault restore-body result omitted total_body_bytes"),
            bodyMemberNames.Select(item => item?.GetValue<string>() ?? string.Empty).ToArray(),
            result["wrapped_key"]?.DeepClone(),
            result["encrypted_blob_response"]?.DeepClone());
    }

    private static Dictionary<string, string> ReadBlock(IReadOnlyList<string> lines, string block)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var range = FindTopLevelBlock(lines, block);
        if (range is null)
        {
            return result;
        }

        for (var i = range.Value.Start + 1; i < range.Value.End; i++)
        {
            var line = lines[i];
            if (!line.StartsWith("  ", StringComparison.Ordinal) || line.StartsWith("    ", StringComparison.Ordinal))
            {
                continue;
            }

            var trimmed = line.Trim();
            var colon = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            result[trimmed[..colon]] = Unquote(trimmed[(colon + 1)..].Trim());
        }

        return result;
    }

    private string? ReadCeremonyId()
    {
        var lines = File.ReadAllLines(_tn.YamlPath);
        return NonEmpty(ReadBlock(lines, "ceremony").GetValueOrDefault("id"));
    }

    private string? ReadProjectName()
    {
        var lines = File.ReadAllLines(_tn.YamlPath);
        return NonEmpty(ReadBlock(lines, "ceremony").GetValueOrDefault("project_name"));
    }

    private async Task<VaultInitUploadResult?> ReadPendingClaimAsync(CancellationToken cancellationToken)
    {
        var path = SyncStatePath();
        if (!File.Exists(path))
        {
            return null;
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
            var state = await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false) as JsonObject;
            var pending = state?["pending_claim"] as JsonObject;
            if (pending is null)
            {
                return null;
            }

            var expiresAt = pending["expires_at"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(expiresAt)
                || !DateTimeOffset.TryParse(expiresAt, out var expires)
                || expires <= DateTimeOffset.UtcNow)
            {
                return null;
            }

            var vaultId = pending["vault_id"]?.GetValue<string>();
            var claimUrl = pending["claim_url"]?.GetValue<string>();
            var password = pending["password_b64"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(vaultId)
                || string.IsNullOrWhiteSpace(claimUrl)
                || string.IsNullOrWhiteSpace(password))
            {
                return null;
            }

            return new VaultInitUploadResult(vaultId, expiresAt, claimUrl, password, Reused: true);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task PersistPendingClaimSurfacesAsync(
        VaultInitUploadResult result,
        CancellationToken cancellationToken)
    {
        var statePath = SyncStatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(statePath)!);
        JsonObject state = [];
        if (File.Exists(statePath))
        {
            try
            {
                await using var stream = new FileStream(
                    statePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite,
                    bufferSize: 4096,
                    FileOptions.Asynchronous);
                state = await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken)
                    .ConfigureAwait(false) as JsonObject ?? [];
            }
            catch (JsonException)
            {
                state = [];
            }
        }

        state["pending_claim"] = new JsonObject
        {
            ["vault_id"] = result.VaultId,
            ["expires_at"] = result.ExpiresAt,
            ["claim_url"] = result.ClaimUrl,
            ["password_b64"] = result.PasswordBase64Url,
        };
        await File.WriteAllTextAsync(
            statePath,
            state.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            cancellationToken).ConfigureAwait(false);
        await File.WriteAllTextAsync(
            Path.Combine(Path.GetDirectoryName(statePath)!, "claim_url.txt"),
            result.ClaimUrl + Environment.NewLine,
            cancellationToken).ConfigureAwait(false);
        await PersistClaimUrlAdminEventAsync(result, cancellationToken).ConfigureAwait(false);
    }

    private async Task PersistClaimUrlAdminEventAsync(
        VaultInitUploadResult result,
        CancellationToken cancellationToken)
    {
        var yamlDir = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("tn.yaml path has no parent directory");
        var outbox = Path.Combine(yamlDir, ".tn", "admin", "outbox");
        Directory.CreateDirectory(outbox);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssffffffZ");
        var path = Path.Combine(outbox, $"claim_url_issued_{stamp}_{result.VaultId}.json");
        var envelope = new JsonObject
        {
            ["claim_url_redacted"] = RedactClaimUrl(result.ClaimUrl),
            ["did"] = _tn.Did,
            ["emitted_at"] = DateTimeOffset.UtcNow.ToString("O"),
            ["event_type"] = "tn.vault.claim_url_issued",
            ["expires_at"] = result.ExpiresAt,
            ["vault_id"] = result.VaultId,
        };
        await File.WriteAllTextAsync(
            path,
            envelope.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            cancellationToken).ConfigureAwait(false);
    }

    private string SyncStatePath()
    {
        var yamlDirectory = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("tn.yaml path has no parent directory");
        return Path.Combine(yamlDirectory, ".tn", "sync", "state.json");
    }

    private string LocalPrivateKeyPath()
    {
        var yamlDirectory = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("tn.yaml path has no parent directory");
        var defaultPath = Path.Combine(yamlDirectory, "keys", "local.private");
        if (File.Exists(defaultPath))
        {
            return defaultPath;
        }

        var yaml = File.ReadAllLines(_tn.YamlPath);
        var inKeystore = false;
        foreach (var rawLine in yaml)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (!rawLine.StartsWith(' ') && line.EndsWith(':'))
            {
                inKeystore = string.Equals(line, "keystore:", StringComparison.Ordinal);
                continue;
            }

            if (inKeystore && line.StartsWith("path:", StringComparison.Ordinal))
            {
                var rawPath = line["path:".Length..].Trim().Trim('"', '\'');
                var resolved = Path.IsPathRooted(rawPath)
                    ? rawPath
                    : Path.GetFullPath(Path.Combine(yamlDirectory, rawPath));
                var localPrivate = Directory.Exists(resolved)
                    ? Path.Combine(resolved, "local.private")
                    : resolved;
                if (File.Exists(localPrivate))
                {
                    return localPrivate;
                }
            }
        }

        throw new TnException($"local private key not found at {defaultPath}");
    }

    private static void EnsureTopLevelBlock(List<string> lines, string block)
    {
        if (FindTopLevelBlock(lines, block) is not null)
        {
            return;
        }

        if (lines.Count > 0 && !string.IsNullOrWhiteSpace(lines[^1]))
        {
            lines.Add(string.Empty);
        }

        lines.Add($"{block}:");
    }

    private static void EnsureBlockScalar(List<string> lines, string block, string key, string value)
    {
        var existing = ReadBlock(lines, block);
        if (existing.ContainsKey(key))
        {
            return;
        }

        SetBlockScalar(lines, block, key, value);
    }

    private static void SetBlockScalar(List<string> lines, string block, string key, string value)
    {
        var maybeRange = FindTopLevelBlock(lines, block)
            ?? throw new TnException($"tn.yaml does not contain a {block} block");
        var range = maybeRange;
        var rendered = $"  {key}: {RenderScalar(value)}";
        for (var i = range.Start + 1; i < range.End; i++)
        {
            var line = lines[i];
            if (!line.StartsWith("  ", StringComparison.Ordinal) || line.StartsWith("    ", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.TrimStart().StartsWith($"{key}:", StringComparison.Ordinal))
            {
                lines[i] = rendered;
                return;
            }
        }

        lines.Insert(range.End, rendered);
    }

    private static (int Start, int End)? FindTopLevelBlock(IReadOnlyList<string> lines, string block)
    {
        var header = $"{block}:";
        for (var i = 0; i < lines.Count; i++)
        {
            if (!string.Equals(lines[i].TrimEnd(), header, StringComparison.Ordinal))
            {
                continue;
            }

            var end = i + 1;
            while (end < lines.Count)
            {
                var line = lines[end];
                if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
                {
                    break;
                }

                end++;
            }

            return (i, end);
        }

        return null;
    }

    private static string? NonEmpty(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static bool? ParseBool(string? value)
    {
        return value?.Trim().ToLowerInvariant() switch
        {
            "true" => true,
            "false" => false,
            _ => null,
        };
    }

    private static int? ParseInt(string? value)
    {
        return int.TryParse(value, out var parsed) ? parsed : null;
    }

    private static string Base64UrlNoPadding(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string RedactClaimUrl(string claimUrl)
    {
        var index = claimUrl.IndexOf('#', StringComparison.Ordinal);
        return index < 0 ? claimUrl : claimUrl[..index] + "#<redacted>";
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

    private static string Unquote(string value)
    {
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'')
        {
            return value[1..^1].Replace("''", "'", StringComparison.Ordinal);
        }

        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
        {
            return value[1..^1];
        }

        return value;
    }

    private static string RenderScalar(string value)
    {
        if (value.Length == 0)
        {
            return "''";
        }

        if (value.Any(char.IsWhiteSpace) || value.Contains('#', StringComparison.Ordinal))
        {
            return $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";
        }

        return value;
    }
}
