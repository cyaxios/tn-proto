using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TnProto.Account;

/// <summary>
/// Local account binding helpers for vault-backed workflows.
/// </summary>
public sealed class AccountClient
{
    private readonly Tn _tn;

    internal AccountClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// Read the persisted local account binding state.
    /// </summary>
    public async Task<AccountState> StateAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var state = await ReadStateJsonAsync(cancellationToken).ConfigureAwait(false);
        return new AccountState(
            state["account_id"]?.GetValue<string>(),
            state["account_bound"]?.GetValue<bool>() ?? false);
    }

    /// <summary>
    /// Return a user-facing account status snapshot.
    /// </summary>
    public async Task<AccountStatus> StatusAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var state = await StateAsync(cancellationToken).ConfigureAwait(false);
        var keyCached = await IsAccountKeyCachedAsync(state, cancellationToken).ConfigureAwait(false);
        var verdict = !state.AccountBound
            ? AccountVerdict.NotLoggedIn
            : keyCached
                ? AccountVerdict.BackedUp
                : AccountVerdict.LinkedNoKey;

        return new AccountStatus(
            _tn.Did,
            state.AccountId,
            state.AccountBound,
            Vault: null,
            keyCached,
            verdict);
    }

    private static async Task<bool> IsAccountKeyCachedAsync(
        AccountState state,
        CancellationToken cancellationToken)
    {
        if (!state.AccountBound || string.IsNullOrWhiteSpace(state.AccountId))
        {
            return false;
        }

        try
        {
            return await AccountCredentialStore.Default()
                .GetAccountAwkAsync(state.AccountId, cancellationToken)
                .ConfigureAwait(false) is not null;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Alias for <see cref="StatusAsync"/> shaped like Python and TypeScript account helpers.
    /// </summary>
    public Task<AccountStatus> WhoamiAsync(CancellationToken cancellationToken = default)
    {
        return StatusAsync(cancellationToken);
    }

    /// <summary>
    /// Redeem a vault connect code and mark this local project as account-bound.
    /// </summary>
    public async Task<AccountConnectResult> ConnectCodeAsync(
        string code,
        AccountConnectOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(code))
        {
            throw new ArgumentException("Connect code must not be empty.", nameof(code));
        }

        var connectOptions = options ?? new AccountConnectOptions();
        if (string.IsNullOrWhiteSpace(connectOptions.VaultBaseUrl))
        {
            throw new ArgumentException("Vault base URL must not be empty.", nameof(options));
        }

        var vault = connectOptions.VaultBaseUrl.TrimEnd('/');
        using var ownedClient = connectOptions.HttpClient is null ? new HttpClient() : null;
        var client = connectOptions.HttpClient ?? ownedClient!;
        var signature = await SignConnectCodeAsync(code, cancellationToken).ConfigureAwait(false);
        var body = new JsonObject
        {
            ["code"] = code,
            ["did"] = _tn.Did,
            ["signature_b64"] = signature,
        };

        using var response = await client.PostAsJsonAsync(
            $"{vault}/api/v1/account/connect-codes/redeem",
            body,
            cancellationToken).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new TnException($"Vault connect-code redemption failed ({(int)response.StatusCode}): {text}");
        }

        var result = JsonNode.Parse(text) as JsonObject
            ?? throw new TnException("vault connect-code response was not a JSON object");
        var accountId = result["account_id"]?.GetValue<string>()
            ?? throw new TnException("vault connect-code response omitted account_id");

        await MarkAccountBoundAsync(accountId, cancellationToken).ConfigureAwait(false);

        return new AccountConnectResult(
            accountId,
            result["project_id"]?.GetValue<string>(),
            result["project_name"]?.GetValue<string>(),
            vault,
            result);
    }

    /// <summary>
    /// Clear the local account binding without deleting project data.
    /// </summary>
    public async Task<AccountLogoutResult> LogoutAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var state = await ReadStateJsonAsync(cancellationToken).ConfigureAwait(false);
        var previous = new AccountLogoutResult(
            state["account_bound"]?.GetValue<bool>() ?? false,
            state["account_id"]?.GetValue<string>());
        state.Remove("account_id");
        state["account_bound"] = false;
        state.Remove("pending_claim");
        await WriteStateJsonAsync(state, cancellationToken).ConfigureAwait(false);
        return previous;
    }

    private async Task MarkAccountBoundAsync(string accountId, CancellationToken cancellationToken)
    {
        var state = await ReadStateJsonAsync(cancellationToken).ConfigureAwait(false);
        state["account_id"] = accountId;
        state["account_bound"] = true;
        state.Remove("pending_claim");
        await WriteStateJsonAsync(state, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> SignConnectCodeAsync(string code, CancellationToken cancellationToken)
    {
        var seedPath = LocalPrivateKeyPath();
        var seed = await File.ReadAllBytesAsync(seedPath, cancellationToken).ConfigureAwait(false);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        var wireSignature = TnIdentity.Sign(seed, digest);
        return Convert.ToBase64String(DecodeUrlSafeBase64(wireSignature));
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

    private async Task<JsonObject> ReadStateJsonAsync(CancellationToken cancellationToken)
    {
        var path = StatePath();
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
            return await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false) as JsonObject
                ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private async Task WriteStateJsonAsync(JsonObject state, CancellationToken cancellationToken)
    {
        var path = StatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, state.ToJsonString(), cancellationToken).ConfigureAwait(false);
    }

    private string StatePath()
    {
        var yamlDirectory = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("tn.yaml path has no parent directory");
        return Path.Combine(yamlDirectory, ".tn", "sync", "state.json");
    }

    private static byte[] DecodeUrlSafeBase64(string value)
    {
        var standard = value.Replace('-', '+').Replace('_', '/');
        var padding = standard.Length % 4;
        if (padding != 0)
        {
            standard = standard.PadRight(standard.Length + 4 - padding, '=');
        }

        return Convert.FromBase64String(standard);
    }
}
