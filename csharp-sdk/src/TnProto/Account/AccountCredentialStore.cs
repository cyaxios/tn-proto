using System.Text.Json;

namespace TnProto.Account;

/// <summary>
/// File-backed store for account-scoped cached credential material.
/// </summary>
public sealed class AccountCredentialStore
{
    private readonly string _path;

    /// <summary>
    /// Create a file-backed credential store at <paramref name="path"/>.
    /// </summary>
    public AccountCredentialStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Credential store path must not be empty.", nameof(path));
        }

        _path = System.IO.Path.GetFullPath(path);
    }

    /// <summary>
    /// Full path to the backing <c>credentials.json</c> file.
    /// </summary>
    public string Path => _path;

    /// <summary>
    /// Return the default credential store beside the machine-global identity.
    /// </summary>
    public static AccountCredentialStore Default()
    {
        return new AccountCredentialStore(System.IO.Path.Combine(
            TnIdentity.DefaultIdentityDirectory(),
            "credentials.json"));
    }

    /// <summary>
    /// Stable store key for an account wrapping key.
    /// </summary>
    public static string AwkKeyName(string accountId)
    {
        if (string.IsNullOrWhiteSpace(accountId))
        {
            throw new ArgumentException("Account id must not be empty.", nameof(accountId));
        }

        return $"awk:{accountId}";
    }

    /// <summary>
    /// Store a 32-byte account wrapping key for an account id.
    /// </summary>
    public async Task SetAccountAwkAsync(
        string accountId,
        byte[] awk,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(awk);
        if (awk.Length != 32)
        {
            throw new ArgumentException("Account wrapping keys must be exactly 32 bytes.", nameof(awk));
        }

        await SetAsync(AwkKeyName(accountId), awk, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Return a cached 32-byte account wrapping key, or <c>null</c> when absent or malformed.
    /// </summary>
    public async Task<byte[]?> GetAccountAwkAsync(
        string accountId,
        CancellationToken cancellationToken = default)
    {
        var value = await GetAsync(AwkKeyName(accountId), cancellationToken).ConfigureAwait(false);
        return value is { Length: 32 } ? value : null;
    }

    /// <summary>
    /// Delete the cached account wrapping key for an account id.
    /// </summary>
    public Task DeleteAccountAwkAsync(string accountId, CancellationToken cancellationToken = default)
    {
        return DeleteAsync(AwkKeyName(accountId), cancellationToken);
    }

    /// <summary>
    /// Read a named credential, returning <c>null</c> when missing or malformed.
    /// </summary>
    public async Task<byte[]?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        var doc = await LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!doc.TryGetValue(name, out var encoded))
        {
            return null;
        }

        try
        {
            return Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Store a named credential as standard base64 in <c>credentials.json</c>.
    /// </summary>
    public async Task SetAsync(string name, byte[] value, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Credential name must not be empty.", nameof(name));
        }

        ArgumentNullException.ThrowIfNull(value);
        var doc = await LoadAsync(cancellationToken).ConfigureAwait(false);
        doc[name] = Convert.ToBase64String(value);
        await SaveAsync(doc, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Delete a named credential. Missing entries are ignored.
    /// </summary>
    public async Task DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        var doc = await LoadAsync(cancellationToken).ConfigureAwait(false);
        if (doc.Remove(name))
        {
            await SaveAsync(doc, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<SortedDictionary<string, string>> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new SortedDictionary<string, string>(StringComparer.Ordinal);
        }

        try
        {
            await using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                bufferSize: 4096,
                FileOptions.Asynchronous);
            var doc = await JsonSerializer.DeserializeAsync<SortedDictionary<string, string>>(
                stream,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return doc ?? new SortedDictionary<string, string>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            return new SortedDictionary<string, string>(StringComparer.Ordinal);
        }
    }

    private async Task SaveAsync(
        SortedDictionary<string, string> doc,
        CancellationToken cancellationToken)
    {
        var directory = System.IO.Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tmp = _path + "." + Environment.ProcessId + ".tmp";
        var json = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(tmp, json + Environment.NewLine, cancellationToken).ConfigureAwait(false);
        if (File.Exists(_path))
        {
            File.Delete(_path);
        }

        File.Move(tmp, _path);
    }
}
