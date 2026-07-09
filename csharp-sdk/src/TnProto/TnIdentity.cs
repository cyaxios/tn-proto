using System.Text.Json;
using System.Text.Json.Nodes;
using TnProto.Native;

namespace TnProto;

/// <summary>
/// Helpers for creating and restoring TN device identities.
/// </summary>
public static class TnIdentity
{
    private const int IdentitySchemaVersion = 1;

    /// <summary>
    /// Return the machine-global TN identity directory used by Python,
    /// TypeScript, and Rust.
    /// </summary>
    public static string DefaultIdentityDirectory()
    {
        var overrideDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        if (!string.IsNullOrWhiteSpace(overrideDir))
        {
            return Path.GetFullPath(overrideDir);
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        if (!string.IsNullOrWhiteSpace(xdg))
        {
            return Path.GetFullPath(Path.Combine(xdg, "tn"));
        }

        if (OperatingSystem.IsWindows())
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            var baseDir = string.IsNullOrWhiteSpace(appData)
                ? Path.Combine(HomeDirectory(), "AppData", "Roaming")
                : appData;
            return Path.GetFullPath(Path.Combine(baseDir, "tn"));
        }

        return Path.GetFullPath(Path.Combine(HomeDirectory(), ".local", "share", "tn"));
    }

    /// <summary>
    /// Return the machine-global <c>identity.json</c> path used by Python,
    /// TypeScript, and Rust.
    /// </summary>
    public static string DefaultIdentityPath()
    {
        return Path.Combine(DefaultIdentityDirectory(), "identity.json");
    }

    /// <summary>
    /// Load an existing raw 32-byte identity seed from disk, or create one if missing.
    /// </summary>
    public static async Task<IdentityLoadResult> LoadOrCreateAsync(
        string seedPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(seedPath))
        {
            throw new ArgumentException("Seed path must not be empty.", nameof(seedPath));
        }

        var fullPath = Path.GetFullPath(seedPath);
        if (File.Exists(fullPath))
        {
            return new IdentityLoadResult(
                await LoadAsync(fullPath, cancellationToken).ConfigureAwait(false),
                fullPath,
                Created: false);
        }

        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var identity = Generate();
        try
        {
            await using var stream = new FileStream(
                fullPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous);
            await stream.WriteAsync(identity.Seed, cancellationToken).ConfigureAwait(false);
            return new IdentityLoadResult(identity, fullPath, Created: true);
        }
        catch (IOException) when (File.Exists(fullPath))
        {
            return new IdentityLoadResult(
                await LoadAsync(fullPath, cancellationToken).ConfigureAwait(false),
                fullPath,
                Created: false);
        }
    }

    /// <summary>
    /// Load a raw 32-byte identity seed from disk.
    /// </summary>
    public static async Task<DeviceIdentity> LoadAsync(
        string seedPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(seedPath))
        {
            throw new ArgumentException("Seed path must not be empty.", nameof(seedPath));
        }

        var fullPath = Path.GetFullPath(seedPath);
        var seed = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
        return FromSeed(seed);
    }

    /// <summary>
    /// Generate a fresh Ed25519 TN device identity.
    /// </summary>
    public static DeviceIdentity Generate()
    {
        return ParseIdentity(NativeBridge.IdentityGenerate());
    }

    /// <summary>
    /// Restore a deterministic Ed25519 TN device identity from a 32-byte seed.
    /// </summary>
    public static DeviceIdentity FromSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != 32)
        {
            throw new ArgumentException("TN Ed25519 identity seeds must be exactly 32 bytes.", nameof(seed));
        }

        return FromSeedBase64(Convert.ToBase64String(seed));
    }

    /// <summary>
    /// Restore a deterministic Ed25519 TN device identity from a base64-encoded 32-byte seed.
    /// </summary>
    public static DeviceIdentity FromSeedBase64(string seedBase64)
    {
        if (string.IsNullOrWhiteSpace(seedBase64))
        {
            throw new ArgumentException("Seed base64 must not be empty.", nameof(seedBase64));
        }

        var seed = Convert.FromBase64String(seedBase64);
        if (seed.Length != 32)
        {
            throw new ArgumentException(
                "TN Ed25519 identity seeds must decode to exactly 32 bytes.",
                nameof(seedBase64));
        }

        return ParseIdentity(NativeBridge.IdentityFromSeedBase64(seedBase64));
    }

    /// <summary>
    /// Restore a deterministic TN machine identity from BIP-39 mnemonic words.
    /// </summary>
    public static MnemonicIdentityResult FromMnemonic(string words, string? passphrase = null)
    {
        if (string.IsNullOrWhiteSpace(words))
        {
            throw new ArgumentException("Mnemonic words must not be empty.", nameof(words));
        }

        var resultJson = NativeBridge.IdentityFromMnemonic(words, passphrase);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native mnemonic identity returned non-object JSON");

        return new MnemonicIdentityResult(
            ParseIdentity(resultJson),
            result["identity_seed_b64url"]?.GetValue<string>()
                ?? throw new TnException("native mnemonic identity omitted identity_seed_b64url"),
            result["mnemonic"]?.GetValue<string>()
                ?? throw new TnException("native mnemonic identity omitted mnemonic"));
    }

    /// <summary>
    /// Sign message bytes with a 32-byte Ed25519 seed.
    /// </summary>
    /// <returns>URL-safe base64 signature without padding.</returns>
    public static string Sign(byte[] seed, byte[] message)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(message);
        if (seed.Length != 32)
        {
            throw new ArgumentException("TN Ed25519 identity seeds must be exactly 32 bytes.", nameof(seed));
        }

        return NativeBridge.IdentitySignBase64(
            Convert.ToBase64String(seed),
            Convert.ToBase64String(message));
    }

    /// <summary>
    /// Sign message bytes with a base64-encoded 32-byte Ed25519 seed.
    /// </summary>
    /// <returns>URL-safe base64 signature without padding.</returns>
    public static string SignBase64(string seedBase64, byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var identity = FromSeedBase64(seedBase64);
        return Sign(identity.Seed, message);
    }

    /// <summary>
    /// Verify a TN wire signature against a <c>did:key</c> and message bytes.
    /// </summary>
    public static bool VerifyDid(string did, byte[] message, string signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            throw new ArgumentException("DID must not be empty.", nameof(did));
        }

        ArgumentNullException.ThrowIfNull(message);
        if (string.IsNullOrWhiteSpace(signatureBase64))
        {
            throw new ArgumentException("Signature base64 must not be empty.", nameof(signatureBase64));
        }

        var resultJson = NativeBridge.IdentityVerifyDidBase64(
            did,
            Convert.ToBase64String(message),
            signatureBase64);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native identity verify returned non-object JSON");

        return result["valid"]?.GetValue<bool>()
            ?? throw new TnException("native identity verify result omitted valid flag");
    }

    /// <summary>
    /// Save a Python/TypeScript-compatible unencrypted <c>identity.json</c>.
    /// </summary>
    public static async Task<string> SaveJsonAsync(
        DeviceIdentity identity,
        string path,
        IdentityJsonOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(identity);
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Identity JSON path must not be empty.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var seedBase64Url = options?.SeedBase64Url ?? ToBase64UrlNoPadding(identity.Seed);
        if (DecodeBase64Url(seedBase64Url).Length is not (32 or 64))
        {
            throw new ArgumentException(
                "SeedBase64Url must decode to either a 32-byte device seed or 64-byte BIP-39 seed.",
                nameof(options));
        }

        var doc = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["device_priv_b64_enc"] = ToBase64UrlNoPadding(identity.Seed),
            ["device_priv_enc_method"] = "none",
            ["device_pub_b64"] = ToBase64UrlNoPadding(identity.PublicKey),
            ["did"] = identity.Did,
            ["linked_account_id"] = options?.LinkedAccountId,
            ["linked_vault"] = options?.LinkedVault,
            ["mnemonic_stored"] = options?.MnemonicStored,
            ["prefs"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["backup"] = new SortedDictionary<string, object?>(StringComparer.Ordinal),
                ["share"] = new SortedDictionary<string, object?>(StringComparer.Ordinal),
            },
            ["prefs_version"] = 0,
            ["seed_b64"] = seedBase64Url,
            ["version"] = IdentitySchemaVersion,
        };

        var json = JsonSerializer.Serialize(
            doc,
            new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(fullPath, json + Environment.NewLine, cancellationToken).ConfigureAwait(false);
        return fullPath;
    }

    /// <summary>
    /// Load a Python/TypeScript-compatible unencrypted <c>identity.json</c>.
    /// </summary>
    public static async Task<IdentityJsonLoadResult> LoadJsonAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Identity JSON path must not be empty.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        var raw = await File.ReadAllTextAsync(fullPath, cancellationToken).ConfigureAwait(false);
        var doc = JsonNode.Parse(raw) as JsonObject
            ?? throw new TnException($"identity.json at {fullPath} must contain a JSON object");

        var version = RequiredInt(doc, "version", "identity.json omitted version");
        if (version != IdentitySchemaVersion)
        {
            throw new TnException($"identity schema version {version} != {IdentitySchemaVersion}");
        }

        var encMethod = OptionalString(doc, "device_priv_enc_method") ?? "none";
        if (!string.Equals(encMethod, "none", StringComparison.Ordinal))
        {
            throw new TnException(
                $"identity.json device key is stored with encryption {JsonSerializer.Serialize(encMethod)}; C# cannot unwrap it");
        }

        var seedBytes = DecodeBase64Url(RequiredString(
            doc,
            "device_priv_b64_enc",
            "identity.json omitted device_priv_b64_enc"));
        if (seedBytes.Length != 32)
        {
            throw new TnException($"identity.json device seed must be 32 bytes; got {seedBytes.Length}");
        }

        var identity = FromSeed(seedBytes);
        var did = RequiredString(doc, "did", "identity.json omitted did");
        if (!string.Equals(did, identity.Did, StringComparison.Ordinal))
        {
            throw new TnException("identity.json did does not match the device private key");
        }

        var publicKeyBytes = DecodeBase64Url(RequiredString(
            doc,
            "device_pub_b64",
            "identity.json omitted device_pub_b64"));
        if (!publicKeyBytes.SequenceEqual(identity.PublicKey))
        {
            throw new TnException("identity.json device_pub_b64 does not match the device private key");
        }

        return new IdentityJsonLoadResult(
            identity,
            fullPath,
            version,
            encMethod,
            OptionalString(doc, "seed_b64"),
            OptionalString(doc, "mnemonic_stored"),
            OptionalString(doc, "linked_vault"),
            OptionalString(doc, "linked_account_id"));
    }

    /// <summary>
    /// Return the mnemonic persisted in <c>identity.json</c>, when the user
    /// explicitly opted into storing it.
    /// </summary>
    public static async Task<string> ExportMnemonicAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var loaded = await LoadJsonAsync(path, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(loaded.MnemonicStored))
        {
            throw new TnException(
                "no mnemonic stored in identity.json; create or restore an identity with mnemonic persistence enabled");
        }

        return loaded.MnemonicStored;
    }

    private static DeviceIdentity ParseIdentity(string identityJson)
    {
        var identity = JsonNode.Parse(identityJson) as JsonObject
            ?? throw new TnException("native identity returned non-object JSON");

        return new DeviceIdentity(
            identity["seed_b64"]?.GetValue<string>()
                ?? throw new TnException("native identity omitted seed_b64"),
            identity["public_key_b64"]?.GetValue<string>()
                ?? throw new TnException("native identity omitted public_key_b64"),
            identity["did"]?.GetValue<string>()
                ?? throw new TnException("native identity omitted did"));
    }

    private static string RequiredString(JsonObject obj, string key, string message)
    {
        return OptionalString(obj, key) ?? throw new TnException(message);
    }

    private static string? OptionalString(JsonObject obj, string key)
    {
        return obj[key]?.GetValue<string>();
    }

    private static int RequiredInt(JsonObject obj, string key, string message)
    {
        return obj[key]?.GetValue<int>() ?? throw new TnException(message);
    }

    private static string ToBase64UrlNoPadding(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static byte[] DecodeBase64Url(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new TnException("base64url value must not be empty");
        }

        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '=');
        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException ex)
        {
            throw new TnException("invalid base64url value", ex);
        }
    }

    private static string HomeDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (!string.IsNullOrWhiteSpace(userProfile))
            {
                return userProfile;
            }

            var drive = Environment.GetEnvironmentVariable("HOMEDRIVE");
            var path = Environment.GetEnvironmentVariable("HOMEPATH");
            if (!string.IsNullOrWhiteSpace(drive) && !string.IsNullOrWhiteSpace(path))
            {
                return drive + path;
            }
        }

        var home = Environment.GetEnvironmentVariable("HOME");
        return string.IsNullOrWhiteSpace(home) ? "." : home;
    }
}
