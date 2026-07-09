namespace TnProto;

/// <summary>
/// Parsed cold-start API-key bootstrap material.
/// </summary>
/// <remarks>
/// TN API keys have the form <c>tn_apikey_&lt;seed&gt;_&lt;key_id&gt;</c>. They are
/// not account bearer tokens. The seed authenticates with the vault using DID
/// challenge auth, and the key id selects a recipient-sealed bootstrap bundle.
/// </remarks>
public sealed record TnApiKey(
    string Raw,
    byte[] Seed,
    string KeyId,
    byte[] KeyIdBytes,
    DeviceIdentity Identity)
{
    private const string Prefix = "tn_apikey_";
    private const int SeedBase64UrlLength = 43;
    private const int KeyIdBase64UrlLength = 22;
    private const int SeedLength = 32;
    private const int KeyIdLength = 16;

    /// <summary>
    /// DID derived from the API-key seed.
    /// </summary>
    public string Did => Identity.Did;

    /// <summary>
    /// Parse a cold-start API key, throwing when the key shape is invalid.
    /// </summary>
    public static TnApiKey Parse(string apiKey)
    {
        if (TryParse(apiKey, out var parsed))
        {
            return parsed;
        }

        throw new FormatException(
            "TN API keys must have the form tn_apikey_<43-char seed>_<22-char key id>.");
    }

    /// <summary>
    /// Try to parse a cold-start API key without throwing.
    /// </summary>
    public static bool TryParse(string? apiKey, out TnApiKey parsed)
    {
        parsed = null!;

        if (string.IsNullOrWhiteSpace(apiKey) || !apiKey.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var rest = apiKey[Prefix.Length..];
        var expectedLength = SeedBase64UrlLength + 1 + KeyIdBase64UrlLength;
        if (rest.Length != expectedLength || rest[SeedBase64UrlLength] != '_')
        {
            return false;
        }

        var seedBase64Url = rest[..SeedBase64UrlLength];
        var keyId = rest[(SeedBase64UrlLength + 1)..];

        if (!TryDecodeBase64Url(seedBase64Url, out var seed) || seed.Length != SeedLength)
        {
            return false;
        }

        if (!TryDecodeBase64Url(keyId, out var keyIdBytes) || keyIdBytes.Length != KeyIdLength)
        {
            return false;
        }

        parsed = new TnApiKey(
            apiKey,
            seed,
            keyId,
            keyIdBytes,
            TnIdentity.FromSeed(seed));
        return true;
    }

    private static bool TryDecodeBase64Url(string value, out byte[] bytes)
    {
        bytes = [];
        if (value.Length == 0)
        {
            return false;
        }

        var padded = value.Replace('-', '+').Replace('_', '/');
        var padding = padded.Length % 4;
        padded = padding switch
        {
            0 => padded,
            2 => padded + "==",
            3 => padded + "=",
            _ => string.Empty,
        };

        if (padded.Length == 0)
        {
            return false;
        }

        try
        {
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
