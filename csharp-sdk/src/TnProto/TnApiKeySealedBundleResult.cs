namespace TnProto;

/// <summary>
/// Sealed bootstrap bundle fetched from the vault using a cold-start API key.
/// </summary>
public sealed record TnApiKeySealedBundleResult(
    TnApiKey ApiKey,
    string VaultBaseUrl,
    string Token,
    byte[] SealedBytes,
    string? Kind);
