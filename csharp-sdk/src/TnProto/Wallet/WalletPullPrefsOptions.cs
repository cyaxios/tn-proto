namespace TnProto.Wallet;

/// <summary>
/// Options for pulling account preferences from the vault.
/// </summary>
public sealed class WalletPullPrefsOptions
{
    /// <summary>
    /// Vault base URL. When omitted, the linked vault in <c>tn.yaml</c> is used.
    /// </summary>
    public string? VaultBaseUrl { get; init; }

    /// <summary>
    /// Optional bearer token for authenticated vault requests.
    /// </summary>
    public string? BearerToken { get; init; }

    /// <summary>
    /// Optional HTTP client for tests and custom transports.
    /// </summary>
    public HttpClient? HttpClient { get; init; }
}
