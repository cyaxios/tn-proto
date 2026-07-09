namespace TnProto.Wallet;

/// <summary>
/// Options for staging authenticated account inbox packages.
/// </summary>
public sealed class WalletStageInboxOptions
{
    /// <summary>
    /// Vault base URL. Defaults to the linked vault recorded in <c>tn.yaml</c>.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Optional bearer token for authenticated vault account inbox routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Optional HTTP client used for tests or custom transport configuration.
    /// </summary>
    public HttpClient? HttpClient { get; set; }
}
