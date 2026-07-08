namespace TnProto.Wallet;

/// <summary>
/// Options for pulling vault account inbox packages and applying them locally.
/// </summary>
public sealed class WalletPullOptions
{
    /// <summary>
    /// Vault base URL. If omitted, the linked vault from tn.yaml is used.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Bearer token for authenticated vault account inbox routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Optional HTTP client for tests or custom hosting.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>
    /// Also absorb packages that were already staged in the local inbox before this pull.
    /// </summary>
    public bool AbsorbExisting { get; set; } = true;
}
