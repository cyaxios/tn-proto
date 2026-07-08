namespace TnProto.Wallet;

/// <summary>
/// Options for publishing local group-key snapshots to the vault account inbox.
/// </summary>
public sealed class WalletPublishGroupKeysOptions
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
    /// Optional group subset. If omitted, all publishable group keys are exported.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; set; }

    /// <summary>
    /// Optional vault inbox timestamp override for deterministic tests.
    /// </summary>
    public string? Timestamp { get; set; }
}
