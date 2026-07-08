namespace TnProto.Vault;

/// <summary>
/// Options for the unauthenticated pending-claim onboarding upload.
/// </summary>
public sealed class VaultInitUploadOptions
{
    /// <summary>
    /// Vault base URL, for example <c>https://vault.tn-proto.org</c>.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Optional HTTP client used for tests or custom transport configuration.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>
    /// Optional group subset to include in the encrypted full-keystore package.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; set; }

    /// <summary>
    /// Friendly project name sent to the vault. Defaults to the local project name.
    /// </summary>
    public string? ProjectName { get; set; }

    /// <summary>
    /// Reuse an existing non-expired pending claim recorded in local sync state.
    /// </summary>
    public bool ReusePendingClaim { get; set; } = true;
}
