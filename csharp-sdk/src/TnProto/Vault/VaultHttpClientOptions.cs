namespace TnProto.Vault;

/// <summary>
/// Options for the vault HTTP project client.
/// </summary>
public sealed class VaultHttpClientOptions
{
    /// <summary>
    /// Vault base URL, for example <c>https://vault.tn-proto.org</c>.
    /// </summary>
    public string? BaseUrl { get; set; }

    /// <summary>
    /// Optional bearer token for authenticated vault routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Optional HTTP client used for tests or custom transport configuration.
    /// </summary>
    public HttpClient? HttpClient { get; set; }
}
