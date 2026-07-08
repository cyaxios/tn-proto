namespace TnProto.Vault;

/// <summary>
/// Options for creating or discovering a vault project and linking local YAML.
/// </summary>
public sealed class VaultConnectOptions
{
    /// <summary>
    /// Vault base URL, for example <c>https://vault.tn-proto.org</c>.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Optional bearer token for authenticated vault project routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Optional HTTP client used for tests or custom transport configuration.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>
    /// Friendly vault project name. Defaults to the local project name.
    /// </summary>
    public string? ProjectName { get; set; }

    /// <summary>
    /// Run DID challenge authentication automatically when no bearer token is supplied.
    /// </summary>
    public bool AutoAuthenticate { get; set; } = true;
}
