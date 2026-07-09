namespace TnProto;

/// <summary>
/// Options for API-key cold-start bootstrap.
/// </summary>
public sealed class TnApiKeyBootstrapOptions
{
    /// <summary>
    /// Raw <c>tn_apikey_...</c> value. When omitted, callers may choose to read
    /// <c>TN_API_KEY</c> before invoking the bootstrap helper.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Vault base URL, for example <c>https://vault.tn-proto.org</c>.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Project name to create/open before installing the project seed.
    /// </summary>
    public string ProjectName { get; set; } = "bootstrap";

    /// <summary>
    /// Directory that owns the project's <c>.tn</c> folder.
    /// Defaults to the current working directory.
    /// </summary>
    public string? ProjectDirectory { get; set; }

    /// <summary>
    /// Evidence profile to use for the temporary seed-backed project skeleton.
    /// </summary>
    public TnProfile Profile { get; set; } = TnProfile.Transaction;

    /// <summary>
    /// Optional HTTP client used for tests or custom transport configuration.
    /// </summary>
    public HttpClient? HttpClient { get; set; }
}
