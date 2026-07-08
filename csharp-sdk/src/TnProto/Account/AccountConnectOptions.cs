namespace TnProto.Account;

/// <summary>
/// Options for redeeming a vault account connect code.
/// </summary>
public sealed class AccountConnectOptions
{
    /// <summary>
    /// Vault base URL, for example <c>https://vault.tn-proto.org</c>.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Optional HTTP client used for tests or custom transport configuration.
    /// </summary>
    public HttpClient? HttpClient { get; set; }
}
