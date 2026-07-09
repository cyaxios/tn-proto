namespace TnProto.Wallet;

/// <summary>
/// Options for composing the wallet sync flow.
/// </summary>
public sealed class WalletSyncOptions
{
    /// <summary>
    /// Stage and absorb account inbox packages, then stop.
    /// </summary>
    public bool PullOnly { get; set; }

    /// <summary>
    /// Skip pull/absorb and group-key publishing.
    /// </summary>
    public bool PushOnly { get; set; }

    /// <summary>
    /// Publish local group-key snapshots after pull/absorb.
    /// </summary>
    public bool PublishGroupKeys { get; set; } = true;

    /// <summary>
    /// Push the encrypted project body. Requires <see cref="Passphrase" />.
    /// </summary>
    public bool PushBody { get; set; }

    /// <summary>
    /// Vault base URL. If omitted, the linked vault from tn.yaml is used.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Bearer token for authenticated vault routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Optional HTTP client for C#-owned pull and group-key publish routes.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>
    /// Optional group subset for group-key publishing.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; set; }

    /// <summary>
    /// Optional vault inbox timestamp override for deterministic group-key publish tests.
    /// </summary>
    public string? Timestamp { get; set; }

    /// <summary>
    /// Vault project id for encrypted body push. If omitted, linked project id is used.
    /// </summary>
    public string? ProjectId { get; set; }

    /// <summary>
    /// Account passphrase for encrypted body push.
    /// </summary>
    public string? Passphrase { get; set; }

    /// <summary>
    /// Optional credential id for encrypted body push.
    /// </summary>
    public string? CredentialId { get; set; }
}
