namespace TnProto.Vault;

/// <summary>
/// Options for pushing an encrypted project body using a passphrase-derived account wrap key.
/// </summary>
public sealed class VaultPushBodyWithPassphraseOptions
{
    /// <summary>
    /// Vault base URL. If omitted, the linked vault from tn.yaml is used.
    /// </summary>
    public string? VaultBaseUrl { get; set; }

    /// <summary>
    /// Bearer token for authenticated vault routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Vault project id. If omitted, the linked project id from tn.yaml is used.
    /// </summary>
    public string? ProjectId { get; set; }

    /// <summary>
    /// Account passphrase used to derive the account wrap key.
    /// </summary>
    public string? Passphrase { get; set; }

    /// <summary>
    /// Optional credential id when the account has multiple credential rows.
    /// </summary>
    public string? CredentialId { get; set; }
}
