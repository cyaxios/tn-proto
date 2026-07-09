namespace TnProto.Wallet;

/// <summary>
/// Options for restoring an encrypted vault project body into a directory.
/// </summary>
public sealed class WalletRestoreOptions
{
    /// <summary>
    /// Vault base URL. When omitted, the linked vault in <c>tn.yaml</c> is used.
    /// </summary>
    public string? VaultBaseUrl { get; init; }

    /// <summary>
    /// Optional bearer token for authenticated vault requests.
    /// </summary>
    public string? BearerToken { get; init; }

    /// <summary>
    /// Vault project id. When omitted, the linked project id in <c>tn.yaml</c> is used.
    /// </summary>
    public string? ProjectId { get; init; }

    /// <summary>
    /// Passphrase used to unwrap the account key that protects the project body.
    /// </summary>
    public string? Passphrase { get; init; }

    /// <summary>
    /// Use the cached account wrapping key instead of prompting for a passphrase.
    /// </summary>
    public bool UseCachedAccountKey { get; init; }

    /// <summary>
    /// Vault account id for cached account-key restore. When omitted, the local account binding is used.
    /// </summary>
    public string? AccountId { get; init; }

    /// <summary>
    /// Optional credential id. When omitted, the vault chooses the primary credential.
    /// </summary>
    public string? CredentialId { get; init; }

    /// <summary>
    /// Directory that will receive restored <c>tn.yaml</c> and <c>keys/</c>.
    /// </summary>
    public string? TargetDirectory { get; init; }

    /// <summary>
    /// Allow different existing files to be overwritten.
    /// </summary>
    public bool Overwrite { get; init; }
}
