namespace TnProto.Vault;

/// <summary>
/// Options for mutating local vault link-state in <c>tn.yaml</c>.
/// </summary>
public sealed class SetVaultLinkStateOptions
{
    /// <summary>
    /// Vault URL to store when linking.
    /// </summary>
    public string? LinkedVault { get; set; }

    /// <summary>
    /// Vault-side project id to store when linking.
    /// </summary>
    public string? LinkedProjectId { get; set; }
}
