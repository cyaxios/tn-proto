namespace TnProto.Vault;

/// <summary>
/// Result returned after mutating local vault link-state.
/// </summary>
public sealed record VaultLinkStateResult(
    VaultLinkState State,
    string YamlPath,
    string? LinkedVault,
    string? LinkedProjectId)
{
    /// <summary>
    /// Stable string form for CLI and parity checks.
    /// </summary>
    public string StateName => State.ToTnName();
}
