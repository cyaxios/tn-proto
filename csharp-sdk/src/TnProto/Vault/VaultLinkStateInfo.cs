namespace TnProto.Vault;

/// <summary>
/// Local vault link-state read from <c>tn.yaml</c>.
/// </summary>
public sealed record VaultLinkStateInfo(
    VaultLinkState State,
    string YamlPath,
    string? LinkedVault,
    string? LinkedProjectId,
    bool VaultEnabled,
    bool Autosync,
    int? SyncIntervalSeconds)
{
    /// <summary>
    /// Stable string form for CLI and parity checks.
    /// </summary>
    public string StateName => State.ToTnName();
}
