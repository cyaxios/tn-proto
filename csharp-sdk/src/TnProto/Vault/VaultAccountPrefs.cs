namespace TnProto.Vault;

/// <summary>
/// Account preferences returned by the vault.
/// </summary>
public sealed record VaultAccountPrefs(
    string DefaultNewCeremonyMode,
    ulong PrefsVersion);
