namespace TnProto.Wallet;

/// <summary>
/// Result from pulling account preferences from the vault.
/// </summary>
public sealed record WalletPullPrefsResult(
    string VaultBaseUrl,
    string DefaultNewCeremonyMode,
    ulong PrefsVersion,
    string StatePath);
