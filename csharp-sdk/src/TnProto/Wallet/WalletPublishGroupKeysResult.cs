using TnProto.Vault;

namespace TnProto.Wallet;

/// <summary>
/// Result from publishing local group-key material to the vault account inbox.
/// </summary>
public sealed record WalletPublishGroupKeysResult(
    string? PackagePath,
    VaultInboxSnapshot? Snapshot,
    IReadOnlyList<string> RequestedGroups)
{
    /// <summary>
    /// True when there was publishable group-key material.
    /// </summary>
    public bool Published => Snapshot is not null;
}
