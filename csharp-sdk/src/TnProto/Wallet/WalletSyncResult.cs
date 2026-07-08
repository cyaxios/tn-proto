using TnProto.Vault;

namespace TnProto.Wallet;

/// <summary>
/// Result from a composed wallet sync pass.
/// </summary>
public sealed record WalletSyncResult(
    WalletPullResult? Pull,
    WalletPublishGroupKeysResult? GroupKeys,
    VaultPushBodyResult? BodyPush)
{
    /// <summary>
    /// True when encrypted body push ran.
    /// </summary>
    public bool Pushed => BodyPush is not null;
}
