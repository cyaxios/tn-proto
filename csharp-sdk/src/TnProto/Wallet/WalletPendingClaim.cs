namespace TnProto.Wallet;

/// <summary>
/// Pending vault claim recorded in local sync state.
/// </summary>
public sealed record WalletPendingClaim(
    string VaultId,
    string ExpiresAt,
    string ClaimUrl,
    bool Expired);
