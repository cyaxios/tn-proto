using TnProto.Account;
using TnProto.Vault;

namespace TnProto.Wallet;

/// <summary>
/// Project-local wallet status composed from account state, vault link-state, and sync state.
/// </summary>
public sealed record WalletStatus(
    string DeviceDid,
    string YamlPath,
    AccountStatus Account,
    VaultLinkStateInfo Vault,
    WalletPendingClaim? PendingClaim,
    IReadOnlyList<string> Warnings,
    WalletVerdict Verdict)
{
    /// <summary>
    /// Stable string form for CLI and parity checks.
    /// </summary>
    public string VerdictName => Verdict.ToTnName();
}
