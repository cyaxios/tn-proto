namespace TnProto.Account;

/// <summary>
/// Local account and vault status for a TN project.
/// </summary>
public sealed record AccountStatus(
    string DeviceDid,
    string? AccountId,
    bool AccountBound,
    string? Vault,
    bool KeyCached,
    AccountVerdict Verdict)
{
    /// <summary>
    /// Stable string form used by CLI and parity checks.
    /// </summary>
    public string VerdictName => Verdict.ToTnName();
}
