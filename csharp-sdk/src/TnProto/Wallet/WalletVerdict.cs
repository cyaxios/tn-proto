namespace TnProto.Wallet;

/// <summary>
/// High-level local wallet readiness state.
/// </summary>
public enum WalletVerdict
{
    /// <summary>The project has no account binding, vault link, or pending claim.</summary>
    LocalOnly,

    /// <summary>A claim URL has been issued and is waiting for browser-side claim.</summary>
    PendingClaim,

    /// <summary>The local device is account-bound but the project is not linked to a vault project.</summary>
    AccountBound,

    /// <summary>The project is linked to a vault project.</summary>
    Linked,

    /// <summary>The project has inconsistent local wallet state.</summary>
    NeedsRepair,
}

internal static class WalletVerdictExtensions
{
    internal static string ToTnName(this WalletVerdict verdict)
    {
        return verdict switch
        {
            WalletVerdict.LocalOnly => "local_only",
            WalletVerdict.PendingClaim => "pending_claim",
            WalletVerdict.AccountBound => "account_bound",
            WalletVerdict.Linked => "linked",
            WalletVerdict.NeedsRepair => "needs_repair",
            _ => throw new ArgumentOutOfRangeException(nameof(verdict), verdict, null),
        };
    }
}
