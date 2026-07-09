namespace TnProto.Account;

/// <summary>
/// Local account binding health for a TN project.
/// </summary>
public enum AccountVerdict
{
    /// <summary>The project is not bound to a vault account.</summary>
    NotLoggedIn,

    /// <summary>The project is account-bound, but no local account key material is cached.</summary>
    LinkedNoKey,

    /// <summary>The project is account-bound and has local credential material available.</summary>
    BackedUp,
}

internal static class AccountVerdictExtensions
{
    internal static string ToTnName(this AccountVerdict verdict)
    {
        return verdict switch
        {
            AccountVerdict.NotLoggedIn => "not_logged_in",
            AccountVerdict.LinkedNoKey => "linked_no_key",
            AccountVerdict.BackedUp => "backed_up",
            _ => throw new ArgumentOutOfRangeException(nameof(verdict), verdict, null),
        };
    }
}
