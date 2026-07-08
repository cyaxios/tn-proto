namespace TnProto.Account;

/// <summary>
/// Persisted local account binding state for a TN project.
/// </summary>
public sealed record AccountState(
    string? AccountId,
    bool AccountBound);
