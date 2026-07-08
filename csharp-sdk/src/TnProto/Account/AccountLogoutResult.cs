namespace TnProto.Account;

/// <summary>
/// Result returned after clearing the local account binding.
/// </summary>
public sealed record AccountLogoutResult(
    bool WasBound,
    string? AccountId);
