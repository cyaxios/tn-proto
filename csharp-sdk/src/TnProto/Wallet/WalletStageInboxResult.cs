namespace TnProto.Wallet;

/// <summary>
/// Summary from staging vault account inbox packages.
/// </summary>
public sealed record WalletStageInboxResult(
    IReadOnlyList<string> StagedPaths,
    int Skipped,
    bool NotBound,
    bool Unauthorized);
