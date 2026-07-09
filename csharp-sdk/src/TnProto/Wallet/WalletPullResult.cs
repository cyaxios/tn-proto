using TnProto.Packages;

namespace TnProto.Wallet;

/// <summary>
/// Result from pulling vault account inbox packages and absorbing local package files.
/// </summary>
public sealed record WalletPullResult(
    WalletStageInboxResult Stage,
    IReadOnlyList<PackageAbsorbReceipt> AbsorbReceipts,
    IReadOnlyList<string> RejectedPaths)
{
    /// <summary>
    /// Number of package files considered for absorb.
    /// </summary>
    public int AbsorbedPackageCount => AbsorbReceipts.Count;

    /// <summary>
    /// Total new entries/material accepted by package absorb.
    /// </summary>
    public ulong AcceptedCount => AbsorbReceipts.Aggregate(0UL, (sum, receipt) => sum + receipt.AcceptedCount);

    /// <summary>
    /// Total deduped entries/material reported by package absorb.
    /// </summary>
    public ulong DedupedCount => AbsorbReceipts.Aggregate(0UL, (sum, receipt) => sum + receipt.DedupedCount);

    /// <summary>
    /// Total conflicts reported by package absorb.
    /// </summary>
    public ulong ConflictCount => AbsorbReceipts.Aggregate(0UL, (sum, receipt) => sum + receipt.ConflictCount);

    /// <summary>
    /// Number of package files rejected by package absorb.
    /// </summary>
    public int RejectedCount => AbsorbReceipts.Count(receipt => receipt.Rejected) + RejectedPaths.Count;
}
