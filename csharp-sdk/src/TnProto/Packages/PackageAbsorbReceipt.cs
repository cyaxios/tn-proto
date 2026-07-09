namespace TnProto.Packages;

/// <summary>
/// Result from absorbing a TN package.
/// </summary>
public sealed record PackageAbsorbReceipt(
    string Kind,
    string Status,
    ulong AcceptedCount,
    ulong DedupedCount,
    bool NoOp,
    ulong ConflictCount,
    string LegacyStatus,
    string LegacyReason,
    IReadOnlyList<string> ReplacedKitPaths)
{
    /// <summary>
    /// True when the package applied new material.
    /// </summary>
    public bool Accepted => string.Equals(Status, "accepted", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the package was valid but did not change local state.
    /// </summary>
    public bool IsNoOp => string.Equals(Status, "noop", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the package was rejected.
    /// </summary>
    public bool Rejected => string.Equals(Status, "rejected", StringComparison.OrdinalIgnoreCase);
}
