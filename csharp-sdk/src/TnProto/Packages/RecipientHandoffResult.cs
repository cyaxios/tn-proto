namespace TnProto.Packages;

/// <summary>
/// Result from exporting a recipient handoff package pair.
/// </summary>
public sealed record RecipientHandoffResult(
    string AdminSnapshotPath,
    string ReaderBundlePath,
    string RecipientDid,
    IReadOnlyList<string> Groups,
    PackageInfo AdminSnapshot,
    PackageInfo ReaderBundle);
