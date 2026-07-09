namespace TnProto.Packages;

/// <summary>
/// Result from compiling a handoff package.
/// </summary>
public sealed record CompiledPackageResult(
    string Path,
    string RecipientDid,
    IReadOnlyList<string> Groups,
    string ManifestSha256,
    string PackageSha256);
