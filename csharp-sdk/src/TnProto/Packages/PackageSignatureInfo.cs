namespace TnProto.Packages;

/// <summary>
/// Manifest signature verification result for a package inspection.
/// </summary>
public sealed record PackageSignatureInfo(
    string Status,
    bool Verified,
    string? Reason);
