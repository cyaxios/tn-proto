namespace TnProto.Packages;

/// <summary>
/// Result from compiling and attesting an offer package.
/// </summary>
public sealed record OfferReceipt(
    string Path,
    string Group,
    string PeerDid,
    string PackageSha256,
    string Status);
