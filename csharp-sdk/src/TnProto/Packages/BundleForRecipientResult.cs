namespace TnProto.Packages;

/// <summary>
/// Result from minting and exporting a recipient kit bundle.
/// </summary>
public sealed record BundleForRecipientResult(
    string Path,
    string RecipientDid,
    IReadOnlyList<string> Groups);
