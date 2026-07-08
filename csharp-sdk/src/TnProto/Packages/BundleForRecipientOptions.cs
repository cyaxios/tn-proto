namespace TnProto.Packages;

/// <summary>
/// Options for minting and exporting a recipient kit bundle.
/// </summary>
public sealed class BundleForRecipientOptions
{
    /// <summary>
    /// Optional group subset. Defaults to all non-internal groups.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; init; }

    /// <summary>
    /// Encrypt the package body for the recipient DID.
    /// </summary>
    public bool SealForRecipient { get; init; }
}
