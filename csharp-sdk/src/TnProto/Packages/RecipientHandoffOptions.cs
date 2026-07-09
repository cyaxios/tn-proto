namespace TnProto.Packages;

/// <summary>
/// Options for exporting an admin snapshot plus recipient reader bundle.
/// </summary>
public sealed class RecipientHandoffOptions
{
    /// <summary>
    /// Recipient DID the reader bundle is addressed to.
    /// </summary>
    public required string RecipientDid { get; init; }

    /// <summary>
    /// Directory where handoff packages are written.
    /// </summary>
    public required string OutDirectory { get; init; }

    /// <summary>
    /// Optional group subset for the reader bundle. Defaults to all non-internal groups.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; init; }

    /// <summary>
    /// Encrypt the reader bundle body for the recipient DID.
    /// </summary>
    public bool SealForRecipient { get; init; }
}
