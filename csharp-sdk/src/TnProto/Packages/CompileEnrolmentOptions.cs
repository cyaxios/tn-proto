namespace TnProto.Packages;

/// <summary>
/// Options for compiling a recipient enrolment handoff package.
/// </summary>
public sealed class CompileEnrolmentOptions
{
    /// <summary>
    /// Group to include in the handoff package.
    /// </summary>
    public required string Group { get; init; }

    /// <summary>
    /// Recipient DID the package is addressed to.
    /// </summary>
    public required string RecipientDid { get; init; }

    /// <summary>
    /// Destination package path.
    /// </summary>
    public required string OutPath { get; init; }

    /// <summary>
    /// Encrypt the package body for the recipient DID.
    /// </summary>
    public bool SealForRecipient { get; init; }
}
