namespace TnProto.Inbox;

/// <summary>
/// Options for minting an invitation zip.
/// </summary>
public sealed class MintInvitationOptions
{
    /// <summary>
    /// Group to mint the reader kit for. Defaults to <c>default</c>.
    /// </summary>
    public string? Group { get; init; }

    /// <summary>
    /// Sender email or label recorded in the manifest.
    /// </summary>
    public string? FromEmail { get; init; }

    /// <summary>
    /// Linked vault project id, when available.
    /// </summary>
    public string? ProjectId { get; init; }

    /// <summary>
    /// Human project name, when available.
    /// </summary>
    public string? ProjectName { get; init; }

    /// <summary>
    /// Free-form note for the invitation.
    /// </summary>
    public string? Note { get; init; }

    /// <summary>
    /// Optional caller-supplied invitation id.
    /// </summary>
    public string? InvitationId { get; init; }

    /// <summary>
    /// Producer marker. Defaults to the native SDK default.
    /// </summary>
    public string? Provenance { get; init; }
}
