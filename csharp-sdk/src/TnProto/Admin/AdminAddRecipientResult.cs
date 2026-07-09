namespace TnProto.Admin;

/// <summary>
/// Result from minting a reader kit for a recipient.
/// </summary>
public sealed record AdminAddRecipientResult(
    string Group,
    string? RecipientDid,
    ulong LeafIndex,
    string KitPath);
