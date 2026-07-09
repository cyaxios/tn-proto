namespace TnProto.Admin;

/// <summary>
/// Result from revoking a recipient reader leaf.
/// </summary>
public sealed record AdminRevokeRecipientResult(
    string Group,
    ulong LeafIndex);
