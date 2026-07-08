namespace TnProto.Admin;

/// <summary>
/// One recipient roster row derived from admin log replay.
/// </summary>
public sealed record AdminRecipient(
    ulong LeafIndex,
    string? RecipientIdentity,
    string? MintedAt,
    string? KitSha256,
    bool Revoked,
    string? RevokedAt);
