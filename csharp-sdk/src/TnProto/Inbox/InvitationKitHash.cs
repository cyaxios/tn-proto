namespace TnProto.Inbox;

/// <summary>
/// Hash verification status for an invitation's inner reader kit.
/// </summary>
public sealed record InvitationKitHash(
    string Status,
    bool Verified,
    string? Expected);
