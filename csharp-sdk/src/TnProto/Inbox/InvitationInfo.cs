namespace TnProto.Inbox;

/// <summary>
/// Parsed invitation zip metadata.
/// </summary>
public sealed record InvitationInfo(
    InvitationManifest Manifest,
    string GroupName,
    string KitEntryName,
    ulong KitLength,
    string KitSha256Actual,
    InvitationKitHash KitHash,
    bool KitHashVerified);
