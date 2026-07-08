namespace TnProto.Admin;

/// <summary>
/// Result returned after rotating a btn admin group.
/// </summary>
public sealed record AdminRotateGroupResult(
    string Group,
    uint Generation,
    string PreviousKitSha256,
    string NewKitSha256,
    string RotatedAt);
