namespace TnProto.Rotation;

/// <summary>
/// One rotated group and its resulting generation.
/// </summary>
public sealed record RotatedGroup(
    string Group,
    uint Generation);
