namespace TnProto.Rotation;

/// <summary>
/// Replacement kit bundle emitted for one surviving recipient.
/// </summary>
public sealed record RotationArtifact(
    string Path,
    string RecipientDid,
    IReadOnlyList<string> Groups);
