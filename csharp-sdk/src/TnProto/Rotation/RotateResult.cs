namespace TnProto.Rotation;

/// <summary>
/// Result from a deploy-style group rotation.
/// </summary>
public sealed record RotateResult(
    IReadOnlyList<RotatedGroup> Rotated,
    IReadOnlyList<RotationArtifact> Artifacts,
    string? OutDirectory);
