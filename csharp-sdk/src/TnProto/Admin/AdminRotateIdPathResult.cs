namespace TnProto.Admin;

/// <summary>
/// Result from rotating a hibe group's identity path. Future seals target
/// <see cref="NewPath"/>; <see cref="PreviousPath"/> heads the group's
/// idpath history so the authority keeps opening pre-rotation entries.
/// </summary>
public sealed record AdminRotateIdPathResult(
    string Group,
    string PreviousPath,
    string NewPath);
