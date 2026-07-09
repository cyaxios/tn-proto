namespace TnProto.Admin;

/// <summary>
/// Result from ensuring a TN admin group exists and routing fields into it.
/// </summary>
public sealed record AdminEnsureGroupResult(
    string Group,
    IReadOnlyList<string> Fields,
    bool Created,
    bool Changed);
