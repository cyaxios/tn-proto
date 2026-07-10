namespace TnProto.Admin;

/// <summary>
/// Result from granting a hibe reader a delegated identity-key kit.
/// <see cref="IdPath"/> is the identity path the minted key is keyed to
/// (the group's sealing path unless an ancestor path was requested).
/// </summary>
public sealed record AdminGrantReaderResult(
    string Group,
    string? ReaderDid,
    string IdPath,
    string KitPath);
