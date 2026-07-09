using System.Text.Json.Nodes;

namespace TnProto.Wallet;

/// <summary>
/// Result from restoring an encrypted vault project body into a directory.
/// </summary>
public sealed record WalletRestoreResult(
    string ProjectId,
    int BodyMemberCount,
    ulong TotalBodyBytes,
    IReadOnlyList<string> BodyMemberNames,
    string TargetDirectory,
    string YamlPath,
    string KeysDirectory,
    IReadOnlyList<string> WrittenPaths,
    IReadOnlyList<string> DedupedPaths,
    IReadOnlyList<string> SkippedMembers,
    JsonNode? WrappedKey,
    JsonNode? EncryptedBlobResponse);
