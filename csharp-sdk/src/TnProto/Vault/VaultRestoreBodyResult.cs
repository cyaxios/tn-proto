using System.Text.Json.Nodes;

namespace TnProto.Vault;

/// <summary>
/// Read-only metadata from restoring and decrypting a vault body.
/// </summary>
public sealed record VaultRestoreBodyResult(
    string ProjectId,
    int BodyMemberCount,
    ulong TotalBodyBytes,
    IReadOnlyList<string> BodyMemberNames,
    JsonNode? WrappedKey,
    JsonNode? EncryptedBlobResponse);
