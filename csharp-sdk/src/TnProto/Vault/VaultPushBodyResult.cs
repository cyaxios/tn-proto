using System.Text.Json.Nodes;

namespace TnProto.Vault;

/// <summary>
/// Result from pushing the encrypted project body to the vault.
/// </summary>
public sealed record VaultPushBodyResult(
    string ProjectId,
    int BodyMemberCount,
    int EncryptedLength,
    bool WrappedKeyCreated,
    string IfMatch,
    JsonNode? WrappedKeyResponse,
    JsonNode? EncryptedBlobResponse);
