namespace TnProto.Vault;

/// <summary>
/// Vault response after publishing a signed inbox snapshot package.
/// </summary>
public sealed record VaultInboxSnapshot(
    string StoredPath,
    ulong ByteSize,
    string ManifestSignatureBase64,
    string? HeadRowHash);
