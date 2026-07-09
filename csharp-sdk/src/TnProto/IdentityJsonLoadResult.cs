namespace TnProto;

/// <summary>
/// Result of loading a Python/TypeScript-compatible <c>identity.json</c>.
/// </summary>
public sealed record IdentityJsonLoadResult(
    DeviceIdentity Identity,
    string Path,
    int Version,
    string DevicePrivateEncryptionMethod,
    string? SeedBase64Url,
    string? MnemonicStored,
    string? LinkedVault,
    string? LinkedAccountId);
