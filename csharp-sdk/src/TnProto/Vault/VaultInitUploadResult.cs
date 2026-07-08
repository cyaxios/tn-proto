namespace TnProto.Vault;

/// <summary>
/// Result from the unauthenticated vault pending-claim onboarding flow.
/// </summary>
public sealed record VaultInitUploadResult(
    string VaultId,
    string ExpiresAt,
    string ClaimUrl,
    string PasswordBase64Url,
    bool Reused);
