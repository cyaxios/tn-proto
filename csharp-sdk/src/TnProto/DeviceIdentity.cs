namespace TnProto;

/// <summary>
/// Ed25519 TN device identity material.
/// </summary>
/// <param name="SeedBase64">
/// Base64-encoded 32-byte Ed25519 seed. This is private key material.
/// </param>
/// <param name="PublicKeyBase64">
/// Base64-encoded 32-byte Ed25519 public key.
/// </param>
/// <param name="Did">
/// Public <c>did:key</c> identifier derived from the public key.
/// </param>
public sealed record DeviceIdentity(
    string SeedBase64,
    string PublicKeyBase64,
    string Did)
{
    /// <summary>
    /// Raw 32-byte Ed25519 seed. This is private key material.
    /// </summary>
    public byte[] Seed => Convert.FromBase64String(SeedBase64);

    /// <summary>
    /// Raw 32-byte Ed25519 public key.
    /// </summary>
    public byte[] PublicKey => Convert.FromBase64String(PublicKeyBase64);
}
