namespace TnProto.Packages;

/// <summary>
/// Read-only metadata for a .tnpkg package.
/// </summary>
public sealed record PackageInfo(
    string Kind,
    string Category,
    string Scope,
    string PublisherIdentity,
    string? RecipientIdentity,
    string CeremonyId,
    ulong EventCount,
    string? HeadRowHash,
    PackageSignatureInfo Signature,
    ulong BodyEntryCount,
    IReadOnlyList<string> BodyEntryNames,
    bool ContainsSecretMaterial,
    bool ContainsReaderKeys,
    bool HasPackageJson,
    bool Sealed)
{
    /// <summary>
    /// True when the manifest signature verifies against the publisher identity.
    /// </summary>
    public bool Verified => Signature.Verified;

    /// <summary>
    /// True when this package was published by the provided DID.
    /// </summary>
    public bool IsPublishedBy(string did)
    {
        return string.Equals(PublisherIdentity, did, StringComparison.Ordinal);
    }

    /// <summary>
    /// True when this package is addressed to the provided DID.
    /// </summary>
    public bool IsAddressedTo(string did)
    {
        return string.Equals(RecipientIdentity, did, StringComparison.Ordinal);
    }
}
