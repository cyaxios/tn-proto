namespace TnProto;

/// <summary>
/// Result of loading or creating a disk-backed TN identity seed.
/// </summary>
/// <param name="Identity">The loaded or generated device identity.</param>
/// <param name="Path">Full path to the seed file.</param>
/// <param name="Created">Whether the seed file was created by this call.</param>
public sealed record IdentityLoadResult(
    DeviceIdentity Identity,
    string Path,
    bool Created);
