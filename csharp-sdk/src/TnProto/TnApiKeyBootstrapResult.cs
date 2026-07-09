using TnProto.Packages;

namespace TnProto;

/// <summary>
/// Result from installing a cold-start API-key sealed bootstrap bundle.
/// </summary>
public sealed record TnApiKeyBootstrapResult(
    TnApiKey ApiKey,
    string VaultBaseUrl,
    string Token,
    string? Kind,
    PackageAbsorbReceipt Receipt,
    Tn Project)
{
    /// <summary>
    /// True when the sealed bundle installed successfully.
    /// </summary>
    public bool Succeeded => !Receipt.Rejected;
}
