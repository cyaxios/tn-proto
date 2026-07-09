namespace TnProto;

/// <summary>
/// Optional fields to include when writing a Python/TypeScript-compatible
/// <c>identity.json</c> document.
/// </summary>
public sealed class IdentityJsonOptions
{
    /// <summary>
    /// BIP-39 seed bytes encoded as URL-safe base64 without padding, when known.
    /// Defaults to the device seed for raw-key identities.
    /// </summary>
    public string? SeedBase64Url { get; init; }

    /// <summary>
    /// Recovery phrase to persist only when the user explicitly opts in.
    /// </summary>
    public string? MnemonicStored { get; init; }

    /// <summary>
    /// Vault URL remembered for account and wallet flows.
    /// </summary>
    public string? LinkedVault { get; init; }

    /// <summary>
    /// Vault account id remembered after a successful account connect flow.
    /// </summary>
    public string? LinkedAccountId { get; init; }
}
