namespace TnProto.Vault;

/// <summary>
/// Metadata for a package in the authenticated account inbox.
/// </summary>
public sealed record VaultAccountInboxItem(
    string PublisherIdentity,
    string CeremonyId,
    string Timestamp,
    string? ConsumedAt);
