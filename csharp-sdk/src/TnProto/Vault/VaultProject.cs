namespace TnProto.Vault;

/// <summary>
/// Vault-side project metadata.
/// </summary>
public sealed record VaultProject(
    string Id,
    string Name,
    string? CeremonyId);
