namespace TnProto.Vault;

/// <summary>
/// Result returned after creating/discovering a vault project and linking local YAML.
/// </summary>
public sealed record VaultConnectResult(
    string VaultBaseUrl,
    VaultProject Project,
    VaultLinkStateInfo State,
    bool NewlyLinked);
