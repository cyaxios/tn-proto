namespace TnProto.Vault;

/// <summary>
/// Local vault link mode stored in a project's <c>tn.yaml</c>.
/// </summary>
public enum VaultLinkState
{
    /// <summary>The project is local-only.</summary>
    Local,

    /// <summary>The project is linked to a vault project.</summary>
    Linked,
}

internal static class VaultLinkStateExtensions
{
    internal static string ToTnName(this VaultLinkState state)
    {
        return state switch
        {
            VaultLinkState.Local => "local",
            VaultLinkState.Linked => "linked",
            _ => throw new ArgumentOutOfRangeException(nameof(state), state, null),
        };
    }
}
