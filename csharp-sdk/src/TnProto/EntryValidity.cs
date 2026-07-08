namespace TnProto;

/// <summary>
/// Verification flags attached to a verified read entry.
/// </summary>
public sealed class EntryValidity
{
    internal EntryValidity(bool signature, bool rowHash, bool chain)
    {
        Signature = signature;
        RowHash = rowHash;
        Chain = chain;
    }

    /// <summary>
    /// Signature verification result.
    /// </summary>
    public bool Signature { get; }

    /// <summary>
    /// Row hash verification result.
    /// </summary>
    public bool RowHash { get; }

    /// <summary>
    /// Hash-chain verification result.
    /// </summary>
    public bool Chain { get; }

    /// <summary>
    /// True when all verification checks passed.
    /// </summary>
    public bool IsValid => Signature && RowHash && Chain;
}
