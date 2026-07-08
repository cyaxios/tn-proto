namespace TnProto.Packages;

/// <summary>
/// Options for compiling and attesting an offer package.
/// </summary>
public sealed class OfferOptions
{
    /// <summary>
    /// Group being offered to the peer.
    /// </summary>
    public required string Group { get; init; }

    /// <summary>
    /// Peer DID the offer package is addressed to.
    /// </summary>
    public required string PeerDid { get; init; }

    /// <summary>
    /// Destination package path.
    /// </summary>
    public required string OutPath { get; init; }

    /// <summary>
    /// Encrypt the package body for the peer DID.
    /// </summary>
    public bool SealForRecipient { get; init; }
}
