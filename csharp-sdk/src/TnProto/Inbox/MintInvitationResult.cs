namespace TnProto.Inbox;

/// <summary>
/// Result from minting an invitation zip.
/// </summary>
public sealed record MintInvitationResult(
    string Path,
    string RecipientDid,
    InvitationManifest Manifest,
    string KitEntryName,
    ulong ZipLength);
