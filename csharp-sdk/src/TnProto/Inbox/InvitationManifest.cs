using System.Text.Json.Nodes;

namespace TnProto.Inbox;

/// <summary>
/// Parsed manifest metadata from a TN invitation zip.
/// </summary>
public sealed record InvitationManifest(
    string? InvitationId,
    string? FromAccountDid,
    string? FromEmail,
    string? ProjectId,
    string? ProjectName,
    string? GroupName,
    JsonNode? LeafIndex,
    string? KitSha256,
    JsonNode? EventId,
    string? CreatedAt,
    string? Note,
    string? Provenance,
    JsonObject Raw);
