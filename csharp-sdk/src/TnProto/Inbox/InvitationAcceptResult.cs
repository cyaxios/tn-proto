using System.Text.Json.Nodes;

namespace TnProto.Inbox;

/// <summary>
/// Result from accepting an invitation into the active project.
/// </summary>
public sealed record InvitationAcceptResult(
    InvitationInfo Info,
    string KitPath,
    string? BackupPath,
    string AbsorbedAt,
    string GroupName,
    string FromEmail,
    JsonNode? LeafIndex);
