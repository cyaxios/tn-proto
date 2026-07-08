using System.Text.Json.Nodes;

namespace TnProto.Account;

/// <summary>
/// Result returned after a vault account connect-code redemption.
/// </summary>
public sealed record AccountConnectResult(
    string AccountId,
    string? ProjectId,
    string? ProjectName,
    string Vault,
    JsonObject Response);
