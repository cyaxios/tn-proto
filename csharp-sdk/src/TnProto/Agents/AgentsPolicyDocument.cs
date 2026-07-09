namespace TnProto.Agents;

/// <summary>
/// Parsed <c>.tn/config/agents.md</c> policy document for the active ceremony.
/// </summary>
/// <remarks>
/// The core loads this document at runtime open; its per-event templates
/// fill the <c>tn.agents</c> group fields on emit and drive the
/// <c>tn.agents.policy_published</c> lifecycle event.
/// </remarks>
public sealed record AgentsPolicyDocument(
    string Version,
    string Schema,
    string Path,
    string Body,
    string ContentHash,
    IReadOnlyDictionary<string, AgentsPolicyTemplate> Templates);
