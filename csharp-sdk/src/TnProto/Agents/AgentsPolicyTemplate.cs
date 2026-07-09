namespace TnProto.Agents;

/// <summary>
/// One event type's worth of agent policy text from <c>agents.md</c>.
/// </summary>
public sealed record AgentsPolicyTemplate(
    string EventType,
    string Instruction,
    string UseFor,
    string DoNotUseFor,
    string Consequences,
    string OnViolationOrError,
    string ContentHash,
    string Version,
    string Path);
