namespace TnProto.Validation;

/// <summary>
/// Severity for a project validation issue.
/// </summary>
public enum ValidationIssueSeverity
{
    /// <summary>A non-fatal issue worth reporting.</summary>
    Warning,

    /// <summary>A validation failure that should make the project invalid.</summary>
    Error,
}

/// <summary>
/// One project validation issue.
/// </summary>
public sealed record ValidationIssue(
    ValidationIssueSeverity Severity,
    string Message,
    string? Path = null);
