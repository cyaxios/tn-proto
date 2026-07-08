namespace TnProto.Validation;

/// <summary>
/// Result from validating a TN project directory.
/// </summary>
public sealed record ValidationResult(
    string ProjectDirectory,
    string TnRoot,
    IReadOnlyList<string> CeremonyNames,
    IReadOnlyList<ValidationIssue> Issues)
{
    /// <summary>Validation errors.</summary>
    public IReadOnlyList<ValidationIssue> Errors =>
        Issues.Where(issue => issue.Severity == ValidationIssueSeverity.Error).ToArray();

    /// <summary>Validation warnings.</summary>
    public IReadOnlyList<ValidationIssue> Warnings =>
        Issues.Where(issue => issue.Severity == ValidationIssueSeverity.Warning).ToArray();

    /// <summary>True when no validation errors were found.</summary>
    public bool Valid => Errors.Count == 0;
}
