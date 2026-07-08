namespace TnProto.Rotation;

/// <summary>
/// Options for deploy-style group key rotation.
/// </summary>
public sealed class RotateOptions
{
    /// <summary>
    /// Groups to rotate. Defaults to <c>default</c> when omitted by the caller.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; init; }

    /// <summary>
    /// Directory or single <c>.tnpkg</c> path for replacement recipient bundles.
    /// </summary>
    public string? OutPath { get; init; }

    /// <summary>
    /// Seal each replacement package body for its recipient DID.
    /// </summary>
    public bool SealForRecipient { get; init; }
}
