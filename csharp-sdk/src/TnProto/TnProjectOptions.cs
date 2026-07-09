namespace TnProto;

/// <summary>
/// Options for creating or opening a TN project.
/// </summary>
public sealed class TnProjectOptions
{
    /// <summary>
    /// Directory that owns the project's <c>.tn</c> folder.
    /// Defaults to the current working directory.
    /// </summary>
    public string? ProjectDirectory { get; init; }

    /// <summary>
    /// Evidence profile to use for newly-created projects.
    /// </summary>
    public TnProfile Profile { get; init; } = TnProfile.Transaction;

    /// <summary>
    /// Optional explicit 32-byte device seed for advanced bootstrap flows.
    /// Normal callers should leave this unset.
    /// </summary>
    public byte[]? DevicePrivateBytes { get; init; }
}
