namespace TnProto;

/// <summary>
/// Options for reading decrypted TN entries.
/// </summary>
public sealed class ReadOptions
{
    /// <summary>
    /// Include entries from every process run instead of only this runtime run.
    /// </summary>
    public bool AllRuns { get; init; }

    /// <summary>
    /// Include verification metadata.
    /// </summary>
    public bool Verify { get; init; }
}
