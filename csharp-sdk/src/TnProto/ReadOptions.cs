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
    /// Verify integrity and writer trust, rejecting invalid entries. The secure
    /// fail-closed default is <see langword="true" />. Set this to
    /// <see langword="false" /> only as an explicit diagnostic weakening when
    /// invalid entries must be inspected through their verification metadata.
    /// </summary>
    public bool Verify { get; init; } = true;
}
