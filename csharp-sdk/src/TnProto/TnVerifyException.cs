namespace TnProto;

/// <summary>
/// A sealed object failed verification on
/// <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>
/// with <see cref="UnsealOptions.Verify"/> set (the default).
/// </summary>
/// <remarks>
/// Malformed input throws <see cref="TnUnsealException"/> instead, and
/// holding no key that fits any block is not an error at all — the verified
/// public frame comes back with the blocks left sealed.
/// </remarks>
public sealed class TnVerifyException : TnException
{
    /// <summary>
    /// Creates a verification failure from the native error payload.
    /// </summary>
    public TnVerifyException(IReadOnlyList<string> failedChecks, long sequence, string eventType)
        : base(
            $"entry seq={sequence} event=\"{eventType}\" failed: {string.Join(", ", failedChecks)}")
    {
        FailedChecks = failedChecks;
        Sequence = sequence;
        EventType = eventType;
    }

    /// <summary>
    /// Which integrity checks failed (<c>"signature"</c> / <c>"row_hash"</c>).
    /// </summary>
    public IReadOnlyList<string> FailedChecks { get; }

    /// <summary>
    /// The envelope's sequence (always 0 for sealed objects).
    /// </summary>
    public long Sequence { get; }

    /// <summary>
    /// The envelope's event type.
    /// </summary>
    public string EventType { get; }
}
