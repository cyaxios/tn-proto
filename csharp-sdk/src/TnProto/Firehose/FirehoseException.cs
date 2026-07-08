namespace TnProto.Firehose;

/// <summary>
/// Error raised by direct firehose-worker client calls.
/// </summary>
public sealed class FirehoseException : Exception
{
    /// <summary>
    /// Create a firehose exception.
    /// </summary>
    public FirehoseException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Create a firehose exception with an inner exception.
    /// </summary>
    public FirehoseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
