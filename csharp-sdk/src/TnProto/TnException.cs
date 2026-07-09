namespace TnProto;

/// <summary>
/// Base exception for C# SDK errors.
/// </summary>
public class TnException : Exception
{
    /// <summary>
    /// Creates a new TN exception.
    /// </summary>
    public TnException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates a new TN exception with an inner cause.
    /// </summary>
    public TnException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
