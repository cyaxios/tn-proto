namespace TnProto;

/// <summary>
/// The input handed to
/// <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>
/// is not a sealed-object envelope at all (invalid JSON, a non-object
/// document, missing envelope scalars, or an undecodable group block).
/// </summary>
/// <remarks>
/// Failed verification throws <see cref="TnVerifyException"/> instead, and
/// holding no key that fits any block is not an error at all.
/// </remarks>
public sealed class TnUnsealException : TnException
{
    /// <summary>
    /// Creates an unseal input failure.
    /// </summary>
    public TnUnsealException(string message)
        : base(message)
    {
    }
}
