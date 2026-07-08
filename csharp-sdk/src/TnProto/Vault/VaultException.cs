namespace TnProto.Vault;

/// <summary>
/// Raised when the vault returns an error response or malformed JSON.
/// </summary>
public sealed class VaultException : TnException
{
    /// <summary>
    /// HTTP status code returned by the vault, when available.
    /// </summary>
    public int? StatusCode { get; }

    /// <summary>
    /// Raw response body snippet returned by the vault, when available.
    /// </summary>
    public string? Body { get; }

    /// <summary>
    /// Create a vault exception.
    /// </summary>
    public VaultException(string message, int? statusCode = null, string? body = null)
        : base(message)
    {
        StatusCode = statusCode;
        Body = body;
    }
}
