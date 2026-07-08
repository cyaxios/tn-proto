namespace TnProto;

/// <summary>
/// Signature verification result for a TN envelope.
/// </summary>
public sealed record EnvelopeVerifyResult(
    bool Valid,
    bool Signature,
    string? Reason);
