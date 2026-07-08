using System.Text.Json;
using System.Text.Json.Nodes;
using TnProto.Native;

namespace TnProto;

/// <summary>
/// Low-level TN cryptographic verification helpers.
/// </summary>
public static class TnCrypto
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
    };

    /// <summary>
    /// Seal one public-only envelope from the Python/TypeScript <c>tn seal</c> input shape.
    /// </summary>
    public static string SealEnvelope<TInput>(TInput input)
    {
        var inputJson = JsonSerializer.Serialize(input, SerializerOptions);
        return SealEnvelopeRaw(inputJson);
    }

    /// <summary>
    /// Seal one public-only envelope from raw JSON.
    /// </summary>
    public static string SealEnvelopeRaw(string inputJson)
    {
        if (string.IsNullOrWhiteSpace(inputJson))
        {
            throw new ArgumentException("Seal input JSON must not be empty.", nameof(inputJson));
        }

        return NativeBridge.CryptoSealPublic(inputJson);
    }

    /// <summary>
    /// Verify an envelope signature against its device identity and row hash.
    /// </summary>
    public static EnvelopeVerifyResult VerifyEnvelope<TEnvelope>(TEnvelope envelope)
    {
        var envelopeJson = JsonSerializer.Serialize(envelope, SerializerOptions);
        return VerifyEnvelopeRaw(envelopeJson);
    }

    /// <summary>
    /// Verify an envelope signature from raw JSON.
    /// </summary>
    public static EnvelopeVerifyResult VerifyEnvelopeRaw(string envelopeJson)
    {
        if (string.IsNullOrWhiteSpace(envelopeJson))
        {
            throw new ArgumentException("Envelope JSON must not be empty.", nameof(envelopeJson));
        }

        var resultJson = NativeBridge.CryptoVerifyEnvelope(envelopeJson);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native envelope verify returned non-object JSON");

        return new EnvelopeVerifyResult(
            result["valid"]?.GetValue<bool>()
                ?? throw new TnException("native envelope verify result omitted valid flag"),
            result["signature"]?.GetValue<bool>()
                ?? throw new TnException("native envelope verify result omitted signature flag"),
            result["reason"] is JsonValue reason && reason.TryGetValue<string>(out var text)
                ? text
                : null);
    }
}
