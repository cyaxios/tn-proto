using System.Text.Json.Nodes;

namespace TnProto;

/// <summary>
/// A portable attested object returned by <see cref="Tn.SealAsync{TFields}"/>:
/// a signed standalone envelope carrying its fields encrypted per the sealing
/// ceremony's group config.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="RawJson"/> is the transport artifact — the compact envelope
/// JSON line, no trailing newline. Never re-serialize the parsed
/// <see cref="Envelope"/> for transport: a foreign JSON round-trip is exactly
/// what the sealing-time fragile-value guard protects against, and only the
/// verbatim wire string is guaranteed to verify everywhere. Write
/// <see cref="RawJson"/> (or <see cref="ToString"/>) to the file, HTTP body,
/// or prompt.
/// </para>
/// <para>
/// .NET note on the native fragile-float guard: <c>System.Text.Json</c>
/// serializes integral doubles as integers (<c>1.0</c> becomes <c>1</c>), so
/// public field values that reach the native seal are already round-trip
/// stable and the guard rarely fires from C# — by design. It still rejects
/// public integers beyond 2^53-1.
/// </para>
/// </remarks>
public sealed class SealedObject
{
    private JsonObject? _envelope;

    private SealedObject(string rawJson)
    {
        RawJson = rawJson;
    }

    /// <summary>
    /// The verbatim wire line: compact envelope JSON, no trailing newline.
    /// Transport this string, never a re-serialization.
    /// </summary>
    public string RawJson { get; }

    /// <summary>
    /// The envelope parsed as a JSON object (lazily, from
    /// <see cref="RawJson"/>).
    /// </summary>
    public JsonObject Envelope => _envelope ??= ParseEnvelope(RawJson);

    /// <summary>
    /// The object's identity: the row hash the publisher signed.
    /// </summary>
    public string RowHash => Envelope["row_hash"]?.GetValue<string>() ?? "";

    /// <summary>
    /// The sealed object's event type (its <c>object_type</c>).
    /// </summary>
    public string EventType => Envelope["event_type"]?.GetValue<string>() ?? "";

    /// <summary>
    /// DID of the device that sealed and signed the object.
    /// </summary>
    public string DeviceIdentity => Envelope["device_identity"]?.GetValue<string>() ?? "";

    /// <summary>
    /// The reserved detachment marker every sealed object carries
    /// (<c>1</c> on the wire today).
    /// </summary>
    public int TnSealed => Envelope["tn_sealed"]?.GetValue<int>() ?? 0;

    /// <summary>
    /// Wrap a sealed object's wire line (for example one read back from a
    /// file or produced by another SDK's <c>tn.seal</c>).
    /// </summary>
    public static SealedObject FromJson(string rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            throw new ArgumentException("Sealed object JSON must not be empty.", nameof(rawJson));
        }

        return new SealedObject(rawJson.TrimEnd('\r', '\n'));
    }

    /// <summary>
    /// Returns <see cref="RawJson"/> — the wire line — so the object can be
    /// interpolated directly into a file or prompt.
    /// </summary>
    public override string ToString()
    {
        return RawJson;
    }

    private static JsonObject ParseEnvelope(string rawJson)
    {
        try
        {
            return JsonNode.Parse(rawJson) as JsonObject
                ?? throw new TnException("sealed object wire line is not a JSON object");
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new TnException("sealed object wire line is not valid JSON", ex);
        }
    }
}
