using System.Text;
using System.Text.Json;
using TnProto.Native;

namespace TnProto;

/// <summary>
/// Canonical JSON helpers shared with the TN core implementation.
/// </summary>
public static class TnCanonical
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
    };

    /// <summary>
    /// Serialize a value to TN canonical JSON.
    /// </summary>
    public static string Json<TValue>(TValue value)
    {
        var inputJson = JsonSerializer.Serialize(value, SerializerOptions);
        return NativeBridge.CanonicalJson(inputJson);
    }

    /// <summary>
    /// Serialize raw JSON text to TN canonical JSON.
    /// </summary>
    public static string JsonFromRaw(string valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson))
        {
            throw new ArgumentException("JSON input must not be empty.", nameof(valueJson));
        }

        return NativeBridge.CanonicalJson(valueJson);
    }

    /// <summary>
    /// Serialize a value to TN canonical JSON bytes.
    /// </summary>
    public static byte[] Bytes<TValue>(TValue value)
    {
        return Encoding.UTF8.GetBytes(Json(value));
    }

    /// <summary>
    /// Serialize raw JSON text to TN canonical JSON bytes.
    /// </summary>
    public static byte[] BytesFromRaw(string valueJson)
    {
        return Encoding.UTF8.GetBytes(JsonFromRaw(valueJson));
    }

    /// <summary>
    /// Serialize a value to TN canonical bytes and return lowercase hex.
    /// </summary>
    public static string BytesHex<TValue>(TValue value)
    {
        var inputJson = JsonSerializer.Serialize(value, SerializerOptions);
        return NativeBridge.CanonicalBytesHex(inputJson);
    }

    /// <summary>
    /// Serialize raw JSON text to TN canonical bytes and return lowercase hex.
    /// </summary>
    public static string BytesHexFromRaw(string valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson))
        {
            throw new ArgumentException("JSON input must not be empty.", nameof(valueJson));
        }

        return NativeBridge.CanonicalBytesHex(valueJson);
    }
}
