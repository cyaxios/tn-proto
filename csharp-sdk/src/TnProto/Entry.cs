using System.Text.Json.Nodes;

namespace TnProto;

/// <summary>
/// One decrypted flat TN log entry.
/// </summary>
public sealed class Entry
{
    internal Entry(JsonObject fields)
    {
        Fields = fields;
    }

    /// <summary>
    /// Underlying flexible JSON entry fields.
    /// </summary>
    public JsonObject Fields { get; }

    /// <summary>
    /// Entry event type, when present.
    /// </summary>
    public string? EventType => GetString("event_type");

    /// <summary>
    /// Entry level, when present.
    /// </summary>
    public string? Level => GetString("level");

    /// <summary>
    /// Entry sequence number, when present.
    /// </summary>
    public long? Sequence => Fields["sequence"]?.GetValue<long>();

    /// <summary>
    /// Verification flags when the entry was read with verification enabled.
    /// </summary>
    public EntryValidity? Validity
    {
        get
        {
            if (Fields["_valid"] is not JsonObject valid)
            {
                return null;
            }

            return new EntryValidity(
                valid["signature"]?.GetValue<bool>() ?? false,
                valid["row_hash"]?.GetValue<bool>() ?? false,
                valid["chain"]?.GetValue<bool>() ?? false);
        }
    }

    /// <summary>
    /// Return a string field by name.
    /// </summary>
    public string? GetString(string key)
    {
        return Fields[key]?.GetValue<string>();
    }

    /// <summary>
    /// Return a JSON field by name.
    /// </summary>
    public JsonNode? Get(string key)
    {
        return Fields[key];
    }
}
