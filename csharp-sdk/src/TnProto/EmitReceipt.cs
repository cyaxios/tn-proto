using System.Text.Json.Nodes;

namespace TnProto;

/// <summary>
/// Result returned from an emit call.
/// </summary>
public sealed class EmitReceipt
{
    internal EmitReceipt(bool emitted, JsonObject? envelope)
    {
        Emitted = emitted;
        Envelope = envelope;
    }

    /// <summary>
    /// True when an envelope was written.
    /// </summary>
    public bool Emitted { get; }

    /// <summary>
    /// Raw encrypted envelope written by the runtime, when emitted.
    /// </summary>
    public JsonObject? Envelope { get; }
}
