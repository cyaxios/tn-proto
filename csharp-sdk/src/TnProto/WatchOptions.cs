namespace TnProto;

/// <summary>
/// Options for the read-backed polling watcher.
/// </summary>
public sealed class WatchOptions
{
    /// <summary>
    /// Start by returning entries that are already visible.
    /// Defaults to only entries emitted after the watcher is created.
    /// </summary>
    public bool FromBeginning { get; init; }

    /// <summary>
    /// Exact event type filter. When combined with <see cref="EventTypePrefix" />,
    /// both filters must match.
    /// </summary>
    public string? EventType { get; init; }

    /// <summary>
    /// Event type prefix filter. When combined with <see cref="EventType" />,
    /// both filters must match.
    /// </summary>
    public string? EventTypePrefix { get; init; }

    /// <summary>
    /// Poll interval used while waiting for new entries.
    /// </summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Read options forwarded to <see cref="Tn.ReadAsync(ReadOptions?, CancellationToken)" />.
    /// </summary>
    public ReadOptions ReadOptions { get; init; } = new();
}
