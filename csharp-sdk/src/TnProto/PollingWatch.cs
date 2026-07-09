namespace TnProto;

/// <summary>
/// Synchronous-looking, read-backed polling watcher for a TN project.
///
/// This v0 watcher polls <see cref="Tn.ReadAsync(ReadOptions?, CancellationToken)" />.
/// It is not a native file-notification watcher.
/// </summary>
public sealed class PollingWatch
{
    private readonly Tn _tn;
    private readonly WatchOptions _options;
    private int _cursor;

    internal PollingWatch(Tn tn, WatchOptions options, int cursor)
    {
        _tn = tn;
        _options = options;
        _cursor = cursor;
    }

    /// <summary>
    /// Poll once and return newly visible entries.
    /// </summary>
    public async Task<IReadOnlyList<Entry>> PollAsync(CancellationToken cancellationToken = default)
    {
        var entries = await _tn.ReadAsync(_options.ReadOptions, cancellationToken).ConfigureAwait(false);
        if (_cursor > entries.Count)
        {
            _cursor = 0;
        }

        var next = entries
            .Skip(_cursor)
            .Where(Matches)
            .ToArray();

        _cursor = entries.Count;
        return next;
    }

    /// <summary>
    /// Poll until at least one entry is available or timeout elapses.
    /// </summary>
    public async Task<IReadOnlyList<Entry>> WaitForEntriesAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entries = await PollAsync(cancellationToken).ConfigureAwait(false);
            if (entries.Count > 0)
            {
                return entries;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                return Array.Empty<Entry>();
            }

            var delay = _options.PollInterval;
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining < delay)
            {
                delay = remaining;
            }

            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private bool Matches(Entry entry)
    {
        if (_options.EventType is not null && !string.Equals(entry.EventType, _options.EventType, StringComparison.Ordinal))
        {
            return false;
        }

        if (_options.EventTypePrefix is not null &&
            (entry.EventType is null || !entry.EventType.StartsWith(_options.EventTypePrefix, StringComparison.Ordinal)))
        {
            return false;
        }

        return true;
    }
}
