namespace TnProto.Discovery;

/// <summary>
/// Read-only project discovery helpers.
/// </summary>
public static class TnProjectDiscovery
{
    /// <summary>
    /// List ceremonies/streams declared under <c>.tn/&lt;name&gt;/tn.yaml</c>.
    /// </summary>
    public static async Task<IReadOnlyList<TnStreamInfo>> ListStreamsAsync(
        string? projectDirectory = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fullProjectDirectory = Path.GetFullPath(projectDirectory ?? Environment.CurrentDirectory);
        var tnRoot = Path.Combine(fullProjectDirectory, ".tn");
        if (!Directory.Exists(tnRoot))
        {
            return [];
        }

        var streams = new List<TnStreamInfo>();
        foreach (var directory in Directory.EnumerateDirectories(tnRoot).Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var yamlPath = Path.Combine(directory, "tn.yaml");
            if (!File.Exists(yamlPath))
            {
                continue;
            }

            var name = Path.GetFileName(directory);
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var profile = await ReadProfileAsync(yamlPath, cancellationToken).ConfigureAwait(false)
                ?? "(unspecified)";
            streams.Add(new TnStreamInfo(name, profile, Path.GetFullPath(yamlPath)));
        }

        return streams;
    }

    private static async Task<string?> ReadProfileAsync(string yamlPath, CancellationToken cancellationToken)
    {
        try
        {
            var lines = await File.ReadAllLinesAsync(yamlPath, cancellationToken).ConfigureAwait(false);
            var inCeremony = false;
            foreach (var rawLine in lines)
            {
                var line = StripComment(rawLine);
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var indent = line.TakeWhile(char.IsWhiteSpace).Count();
                var trimmed = line.Trim();
                if (indent == 0)
                {
                    inCeremony = trimmed.StartsWith("ceremony:", StringComparison.Ordinal);
                    continue;
                }

                if (inCeremony && indent == 2 && trimmed.StartsWith("profile:", StringComparison.Ordinal))
                {
                    return Unquote(trimmed["profile:".Length..].Trim());
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return null;
    }

    private static string StripComment(string line)
    {
        var quote = false;
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] == '"')
            {
                quote = !quote;
            }
            else if (!quote && line[i] == '#')
            {
                return line[..i];
            }
        }

        return line;
    }

    private static string Unquote(string value)
    {
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
        {
            return value[1..^1];
        }

        return value;
    }
}
