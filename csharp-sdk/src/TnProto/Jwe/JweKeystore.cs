namespace TnProto.Jwe;

/// <summary>
/// Loads a ceremony keystore directory's jwe reader keys into managed
/// ciphers for the <see cref="UnsealOptions.GroupCiphers"/> second-pass
/// seam:
/// <c>UnsealAsync(src, new UnsealOptions { GroupCiphers = JweKeystore.LoadGroupCiphers(dir) })</c>.
/// </summary>
public static class JweKeystore
{
    private const string MyKeySuffix = ".jwe.mykey";

    private const string RevokedMarker = ".jwe.mykey.revoked.";

    /// <summary>
    /// Scan <paramref name="keystoreDir"/> for the language-neutral jwe
    /// key files every SDK writes (<c>python/tn/cipher.py</c> layout):
    /// each <c>&lt;group&gt;.jwe.mykey</c> — the raw 32-byte X25519
    /// reader private — becomes one <see cref="JweSealedGroupCipher"/>
    /// keyed by group name, trialing the current key first and then any
    /// rotation-archived <c>&lt;group&gt;.jwe.mykey.revoked.&lt;ts&gt;</c>
    /// keys newest first, so pre-rotation blocks keep opening.
    /// </summary>
    /// <remarks>
    /// Unreadable or wrong-size key files are skipped silently — that
    /// key generation's blocks just stay sealed, everything else loads
    /// (the <c>_load_prior_jwe_sks</c> posture). A missing directory
    /// yields an empty map.
    /// </remarks>
    public static IReadOnlyDictionary<string, ISealedGroupCipher> LoadGroupCiphers(string keystoreDir)
    {
        ArgumentNullException.ThrowIfNull(keystoreDir);

        var ciphers = new Dictionary<string, ISealedGroupCipher>(StringComparer.Ordinal);
        if (!Directory.Exists(keystoreDir))
        {
            return ciphers;
        }

        // One directory listing, filtered managed-side: OS glob patterns
        // differ across platforms and this mirrors the TS loader.
        var fileNames = Directory.EnumerateFiles(keystoreDir)
            .Select(Path.GetFileName)
            .OfType<string>()
            .ToList();

        foreach (var fileName in fileNames)
        {
            if (!fileName.EndsWith(MyKeySuffix, StringComparison.Ordinal))
            {
                continue;
            }

            var group = fileName[..^MyKeySuffix.Length];
            if (group.Length == 0)
            {
                continue;
            }

            var keys = new List<byte[]>();
            if (TryReadKey(Path.Combine(keystoreDir, fileName)) is { } current)
            {
                keys.Add(current);
            }

            foreach (var revokedName in RevokedNewestFirst(fileNames, group))
            {
                if (TryReadKey(Path.Combine(keystoreDir, revokedName)) is { } revoked)
                {
                    keys.Add(revoked);
                }
            }

            if (keys.Count > 0)
            {
                ciphers[group] = new JweSealedGroupCipher([.. keys]);
            }
        }

        return ciphers;
    }

    /// <summary>
    /// The group's <c>.revoked.&lt;ts&gt;</c> archive names ordered
    /// newest first — numeric timestamps descending, then any
    /// non-numeric suffixes (e.g. the <c>&lt;ts&gt;_&lt;n&gt;</c>
    /// collision form) ordinal-descending. Order only tunes the trial
    /// walk; every archived key stays in the set.
    /// </summary>
    private static IEnumerable<string> RevokedNewestFirst(IEnumerable<string> fileNames, string group)
    {
        var prefix = group + RevokedMarker;
        return fileNames
            .Where(name => name.Length > prefix.Length && name.StartsWith(prefix, StringComparison.Ordinal))
            .Select(name => (
                Name: name,
                Timestamp: ulong.TryParse(name[prefix.Length..], out var ts) ? ts : (ulong?)null))
            .OrderByDescending(entry => entry.Timestamp.HasValue)
            .ThenByDescending(entry => entry.Timestamp ?? 0)
            .ThenByDescending(entry => entry.Name, StringComparer.Ordinal)
            .Select(entry => entry.Name);
    }

    /// <summary>
    /// Read one raw X25519 private key file; <see langword="null"/> for
    /// anything unreadable or not exactly 32 bytes.
    /// </summary>
    private static byte[]? TryReadKey(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            return bytes.Length == 32 ? bytes : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
