namespace TnProto.Tests;

public sealed class ReadVerifyTests
{
    /// <summary>
    /// A verified read (<c>ReadOptions.Verify = true</c>) that rejects a
    /// record raises <see cref="TnVerifyException"/> carrying the read-policy
    /// reasons -- the same typed channel as a rejected unseal. A
    /// non-verifying read returns the row without raising.
    /// </summary>
    [Fact]
    public async Task VerifiedReadRaisesTypedExceptionOnTamperedRow()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        string yamlPath;
        string logPath;

        // Emit a signed row, then close the handle so the native runtime
        // releases the log file before we tamper it on disk.
        await using (var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.InfoAsync("user.event", new { amount = 1 });

            var ok = await tn.ReadAsync(new ReadOptions { Verify = true });
            Assert.Single(ok.Where(e => e.EventType == "user.event"));

            yamlPath = tn.YamlPath;
            logPath = tn.LogPath;
        }

        // Tamper a public header field: the recomputed row_hash no longer
        // matches the signed row_hash string, so a verified read rejects it.
        var contents = await File.ReadAllTextAsync(logPath);
        var tampered = contents.Replace("\"level\":\"info\"", "\"level\":\"warn\"");
        Assert.NotEqual(contents, tampered);
        await File.WriteAllTextAsync(logPath, tampered);

        await using var reopened = await Tn.InitAsync(yamlPath);

        // The tampered row is from a prior run, so span all runs to reach it.
        var error = await Assert.ThrowsAsync<TnVerifyException>(
            () => reopened.ReadAsync(new ReadOptions { Verify = true, AllRuns = true }));
        Assert.Contains("row_hash_invalid", error.FailedChecks);

        // A non-verifying read returns the tampered row without raising.
        var permissive = await reopened.ReadAsync(new ReadOptions { Verify = false, AllRuns = true });
        Assert.Single(permissive.Where(e => e.EventType == "user.event"));
    }
}
