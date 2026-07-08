namespace TnProto.Tests;

public sealed class WatchTests
{
    [Fact]
    public async Task WatchFromBeginningReturnsExistingEntries()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.InfoAsync("watch.ready", new { ok = true });

        var watch = await tn.WatchAsync(new WatchOptions { FromBeginning = true });
        var entries = await watch.PollAsync();

        Assert.Contains(entries, e => e.EventType == "watch.ready");
    }

    [Fact]
    public async Task WatchLatestReturnsEntriesAfterCreation()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.InfoAsync("watch.before", new { ok = true });
        var watch = await tn.WatchAsync();
        await tn.InfoAsync("watch.after", new { ok = true });

        var entries = await watch.WaitForEntriesAsync(TimeSpan.FromSeconds(2));

        Assert.DoesNotContain(entries, e => e.EventType == "watch.before");
        Assert.Contains(entries, e => e.EventType == "watch.after");
    }

    [Fact]
    public async Task WatchFiltersByExactEventTypeAndPrefix()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var exact = await tn.WatchAsync(new WatchOptions
        {
            EventType = "order.created",
            FromBeginning = true,
        });
        var prefix = await tn.WatchAsync(new WatchOptions
        {
            EventTypePrefix = "order.",
            FromBeginning = true,
        });

        await tn.InfoAsync("invoice.created", new { ok = true });
        await tn.InfoAsync("order.created", new { ok = true });
        await tn.InfoAsync("order.shipped", new { ok = true });

        var exactEntries = await exact.PollAsync();
        var prefixEntries = await prefix.PollAsync();

        Assert.Single(exactEntries);
        Assert.Equal("order.created", exactEntries[0].EventType);
        Assert.Contains(prefixEntries, e => e.EventType == "order.created");
        Assert.Contains(prefixEntries, e => e.EventType == "order.shipped");
        Assert.DoesNotContain(prefixEntries, e => e.EventType == "invoice.created");
    }

    [Fact]
    public async Task WatchExactAndPrefixFiltersAreConjunctive()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });
        var watch = await tn.WatchAsync(new WatchOptions
        {
            EventType = "order.created",
            EventTypePrefix = "order.",
            FromBeginning = true,
        });

        await tn.InfoAsync("order.created", new { ok = true });
        await tn.InfoAsync("order.shipped", new { ok = true });

        var entries = await watch.PollAsync();

        var entry = Assert.Single(entries);
        Assert.Equal("order.created", entry.EventType);
    }

    [Fact]
    public async Task WatchExactAndPrefixMismatchReturnsNoEntries()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });
        var watch = await tn.WatchAsync(new WatchOptions
        {
            EventType = "order.created",
            EventTypePrefix = "invoice.",
            FromBeginning = true,
        });

        await tn.InfoAsync("order.created", new { ok = true });
        await tn.InfoAsync("invoice.created", new { ok = true });

        var entries = await watch.PollAsync();

        Assert.Empty(entries);
    }

    [Fact]
    public async Task WatchRecoversWhenVisibleEntryCountShrinks()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });
        var constructor = typeof(PollingWatch).GetConstructor(
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
            binder: null,
            [typeof(Tn), typeof(WatchOptions), typeof(int)],
            modifiers: null)
            ?? throw new InvalidOperationException("PollingWatch internal constructor was not found");
        var watch = (PollingWatch)constructor.Invoke(
            [tn, new WatchOptions { FromBeginning = true }, 100]);
        await tn.InfoAsync("watch.after-truncate", new { ok = true });

        var entries = await watch.PollAsync();

        Assert.Contains(entries, entry => entry.EventType == "watch.after-truncate");
    }
}
