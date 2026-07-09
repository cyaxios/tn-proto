using System.Text.Json.Nodes;

namespace TnProto.Tests;

public sealed class EmitReadTests
{
    [Fact]
    public async Task InfoAsyncAndReadAsyncRoundTripFields()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await tn.InfoAsync(
            "payment.created",
            new { order_id = "A-100", amount = 42 });

        Assert.True(receipt.Emitted);
        Assert.NotNull(receipt.Envelope);

        var entries = await tn.ReadAsync();
        var entry = Assert.Single(entries.Where(e => e.EventType == "payment.created"));

        Assert.Equal("info", entry.Level);
        Assert.Equal("A-100", entry.GetString("order_id"));
        Assert.Equal(42, entry.Get("amount")!.GetValue<int>());
    }

    [Fact]
    public async Task ReadAsyncAllRunsSeesEntriesAfterReopen()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        string yamlPath;

        await using (var tn = await Tn.InitProjectAsync(
            "audit",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.LogAsync("audit.created", new { actor = "alice" });
            yamlPath = tn.YamlPath;
        }

        await using var reopened = await Tn.InitAsync(yamlPath);

        var currentRunEntries = await reopened.ReadAsync();
        var allRunEntries = await reopened.ReadAsync(new ReadOptions { AllRuns = true });

        Assert.DoesNotContain(currentRunEntries, e => e.EventType == "audit.created");
        Assert.Contains(allRunEntries, e => e.EventType == "audit.created");
    }

    [Fact]
    public async Task InfoAsyncRejectsNonObjectFields()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<TnException>(() =>
            tn.InfoAsync("bad.fields", "not an object"));

        Assert.Contains("JSON object", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(TnLogLevel.Debug, "debug", "debug.created")]
    [InlineData(TnLogLevel.Warning, "warning", "warning.created")]
    [InlineData(TnLogLevel.Error, "error", "error.created")]
    public async Task EmitAsyncWritesSelectedLevel(TnLogLevel level, string expectedLevel, string eventType)
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "levels",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await tn.EmitAsync(level, eventType, new { ok = true });

        Assert.True(receipt.Emitted);

        var entries = await tn.ReadAsync();
        var entry = Assert.Single(entries.Where(e => e.EventType == eventType));

        Assert.Equal(expectedLevel, entry.Level);
    }

    [Fact]
    public async Task LevelSpecificHelpersWriteExpectedLevels()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "helpers",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.DebugAsync("helper.debug", new { ok = true });
        await tn.WarningAsync("helper.warning", new { ok = true });
        await tn.ErrorAsync("helper.error", new { ok = true });

        var entries = await tn.ReadAsync();

        Assert.Contains(entries, e => e.EventType == "helper.debug" && e.Level == "debug");
        Assert.Contains(entries, e => e.EventType == "helper.warning" && e.Level == "warning");
        Assert.Contains(entries, e => e.EventType == "helper.error" && e.Level == "error");
    }

    [Fact]
    public async Task EmitAsyncRejectsEmptyEventTypeBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.EmitAsync(TnLogLevel.Info, "", new { ok = true }));

        Assert.Equal("eventType", error.ParamName);
    }

    [Fact]
    public async Task InfoAsyncWithAadBindsMarkersAndReadsBack()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "aadmarkers",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var marker = new Dictionary<string, object?>
        {
            ["purpose"] = "audit",
            ["ticket"] = "T-77",
        };
        var receipt = await tn.InfoAsync(
            "payment.flagged",
            new { secret_note = "escalate" },
            aad: marker);

        Assert.True(receipt.Emitted);
        Assert.NotNull(receipt.Envelope);
        var echoed = receipt.Envelope["tn_aad"]?.GetValue<string>();
        Assert.NotNull(echoed);

        // The sealed group still opens on read: the reader reconstructs
        // the bound AAD bytes from the public tn_aad echo.
        var entries = await tn.ReadAsync();
        var entry = Assert.Single(entries.Where(e => e.EventType == "payment.flagged"));
        Assert.Equal("escalate", entry.GetString("secret_note"));

        // The marker dict round-trips through the canonical tn_aad echo.
        Assert.Equal(echoed, entry.TnAad);
        var binding = JsonNode.Parse(entry.TnAad!) as JsonObject;
        Assert.NotNull(binding);
        var boundMarker = binding["default"] as JsonObject;
        Assert.NotNull(boundMarker);
        Assert.Equal("audit", boundMarker["purpose"]?.GetValue<string>());
        Assert.Equal("T-77", boundMarker["ticket"]?.GetValue<string>());
    }

    [Fact]
    public async Task EmptyAadKeepsWireShapeIdenticalToPlainEmit()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "aadempty",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var withEmpty = await tn.InfoAsync(
            "payment.plain",
            new { secret_note = "quiet" },
            aad: new Dictionary<string, object?>());
        var withNull = await tn.InfoAsync("payment.plain", new { secret_note = "quiet" });

        foreach (var receipt in new[] { withEmpty, withNull })
        {
            Assert.True(receipt.Emitted);
            Assert.NotNull(receipt.Envelope);
            Assert.False(
                receipt.Envelope.ContainsKey("tn_aad"),
                "empty aad must not add a tn_aad field");
        }

        var entries = await tn.ReadAsync();
        foreach (var entry in entries.Where(e => e.EventType == "payment.plain"))
        {
            Assert.Null(entry.TnAad);
        }
    }

    [Fact]
    public async Task ReadAsyncVerifyMarksValidEntries()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "verify",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.InfoAsync("verify.valid", new { marker = "valid-row" });

        var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true, Verify = true });
        var entry = Assert.Single(entries.Where(e => e.EventType == "verify.valid"));

        Assert.NotNull(entry.Validity);
        Assert.True(entry.Validity.Signature);
        Assert.True(entry.Validity.RowHash);
        Assert.True(entry.Validity.Chain);
        Assert.True(entry.Validity.IsValid);
    }

    [Fact]
    public async Task ReadAsyncVerifyFlagsTamperedRows()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        string logPath;
        string yamlPath;

        await using (var tn = await Tn.InitProjectAsync(
            "verify",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.InfoAsync("verify.original", new { marker = "tamper-row" });
            logPath = tn.LogPath;
            yamlPath = tn.YamlPath;
        }

        var rawLog = await File.ReadAllTextAsync(logPath);
        Assert.Contains("verify.original", rawLog, StringComparison.Ordinal);
        await File.WriteAllTextAsync(
            logPath,
            rawLog.Replace("verify.original", "verify.tampered", StringComparison.Ordinal));

        await using var reopened = await Tn.InitAsync(yamlPath);
        var entries = await reopened.ReadAsync(new ReadOptions { AllRuns = true, Verify = true });
        var entry = Assert.Single(entries.Where(e => e.EventType == "verify.tampered"));

        Assert.NotNull(entry.Validity);
        Assert.False(entry.Validity.IsValid);
        Assert.Equal("tamper-row", entry.GetString("marker"));
    }
}
