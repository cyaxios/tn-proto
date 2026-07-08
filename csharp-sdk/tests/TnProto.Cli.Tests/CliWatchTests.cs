using System.Text.Json.Nodes;
using TnProto;

namespace TnProto.Cli.Tests;

public sealed class CliWatchTests
{
    [Fact]
    public async Task WatchFromBeginningPrintsEntriesAsJson()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["watch", "--yaml", yamlPath, "--from-beginning", "--all-runs", "--timeout-ms", "0", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var entries = JsonNode.Parse(output.ToString()) as JsonArray
            ?? throw new InvalidOperationException("CLI watch output was not an array.");
        Assert.Contains(entries.OfType<JsonObject>(), entry => entry["event_type"]?.GetValue<string>() == "order.created");
        Assert.Contains(entries.OfType<JsonObject>(), entry => entry["event_type"]?.GetValue<string>() == "invoice.created");
    }

    [Fact]
    public async Task WatchFiltersByExactEventType()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "watch",
                "--yaml", yamlPath,
                "--from-beginning",
                "--all-runs",
                "--event-type", "order.created",
                "--timeout-ms", "0",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        var entries = JsonNode.Parse(output.ToString()) as JsonArray
            ?? throw new InvalidOperationException("CLI watch output was not an array.");
        var entry = Assert.Single(entries.OfType<JsonObject>());
        Assert.Equal("order.created", entry["event_type"]?.GetValue<string>());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task WatchFiltersByEventTypePrefixAndLimit()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "watch",
                "--yaml", yamlPath,
                "--from-beginning",
                "--all-runs",
                "--event-type-prefix", "order.",
                "--limit", "1",
                "--timeout-ms", "0",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        var entries = JsonNode.Parse(output.ToString()) as JsonArray
            ?? throw new InvalidOperationException("CLI watch output was not an array.");
        var entry = Assert.Single(entries.OfType<JsonObject>());
        Assert.StartsWith("order.", entry["event_type"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task WatchPrintsTextOutput()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["watch", "--yaml", yamlPath, "--from-beginning", "--all-runs", "--event-type", "order.created", "--timeout-ms", "0"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Contains("order.created", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task WatchTimeoutWithNoEntriesPrintsEmptyJsonArray()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["watch", "--yaml", tn.YamlPath, "--timeout-ms", "0", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal("[]" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task WatchRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["watch"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WatchRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["watch", "--yaml", "tn.yaml", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown watch option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WatchRejectsMalformedTimeout()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["watch", "--yaml", "tn.yaml", "--timeout-ms", "nope"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("--timeout-ms must be", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectWithEntriesAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "watch",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.InfoAsync("invoice.created", new { ok = true });
        await tn.InfoAsync("order.created", new { order_id = "A-100" });
        await tn.InfoAsync("order.shipped", new { order_id = "A-100" });
        return tn.YamlPath;
    }
}
