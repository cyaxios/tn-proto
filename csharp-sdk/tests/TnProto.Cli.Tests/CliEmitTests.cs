using System.Text.Json.Nodes;
using TnProto;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliEmitTests
{
    [Fact]
    public async Task LogEmitsSeveritylessEvent()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["log", "payment.created", "--yaml", yamlPath, "--fields", """{"order_id":"A-100"}""", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI JSON output was not an object.");
        Assert.True(result["emitted"]?.GetValue<bool>());

        await using var tn = await Tn.InitAsync(yamlPath);
        var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true, Verify = true });
        var entry = Assert.Single(entries.Where(entry => entry.EventType == "payment.created"));
        Assert.True(string.IsNullOrEmpty(entry.Level));
        Assert.Equal("A-100", entry.GetString("order_id"));
    }

    [Fact]
    public async Task InfoEmitsInfoLevelEvent()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["info", "payment.reviewed", "--yaml", yamlPath, "--fields", """{"ok":true}"""],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Contains("emitted payment.reviewed", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());

        await using var tn = await Tn.InitAsync(yamlPath);
        var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true, Verify = true });
        var entry = Assert.Single(entries.Where(entry => entry.EventType == "payment.reviewed"));
        Assert.Equal("info", entry.Level);
        Assert.True(entry.Get("ok")?.GetValue<bool>());
    }

    [Fact]
    public async Task LogDefaultsFieldsToEmptyObject()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["log", "heartbeat", "--yaml", yamlPath], output, error);

        Assert.Equal(0, exitCode);
        await using var tn = await Tn.InitAsync(yamlPath);
        var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true, Verify = true });
        Assert.Contains(entries, entry => entry.EventType == "heartbeat");
    }

    [Fact]
    public async Task LogRejectsNonObjectFields()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["log", "bad.fields", "--yaml", yamlPath, "--fields", "[1,2,3]"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Fields JSON must be an object", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InfoRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["info", "missing.yaml"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        return tn.YamlPath;
    }
}
