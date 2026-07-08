using System.Text.Json.Nodes;
using TnProto;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliReadTests
{
    [Fact]
    public async Task ReadPrintsEntriesAsJsonArray()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["read", "--yaml", yamlPath, "--all-runs"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var entries = JsonNode.Parse(output.ToString()) as JsonArray
            ?? throw new InvalidOperationException("CLI read output was not an array.");
        Assert.Contains(entries.OfType<JsonObject>(), entry =>
            entry["event_type"]?.GetValue<string>() == "payment.created" &&
            entry["order_id"]?.GetValue<string>() == "A-100");
    }

    [Fact]
    public async Task ReadVerifyIncludesValidityFields()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["read", "--yaml", yamlPath, "--all-runs", "--verify"],
            output,
            error);

        Assert.Equal(0, exitCode);
        var entries = JsonNode.Parse(output.ToString()) as JsonArray
            ?? throw new InvalidOperationException("CLI read output was not an array.");
        var payment = entries
            .OfType<JsonObject>()
            .Single(entry => entry["event_type"]?.GetValue<string>() == "payment.created");
        var valid = payment["_valid"] as JsonObject
            ?? throw new InvalidOperationException("Verified read output omitted _valid.");
        Assert.True(valid["signature"]?.GetValue<bool>());
        Assert.True(valid["row_hash"]?.GetValue<bool>());
        Assert.True(valid["chain"]?.GetValue<bool>());
    }

    [Fact]
    public async Task ReadRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["read"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task ReadRejectsUnknownOption()
    {
        var yamlPath = await CreateProjectWithEntriesAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["read", "--yaml", yamlPath, "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown read option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectWithEntriesAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.InfoAsync("payment.created", new { order_id = "A-100", amount = 42 });
        return tn.YamlPath;
    }
}
