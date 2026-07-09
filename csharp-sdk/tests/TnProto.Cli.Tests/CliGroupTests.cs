using System.Text.Json.Nodes;
using TnProto;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliGroupTests
{
    [Fact]
    public async Task GroupAddCreatesGroupAndPrintsJson()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["group", "add", "payments", "--yaml", yamlPath, "--field", "order_id", "--field", "amount", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI group output was not an object.");
        Assert.Equal("payments", result["group"]?.GetValue<string>());
        Assert.True(result["created"]?.GetValue<bool>());
        Assert.True(result["changed"]?.GetValue<bool>());

        var fields = result["fields"] as JsonArray
            ?? throw new InvalidOperationException("CLI group output omitted fields.");
        Assert.Equal(["order_id", "amount"], fields.Select(field => field?.GetValue<string>()).ToArray());

        var yaml = await File.ReadAllTextAsync(yamlPath);
        Assert.Contains("payments", yaml, StringComparison.Ordinal);
        Assert.Contains("order_id", yaml, StringComparison.Ordinal);
        Assert.Contains("amount", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GroupAddReportsUnchangedForExistingRoute()
    {
        var yamlPath = await CreateProjectAsync();
        await CliApp.RunAsync(["group", "add", "payments", "--yaml", yamlPath, "--field", "order_id"]);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["group", "add", "payments", "--yaml", yamlPath, "--field", "order_id"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal("group payments unchanged" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task GroupAddRequiresField()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["group", "add", "payments", "--yaml", yamlPath], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires at least one --field", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task GroupAddRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["group", "add", "payments", "--field", "order_id"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task GroupRejectsUnknownSubcommand()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["group", "remove", "payments"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown group command", error.ToString(), StringComparison.Ordinal);
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
