using System.Text.Json.Nodes;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliInitTests
{
    [Fact]
    public async Task HelpPrintsUsage()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["--help"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("tn-dotnet", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("init <project>", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task InitCreatesProjectAndPrintsJson()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["init", "payments", "--dir", projectDir, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI JSON output was not an object.");
        Assert.Equal("payments", result["project"]?.GetValue<string>());
        Assert.Equal("transaction", result["profile"]?.GetValue<string>());
        Assert.StartsWith("did:key:z", result["did"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(projectDir, ".tn", "payments", "tn.yaml")));
    }

    [Fact]
    public async Task InitHonorsProfileOption()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["init", "payments", "--dir", projectDir, "--profile", "audit", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI JSON output was not an object.");
        Assert.Equal("audit", result["profile"]?.GetValue<string>());
        var yaml = await File.ReadAllTextAsync(Path.Combine(projectDir, ".tn", "payments", "tn.yaml"));
        Assert.Contains("profile: audit", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InitRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["init", "payments", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown init option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }
}
