using System.Text.Json.Nodes;
using TnProto;

namespace TnProto.Cli.Tests;

public sealed class CliRotateTests
{
    [Fact]
    public async Task RotatePrintsJsonAndEmitsArtifact()
    {
        var (yamlPath, projectDir) = await CreateProjectWithRecipientAsync();
        var outDir = Path.Combine(projectDir, "rotated");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["rotate", "payments", "--yaml", yamlPath, "--out", outDir, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI rotate output was not an object.");
        Assert.True(result["ok"]?.GetValue<bool>());
        var rotated = result["rotated"] as JsonArray
            ?? throw new InvalidOperationException("CLI rotate output omitted rotated rows.");
        Assert.Single(rotated);
        var artifacts = result["artifacts"] as JsonArray
            ?? throw new InvalidOperationException("CLI rotate output omitted artifacts.");
        var artifact = Assert.Single(artifacts);
        Assert.True(File.Exists(artifact?.GetValue<string>()));
    }

    [Fact]
    public async Task RotatePrintsNoArtifactTextWhenNoRecipients()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        var yamlPath = tn.YamlPath;
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["rotate", "--yaml", yamlPath], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("no surviving recipients", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task RotateRejectsMissingYaml()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["rotate", "payments"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task RotateRejectsPositionalGroupAndGroupsFlagTogether()
    {
        var (yamlPath, _) = await CreateProjectWithRecipientAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["rotate", "payments", "--groups", "payments", "--yaml", yamlPath],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("either a positional", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<(string YamlPath, string ProjectDir)> CreateProjectWithRecipientAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "alice.btn.mykit"),
            "did:key:zCSharpRecipientAlice");
        return (tn.YamlPath, projectDir);
    }
}
