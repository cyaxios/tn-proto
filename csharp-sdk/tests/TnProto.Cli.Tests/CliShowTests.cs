using System.Text.Json.Nodes;

namespace TnProto.Cli.Tests;

public sealed class CliShowTests
{
    [Fact]
    public async Task ShowEnvPrintsJsonSnapshot()
    {
        var (yamlPath, projectDir) = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "env", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI show env output was not an object.");
        Assert.True(result["ok"]?.GetValue<bool>());
        var me = result["me"] as JsonObject
            ?? throw new InvalidOperationException("CLI show env output omitted me.");
        Assert.StartsWith("did:key:z", me["did"]?.GetValue<string>(), StringComparison.Ordinal);
        var project = result["project"] as JsonObject
            ?? throw new InvalidOperationException("CLI show env output omitted project.");
        Assert.Equal("payments", project["name"]?.GetValue<string>());
        Assert.Equal(Path.GetFullPath(projectDir), project["directory"]?.GetValue<string>());
        Assert.Equal(Path.GetFullPath(yamlPath), project["yaml_path"]?.GetValue<string>());
        var logs = result["logs"] as JsonObject
            ?? throw new InvalidOperationException("CLI show env output omitted logs.");
        Assert.False(string.IsNullOrWhiteSpace(logs["path"]?.GetValue<string>()));
    }

    [Fact]
    public async Task ShowEnvPrintsHumanSnapshotByDefault()
    {
        var (yamlPath, _) = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "env", "--yaml", yamlPath], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("resolved runtime snapshot", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("device:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("yaml.path:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("logs.path:", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task ShowEnvRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "env"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task ShowEnvRejectsUnknownFormat()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "env", "--yaml", "tn.yaml", "--format", "yaml"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("--format must be human or json", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task ShowEnvRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "env", "--yaml", "tn.yaml", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown show env option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task ShowProfilesPrintsJsonCatalog()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "profiles", "--format", "json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI show profiles output was not an object.");
        var profiles = result["profiles"] as JsonArray
            ?? throw new InvalidOperationException("CLI show profiles output omitted profiles.");
        Assert.Equal(5, profiles.Count);
        var transaction = profiles
            .OfType<JsonObject>()
            .Single(profile => profile["name"]?.GetValue<string>() == "transaction");
        Assert.True(transaction["default"]?.GetValue<bool>());
        Assert.True(transaction["encrypts"]?.GetValue<bool>());
        Assert.True(transaction["signs"]?.GetValue<bool>());
        Assert.True(transaction["chains"]?.GetValue<bool>());
        Assert.Equal("fsync", transaction["flush"]?.GetValue<string>());
        Assert.Equal("file_rotating", transaction["default_sink"]?.GetValue<string>());
    }

    [Fact]
    public async Task ShowProfilesAcceptsJsonShortcut()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "profiles", "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("\"profiles\"", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task ShowProfilesPrintsHumanCatalogByDefault()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "profiles"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("NAME", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("transaction*", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("stdout", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("catalog default", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task ShowRejectsUnknownCommand()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "missing"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown show command", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task ShowProfilesRejectsUnknownFormat()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "profiles", "--format", "yaml"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("--format must be human or json", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task ShowProfilesRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["show", "profiles", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown show profiles option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<(string YamlPath, string ProjectDir)> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        return (tn.YamlPath, projectDir);
    }
}
