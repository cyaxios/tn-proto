using System.Text.Json.Nodes;
using TnProto;

namespace TnProto.Cli.Tests;

public sealed class CliValidateTests
{
    [Fact]
    public async Task ValidatePrintsOkForCleanProject()
    {
        var projectDir = await CreateProjectAsync("default");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["validate", "--project-dir", projectDir], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("OK: 1 ceremony valid.", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task ValidatePrintsJson()
    {
        var projectDir = await CreateProjectAsync("default");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["validate", "--project-dir", projectDir, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI validate output was not an object.");
        Assert.True(result["valid"]?.GetValue<bool>());
        Assert.Equal(Path.GetFullPath(projectDir), result["project_directory"]?.GetValue<string>());
        var ceremonies = result["ceremony_names"] as JsonArray
            ?? throw new InvalidOperationException("CLI validate output omitted ceremony names.");
        Assert.Contains(ceremonies, name => name?.GetValue<string>() == "default");
    }

    [Fact]
    public async Task ValidateReturnsOneAndPrintsErrorsForInvalidProject()
    {
        var projectDir = await CreateProjectAsync("default");
        var yamlPath = Tn.ProjectYamlPath(projectDir, "default");
        var yaml = await File.ReadAllTextAsync(yamlPath);
        await File.WriteAllTextAsync(yamlPath, yaml.Replace("profile: transaction", "profile: nope", StringComparison.Ordinal));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["validate", "--project-dir", projectDir], output, error);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Contains("ERROR:", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("unknown profile", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidateMissingTnRootIsNoOp()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["validate", "--project-dir", projectDir], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("nothing to validate", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task ValidateRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["validate", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown validate option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectAsync(string project)
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using (await Tn.InitProjectAsync(project, new TnProjectOptions { ProjectDirectory = projectDir }))
        {
        }

        return projectDir;
    }
}
