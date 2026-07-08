using System.Text.Json.Nodes;
using TnProto;

namespace TnProto.Cli.Tests;

public sealed class CliStreamsTests
{
    [Fact]
    public async Task StreamsPrintsHumanTable()
    {
        var projectDir = await CreateProjectWithStreamsAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["streams", "--project-dir", projectDir], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("NAME", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("audit", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("payments", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("transaction", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task StreamsPrintsJsonRows()
    {
        var projectDir = await CreateProjectWithStreamsAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["streams", "--project-dir", projectDir, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var rows = JsonNode.Parse(output.ToString()) as JsonArray
            ?? throw new InvalidOperationException("CLI streams output was not an array.");
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows.OfType<JsonObject>(), row =>
            row["name"]?.GetValue<string>() == "payments" &&
            row["profile"]?.GetValue<string>() == "transaction" &&
            File.Exists(row["yaml_path"]?.GetValue<string>()));
    }

    [Fact]
    public async Task StreamsMissingTnRootPrintsNoCeremonies()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["streams", "--project-dir", projectDir], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("no ceremonies found", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task StreamsRejectsUnknownFormat()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["streams", "--format", "yaml"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("--format must be human or json", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task StreamsRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["streams", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown streams option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectWithStreamsAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using (await Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
        }

        await using (await Tn.InitProjectAsync(
            "audit",
            new TnProjectOptions
            {
                ProjectDirectory = projectDir,
                Profile = TnProfile.Audit,
            }))
        {
        }

        return projectDir;
    }
}
