using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliCanonicalTests
{
    [Fact]
    public async Task CanonicalPrintsCanonicalJsonFromRawJson()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["canonical", "--json", """{"b":1,"a":{"z":2,"y":1}}"""],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal("""{"a":{"y":1,"z":2},"b":1}""" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task CanonicalPrintsCanonicalBytesHex()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["canonical", "--json", """{"b":1,"a":{"z":2,"y":1}}""", "--hex"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal("7b2261223a7b2279223a312c227a223a327d2c2262223a317d" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task CanonicalReadsInputFromFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var jsonPath = Path.Combine(tempDir, "value.json");
        await File.WriteAllTextAsync(jsonPath, """{"b":2,"a":1}""");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["canonical", "--file", jsonPath], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal("""{"a":1,"b":2}""" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task CanonicalRequiresExactlyOneInputSource()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["canonical", "--json", "{}", "--file", "value.json"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("exactly one input source", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task CanonicalRejectsInvalidJson()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["canonical", "--json", "{"], output, error);

        Assert.Equal(1, exitCode);
        Assert.Contains("valid JSON", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task CanonicalRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["canonical", "--surprise"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown canonical option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }
}
