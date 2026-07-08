using System.Text.Json.Nodes;
using TnProto;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliVerifyTests
{
    [Fact]
    public async Task VerifyAcceptsValidEnvelopeJson()
    {
        var envelope = await CreateEnvelopeAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["verify", "--json", envelope.ToJsonString()],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI verify output was not an object.");
        Assert.True(result["valid"]?.GetValue<bool>());
        Assert.True(result["signature"]?.GetValue<bool>());
        Assert.Null(result["reason"]?.GetValue<string?>());
    }

    [Fact]
    public async Task VerifyReportsTamperedEnvelopeAsInvalid()
    {
        var envelope = await CreateEnvelopeAsync();
        envelope["row_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["verify", "--json", envelope.ToJsonString()],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI verify output was not an object.");
        Assert.False(result["valid"]?.GetValue<bool>());
        Assert.False(result["signature"]?.GetValue<bool>());
        Assert.Contains("signature", result["reason"]?.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyReadsEnvelopeFromFile()
    {
        var envelope = await CreateEnvelopeAsync();
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var envelopePath = Path.Combine(tempDir, "envelope.json");
        await File.WriteAllTextAsync(envelopePath, envelope.ToJsonString());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["verify", "--file", envelopePath], output, error);

        Assert.Equal(0, exitCode);
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI verify output was not an object.");
        Assert.True(result["valid"]?.GetValue<bool>());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task VerifyRejectsMalformedJson()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["verify", "--json", "{"], output, error);

        Assert.Equal(1, exitCode);
        Assert.Contains("valid JSON", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task VerifyRequiresExactlyOneInputSource()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["verify", "--json", "{}", "--file", "envelope.json"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("exactly one input source", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<JsonObject> CreateEnvelopeAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        var receipt = await tn.InfoAsync("verify.cli", new { ok = true });
        return (JsonObject)Assert.IsType<JsonObject>(receipt.Envelope).DeepClone();
    }
}
