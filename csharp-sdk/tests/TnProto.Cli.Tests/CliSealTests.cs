using System.Text.Json.Nodes;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliSealTests
{
    [Fact]
    public async Task SealReadsNdjsonFromStdinAndPrintsEnvelopeNdjson()
    {
        var input = SealInputLine(includeBlankLines: true);
        using var output = new StringWriter();
        using var error = new StringWriter();
        var prior = Console.In;

        try
        {
            Console.SetIn(new StringReader(input));

            var exitCode = await CliApp.RunAsync(["seal"], output, error);

            Assert.Equal(0, exitCode);
            Assert.Equal(string.Empty, error.ToString());
            var lines = output.ToString()
                .Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Single(lines);
            var envelope = JsonNode.Parse(lines[0]) as JsonObject
                ?? throw new InvalidOperationException("seal output was not an object.");
            Assert.Equal("order.created", envelope["event_type"]?.GetValue<string>());
            Assert.Equal("info", envelope["level"]?.GetValue<string>());
            Assert.Equal(100, envelope["amount"]?.GetValue<int>());
            Assert.True(TnCrypto.VerifyEnvelopeRaw(lines[0]).Valid);
        }
        finally
        {
            Console.SetIn(prior);
        }
    }

    [Fact]
    public async Task SealRejectsInvalidJsonOnStdin()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var prior = Console.In;

        try
        {
            Console.SetIn(new StringReader("{\n"));

            var exitCode = await CliApp.RunAsync(["seal"], output, error);

            Assert.Equal(2, exitCode);
            Assert.Contains("invalid JSON on stdin", error.ToString(), StringComparison.Ordinal);
            Assert.Equal(string.Empty, output.ToString());
        }
        finally
        {
            Console.SetIn(prior);
        }
    }

    [Fact]
    public async Task SealRejectsMissingRequiredField()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var prior = Console.In;

        try
        {
            Console.SetIn(new StringReader("""{"seed_b64":"AAAA"}""" + "\n"));

            var exitCode = await CliApp.RunAsync(["seal"], output, error);

            Assert.Equal(2, exitCode);
            Assert.Contains("missing field event_type", error.ToString(), StringComparison.Ordinal);
            Assert.Equal(string.Empty, output.ToString());
        }
        finally
        {
            Console.SetIn(prior);
        }
    }

    [Fact]
    public async Task SealRejectsUnexpectedArguments()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["seal", "--json"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown seal option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static string SealInputLine(bool includeBlankLines)
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var input = new JsonObject
        {
            ["seed_b64"] = Convert.ToBase64String(seed),
            ["event_type"] = "order.created",
            ["level"] = "info",
            ["sequence"] = 1,
            ["prev_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ["timestamp"] = "2026-04-23T12:00:00Z",
            ["event_id"] = "00000000-0000-0000-0000-000000000001",
            ["public_fields"] = new JsonObject
            {
                ["amount"] = 100,
            },
        };
        var line = input.ToJsonString() + "\n";
        return includeBlankLines ? "\n" + line + "\n" : line;
    }
}
