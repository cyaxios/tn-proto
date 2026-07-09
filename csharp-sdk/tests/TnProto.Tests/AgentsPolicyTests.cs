using System.Text.Json.Nodes;

namespace TnProto.Tests;

public sealed class AgentsPolicyTests
{
    private const string PolicyMarkdown = """
        # TN Agents Policy
        version: 1
        schema: tn-agents-policy@v1

        ## deal.approved

        ### instruction
        Record one approved deal.

        ### use_for
        Deal reporting.

        ### do_not_use_for
        Compensation decisions.

        ### consequences
        Exposure violates the deal desk policy.

        ### on_violation_or_error
        Escalate to compliance.
        """;

    [Fact]
    public async Task FreshInitDeclaresTnAgentsGroupAndRoutesPolicyFields()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "agentsgroup",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var yamlText = await File.ReadAllTextAsync(tn.YamlPath);
        Assert.Contains("tn.agents", yamlText, StringComparison.Ordinal);

        // The instruction field is declared under the tn.agents group, so an
        // emit carrying it seals it into that group rather than default.
        var receipt = await tn.InfoAsync(
            "deal.reviewed",
            new { instruction = "Handle with care.", deal_id = "D-1" });

        Assert.True(receipt.Emitted);
        Assert.NotNull(receipt.Envelope);
        var agentsPayload = receipt.Envelope["tn.agents"] as JsonObject;
        Assert.NotNull(agentsPayload);
        Assert.True(
            agentsPayload.ContainsKey("ciphertext"),
            "tn.agents group payload must be sealed");

        var entries = await tn.ReadAsync();
        var entry = Assert.Single(entries.Where(e => e.EventType == "deal.reviewed"));
        Assert.Equal("Handle with care.", entry.GetString("instruction"));
        Assert.Equal("D-1", entry.GetString("deal_id"));
    }

    [Fact]
    public async Task PublishAsyncLoadsPolicySplicesEmitsAndPublishes()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "agentspublish",
            new TnProjectOptions { ProjectDirectory = projectDir });

        Assert.Null(tn.Agents.Current);

        var doc = await tn.Agents.PublishAsync(PolicyMarkdown);

        Assert.Equal("1", doc.Version);
        Assert.Equal("tn-agents-policy@v1", doc.Schema);
        Assert.StartsWith("sha256:", doc.ContentHash, StringComparison.Ordinal);
        var template = doc.Templates["deal.approved"];
        Assert.Equal("Record one approved deal.", template.Instruction);
        Assert.Equal("Deal reporting.", template.UseFor);

        var current = tn.Agents.Current;
        Assert.NotNull(current);
        Assert.Equal(doc.ContentHash, current.ContentHash);

        // The reloaded core splices the policy template into a covered
        // event: the caller only supplies business fields.
        var receipt = await tn.InfoAsync("deal.approved", new { deal_id = "D-9" });
        Assert.True(receipt.Emitted);
        Assert.NotNull(receipt.Envelope);
        var agentsPayload = receipt.Envelope["tn.agents"] as JsonObject;
        Assert.NotNull(agentsPayload);
        Assert.True(
            agentsPayload.ContainsKey("ciphertext"),
            "spliced policy fields must be sealed into the tn.agents group");

        var entries = await tn.ReadAsync();
        var entry = Assert.Single(entries.Where(e => e.EventType == "deal.approved"));
        Assert.Equal("Record one approved deal.", entry.GetString("instruction"));
        Assert.Equal("Escalate to compliance.", entry.GetString("on_violation_or_error"));
        Assert.Contains(doc.ContentHash, entry.GetString("policy"), StringComparison.Ordinal);

        // The reopen emitted tn.agents.policy_published onto the ceremony's
        // admin/protocol surface.
        var adminLog = Path.Combine(
            Path.GetDirectoryName(tn.YamlPath)!,
            "admin",
            "default.ndjson");
        Assert.True(File.Exists(adminLog), "admin surface log missing");
        var adminText = await ReadWhileRuntimeHoldsAsync(adminLog);
        Assert.Contains("tn.agents.policy_published", adminText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PublishAsyncSameContentDoesNotRepublish()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "agentsrepublish",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.Agents.PublishAsync(PolicyMarkdown);
        await tn.Agents.PublishAsync(PolicyMarkdown);

        var adminLog = Path.Combine(
            Path.GetDirectoryName(tn.YamlPath)!,
            "admin",
            "default.ndjson");
        var adminText = await ReadWhileRuntimeHoldsAsync(adminLog);
        var publishedRows = adminText
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(line => line.Contains("tn.agents.policy_published", StringComparison.Ordinal));
        Assert.Equal(1, publishedRows);
    }

    /// <summary>
    /// Read a log file the active runtime still holds a writer on. The
    /// default File helpers open with FileShare.Read and fail on Windows
    /// while the native writer keeps write access.
    /// </summary>
    private static async Task<string> ReadWhileRuntimeHoldsAsync(string path)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

    [Fact]
    public async Task PublishAsyncRejectsMalformedPolicyAndRestoresPriorState()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "agentsmalformed",
            new TnProjectOptions { ProjectDirectory = projectDir });

        // Missing four of the five required subsections.
        var malformed = "## deal.approved\n\n### instruction\nOnly this.\n";
        var error = await Assert.ThrowsAsync<TnException>(() => tn.Agents.PublishAsync(malformed));
        Assert.Contains("missing required subsection", error.Message, StringComparison.OrdinalIgnoreCase);

        // Publish is all-or-nothing: no policy file left behind, no policy
        // loaded, and the runtime still works.
        var policyPath = Path.Combine(
            Path.GetDirectoryName(tn.YamlPath)!,
            ".tn",
            "config",
            "agents.md");
        Assert.False(File.Exists(policyPath), "failed publish must not leave a policy file");
        Assert.Null(tn.Agents.Current);

        var receipt = await tn.InfoAsync("deal.reviewed", new { deal_id = "D-2" });
        Assert.True(receipt.Emitted);
    }
}
