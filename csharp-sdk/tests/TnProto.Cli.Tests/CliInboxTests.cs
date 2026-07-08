using System.Text.Json.Nodes;
using TnProto;

namespace TnProto.Cli.Tests;

public sealed class CliInboxTests
{
    [Fact]
    public async Task InboxAcceptAppliesInviteAndPrintsJson()
    {
        var (consumerYamlPath, invitePath) = await CreateAcceptFixtureAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "accept", invitePath, "--yaml", consumerYamlPath, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI inbox accept output was not an object.");
        Assert.Equal("default", result["group_name"]?.GetValue<string>());
        Assert.Equal("sender@example.com", result["from_email"]?.GetValue<string>());
        Assert.True(File.Exists(result["kit_path"]?.GetValue<string>()));
        Assert.True(result["kit_hash_verified"]?.GetValue<bool>());
        Assert.False(string.IsNullOrWhiteSpace(result["absorbed_at"]?.GetValue<string>()));
        var manifest = result["manifest"] as JsonObject
            ?? throw new InvalidOperationException("CLI inbox accept output omitted manifest.");
        Assert.Equal("sender@example.com", manifest["from_email"]?.GetValue<string>());
    }

    [Fact]
    public async Task InboxAcceptPrintsTextOutput()
    {
        var (consumerYamlPath, invitePath) = await CreateAcceptFixtureAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "accept", invitePath, "--yaml", consumerYamlPath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Contains("accepted invite for default:", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task InboxAcceptRequiresInvitePath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["inbox", "accept"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Usage: tn-dotnet inbox accept", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InboxAcceptRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "accept", "tn-invite-alice.zip"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InboxAcceptRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "accept", "tn-invite-alice.zip", "--yaml", "tn.yaml", "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown inbox accept option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InboxListLocalPrintsInvitePathsAsJson()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectAsync();
        var inboxDir = Path.Combine(projectDir, "inbox");
        Directory.CreateDirectory(inboxDir);
        var firstInvite = Path.Combine(inboxDir, "tn-invite-first.zip");
        var secondInvite = Path.Combine(inboxDir, "tn-invite-second.zip");
        await using (var tn = await Tn.InitAsync(yamlPath))
        {
            await tn.Inbox.MintInviteAsync(recipientDid, secondInvite);
            await tn.Inbox.MintInviteAsync(recipientDid, firstInvite);
        }

        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "list-local", "--yaml", yamlPath, "--dir", inboxDir, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI inbox list-local output was not an object.");
        Assert.Equal(Path.GetFullPath(inboxDir), result["directory"]?.GetValue<string>());
        var invites = result["invites"] as JsonArray
            ?? throw new InvalidOperationException("CLI inbox list-local output omitted invites.");
        Assert.Equal(2, invites.Count);
        Assert.Contains(invites, path => path?.GetValue<string>() == Path.GetFullPath(firstInvite));
        Assert.Contains(invites, path => path?.GetValue<string>() == Path.GetFullPath(secondInvite));
    }

    [Fact]
    public async Task InboxListLocalPrintsTextOutput()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectAsync();
        var inboxDir = Path.Combine(projectDir, "inbox");
        Directory.CreateDirectory(inboxDir);
        var invitePath = Path.Combine(inboxDir, "tn-invite-alice.zip");
        await using (var tn = await Tn.InitAsync(yamlPath))
        {
            await tn.Inbox.MintInviteAsync(recipientDid, invitePath);
        }

        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "list-local", "--yaml", yamlPath, "--dir", inboxDir],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(Path.GetFullPath(invitePath) + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task InboxListLocalRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "list-local", "--dir", "."],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InboxListLocalRequiresDirectory()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "list-local", "--yaml", "tn.yaml"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --dir", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InboxListLocalRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["inbox", "list-local", "--yaml", "tn.yaml", "--dir", ".", "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown inbox list-local option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InviteMintsZipAndPrintsJson()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectAsync();
        var invitePath = Path.Combine(projectDir, "tn-invite-alice.zip");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "invite", recipientDid,
                "--yaml", yamlPath,
                "--out", invitePath,
                "--group", "default",
                "--from-email", "sender@example.com",
                "--project-id", "proj_123",
                "--project-name", "Payments",
                "--note", "hello",
                "--invitation-id", "invite_123",
                "--provenance", "csharp-cli-test",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.True(File.Exists(invitePath));

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI invite output was not an object.");
        Assert.Equal(Path.GetFullPath(invitePath), result["path"]?.GetValue<string>());
        Assert.Equal(recipientDid, result["recipient_did"]?.GetValue<string>());
        Assert.Equal("default", result["group"]?.GetValue<string>());
        Assert.Equal("sender@example.com", result["from_email"]?.GetValue<string>());
        Assert.Equal("proj_123", result["project_id"]?.GetValue<string>());
        Assert.Equal("Payments", result["project_name"]?.GetValue<string>());
        Assert.Equal("hello", result["note"]?.GetValue<string>());
        Assert.Equal("invite_123", result["invitation_id"]?.GetValue<string>());
        Assert.Equal("csharp-cli-test", result["provenance"]?.GetValue<string>());
        Assert.True(result["zip_len"]?.GetValue<ulong>() > 0);

        await using var tn = await Tn.InitAsync(yamlPath);
        var info = await tn.Inbox.InspectAsync(invitePath);
        Assert.True(info.KitHashVerified);
        Assert.Equal("default", info.GroupName);
        Assert.Equal("sender@example.com", info.Manifest.FromEmail);
    }

    [Fact]
    public async Task InvitePrintsTextOutput()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectAsync();
        var invitePath = Path.Combine(projectDir, "tn-invite-alice.zip");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["invite", recipientDid, "--yaml", yamlPath, "--out", invitePath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal($"invite: {Path.GetFullPath(invitePath)}" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task InviteRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["invite", "did:key:zAlice", "--out", "tn-invite-alice.zip"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InviteRequiresOutPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["invite", "did:key:zAlice", "--yaml", "tn.yaml"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --out", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task InviteRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["invite", "did:key:zAlice", "--yaml", "tn.yaml", "--out", "tn-invite-alice.zip", "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown invite option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<(string YamlPath, string ProjectDir, string RecipientDid)> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        var recipient = TnIdentity.FromSeed(Enumerable.Repeat((byte)83, 32).ToArray());
        return (tn.YamlPath, projectDir, recipient.Did);
    }

    private static async Task<(string ConsumerYamlPath, string InvitePath)> CreateAcceptFixtureAsync()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var invitePath = Path.Combine(producerDir, "tn-invite-alice.zip");
        await producer.Inbox.MintInviteAsync(
            consumer.Did,
            invitePath,
            new()
            {
                Group = "default",
                FromEmail = "sender@example.com",
            });

        return (consumer.YamlPath, invitePath);
    }
}
