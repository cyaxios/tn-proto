using System.Text.Json.Nodes;
using TnProto;
using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliAdminTests
{
    [Fact]
    public async Task AdminAddRecipientMintsKitAndPrintsJson()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        var kitPath = Path.Combine(projectDir, "alice.btn.mykit");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "admin", "add-recipient", "payments",
                "--yaml", yamlPath,
                "--out", kitPath,
                "--recipient-did", "did:key:zCSharpRecipientAlice",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.True(File.Exists(kitPath));

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI admin output was not an object.");
        Assert.Equal("payments", result["group"]?.GetValue<string>());
        Assert.Equal("did:key:zCSharpRecipientAlice", result["recipient_did"]?.GetValue<string>());
        Assert.Equal(1UL, result["leaf_index"]?.GetValue<ulong>());
        Assert.Equal(Path.GetFullPath(kitPath), result["kit_path"]?.GetValue<string>());
    }

    [Fact]
    public async Task AdminAddRecipientAllowsMissingRecipientDid()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        var kitPath = Path.Combine(projectDir, "anonymous.btn.mykit");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "add-recipient", "payments", "--yaml", yamlPath, "--out", kitPath, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI admin output was not an object.");
        Assert.Null(result["recipient_did"]?.GetValue<string?>());
        Assert.True(File.Exists(kitPath));
    }

    [Fact]
    public async Task AdminAddRecipientPrintsTextOutput()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        var kitPath = Path.Combine(projectDir, "alice.btn.mykit");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "add-recipient", "payments", "--yaml", yamlPath, "--out", kitPath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Contains("recipient leaf 1 kit:", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task AdminAddRecipientRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "add-recipient", "payments", "--out", "alice.btn.mykit"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminAddRecipientRequiresOutPath()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "add-recipient", "payments", "--yaml", yamlPath],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --out", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRevokeRecipientRevokesLeafAndPrintsJson()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        await using (var tn = await Tn.InitAsync(yamlPath))
        {
            await tn.Admin.AddRecipientAsync(
                "payments",
                Path.Combine(projectDir, "alice.btn.mykit"),
                "did:key:zCSharpRecipientAlice");
        }

        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoke-recipient", "payments", "--yaml", yamlPath, "--leaf", "1", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI admin output was not an object.");
        Assert.Equal("payments", result["group"]?.GetValue<string>());
        Assert.Equal(1UL, result["leaf_index"]?.GetValue<ulong>());

        await using var reopened = await Tn.InitAsync(yamlPath);
        var recipient = Assert.Single(await reopened.Admin.RecipientsAsync("payments", includeRevoked: true));
        Assert.True(recipient.Revoked);
        Assert.Equal(1UL, await reopened.Admin.RevokedCountAsync("payments"));
    }

    [Fact]
    public async Task AdminRevokeRecipientPrintsTextOutput()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        await using (var tn = await Tn.InitAsync(yamlPath))
        {
            await tn.Admin.AddRecipientAsync("payments", Path.Combine(projectDir, "alice.btn.mykit"));
        }

        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoke-recipient", "payments", "--yaml", yamlPath, "--leaf", "1"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal("revoked recipient leaf 1 from payments" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task AdminRevokeRecipientRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoke-recipient", "payments", "--leaf", "1"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRevokeRecipientRequiresLeaf()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoke-recipient", "payments", "--yaml", yamlPath],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --leaf", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRevokeRecipientRejectsMalformedLeaf()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoke-recipient", "payments", "--yaml", yamlPath, "--leaf", "nope"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("--leaf must be", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRevokedCountPrintsZeroBeforeRevocations()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoked-count", "payments", "--yaml", yamlPath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal("0" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task AdminRevokedCountPrintsJsonAfterRevocation()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        await using (var tn = await Tn.InitAsync(yamlPath))
        {
            await tn.Admin.AddRecipientAsync("payments", Path.Combine(projectDir, "alice.btn.mykit"));
            await tn.Admin.RevokeRecipientAsync("payments", 1);
        }

        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoked-count", "payments", "--yaml", yamlPath, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI admin output was not an object.");
        Assert.Equal("payments", result["group"]?.GetValue<string>());
        Assert.Equal(1UL, result["revoked_count"]?.GetValue<ulong>());
    }

    [Fact]
    public async Task AdminRevokedCountRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["admin", "revoked-count", "payments"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRevokedCountRejectsUnknownOption()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "revoked-count", "payments", "--yaml", yamlPath, "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown admin revoked-count option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRotatePrintsJsonAndBumpsYamlEpoch()
    {
        var (yamlPath, projectDir) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "rotate", "payments", "--yaml", yamlPath, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI admin rotate output was not an object.");
        Assert.Equal("payments", result["group"]?.GetValue<string>());
        Assert.True(result["generation"]?.GetValue<uint>() >= 1);
        Assert.StartsWith("sha256:", result["previous_kit_sha256"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.StartsWith("sha256:", result["new_kit_sha256"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(projectDir, ".tn", "payments", "keys", "payments.btn.mykit.retired.0")));

        var yaml = await File.ReadAllTextAsync(yamlPath);
        Assert.Contains("index_epoch: 1", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AdminRotatePrintsTextOutput()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "rotate", "payments", "--yaml", yamlPath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Contains("rotated payments to generation", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task AdminRotateRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["admin", "rotate", "payments"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRotateRejectsUnknownOption()
    {
        var (yamlPath, _) = await CreateProjectWithGroupAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["admin", "rotate", "payments", "--yaml", yamlPath, "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown admin rotate option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AdminRejectsUnknownSubcommand()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["admin", "dance"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown admin command", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<(string YamlPath, string ProjectDir)> CreateProjectWithGroupAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        return (tn.YamlPath, projectDir);
    }
}
