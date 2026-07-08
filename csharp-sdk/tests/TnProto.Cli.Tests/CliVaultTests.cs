using System.Text.Json.Nodes;

namespace TnProto.Cli.Tests;

public sealed class CliVaultTests
{
    [Fact]
    public async Task VaultStatusPrintsFreshLocalState()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["vault", "status", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("vault status output was not an object.");
        Assert.Equal("local", result["state"]?.GetValue<string>());
        Assert.False(result["vault_enabled"]?.GetValue<bool>());
        Assert.False(result["autosync"]?.GetValue<bool>());
    }

    [Fact]
    public async Task VaultLinkPrintsJsonAndUpdatesStatus()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "vault",
                "link",
                "--yaml",
                yamlPath,
                "--vault",
                "https://vault.example.test/",
                "--project-id",
                "proj_123",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("vault link output was not an object.");
        Assert.Equal("linked", result["state"]?.GetValue<string>());
        Assert.Equal("https://vault.example.test", result["linked_vault"]?.GetValue<string>());
        Assert.Equal("proj_123", result["linked_project_id"]?.GetValue<string>());
    }

    [Fact]
    public async Task VaultUnlinkPrintsJson()
    {
        var yamlPath = await CreateProjectAsync();
        await CliApp.RunAsync([
            "vault",
            "link",
            "--yaml",
            yamlPath,
            "--vault",
            "https://vault.example.test",
            "--project-id",
            "proj_123",
        ]);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["vault", "unlink", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("vault unlink output was not an object.");
        Assert.Equal("local", result["state"]?.GetValue<string>());
        Assert.Null(result["linked_vault"]);
        Assert.Null(result["linked_project_id"]);
    }

    [Fact]
    public async Task VaultLinkRequiresProjectId()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["vault", "link", "--yaml", yamlPath, "--vault", "https://vault.example.test"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --project-id", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task VaultConnectRequiresVault()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["vault", "connect", "--yaml", yamlPath], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --vault", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task VaultClaimLinkRequiresVault()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["vault", "claim-link", "--yaml", yamlPath], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --vault", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-vault-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        return tn.YamlPath;
    }
}
