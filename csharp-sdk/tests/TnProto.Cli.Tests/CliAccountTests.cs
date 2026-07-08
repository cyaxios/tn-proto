using System.Text.Json.Nodes;
using TnProto.Account;

namespace TnProto.Cli.Tests;

public sealed class CliAccountTests
{
    [Fact]
    public async Task AccountStatusPrintsJsonForFreshProject()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["account", "status", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("account status output was not an object.");
        Assert.StartsWith("did:key:", result["device_did"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.False(result["account_bound"]?.GetValue<bool>());
        Assert.Equal("not_logged_in", result["verdict"]?.GetValue<string>());
    }

    [Fact]
    public async Task AccountStatusPrintsHumanOutput()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["account", "status", "--yaml", yamlPath], output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains("account_bound:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("key_cached:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("verdict:", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task AccountStatusPrintsCachedKeyHumanOutput()
    {
        var yamlPath = await CreateProjectAsync();
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-account-identity-" + Guid.NewGuid().ToString("N"));
        using var output = new StringWriter();
        using var error = new StringWriter();

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await BindAccountStateAsync(yamlPath, "acct_123");
            await AccountCredentialStore.Default()
                .SetAccountAwkAsync("acct_123", Enumerable.Repeat((byte)3, 32).ToArray());

            var exitCode = await CliApp.RunAsync(["account", "status", "--yaml", yamlPath], output, error);

            Assert.Equal(0, exitCode);
            Assert.Contains("account_id:    acct_123", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("key_cached:    yes", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("verdict:       backed_up", output.ToString(), StringComparison.Ordinal);
            Assert.Equal(string.Empty, error.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task AccountLogoutPrintsJsonForFreshProject()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["account", "logout", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("account logout output was not an object.");
        Assert.False(result["was_bound"]?.GetValue<bool>());
        Assert.Null(result["account_id"]);
    }

    [Fact]
    public async Task AccountConnectRequiresVault()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["account", "connect", "ABC123", "--yaml", yamlPath], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --vault", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AccountRejectsUnknownCommand()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["account", "missing"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown account command", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<string> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-account-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        return tn.YamlPath;
    }

    private static async Task BindAccountStateAsync(string yamlPath, string accountId)
    {
        var yamlDirectory = Path.GetDirectoryName(yamlPath)
            ?? throw new InvalidOperationException("tn.yaml path had no parent directory.");
        var stateDirectory = Path.Combine(yamlDirectory, ".tn", "sync");
        Directory.CreateDirectory(stateDirectory);
        await File.WriteAllTextAsync(
            Path.Combine(stateDirectory, "state.json"),
            new JsonObject
            {
                ["account_id"] = accountId,
                ["account_bound"] = true,
            }.ToJsonString());
    }
}
