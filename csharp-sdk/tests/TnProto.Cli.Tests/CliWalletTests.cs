using System.Text.Json.Nodes;
using TnProto.Account;

namespace TnProto.Cli.Tests;

public sealed class CliWalletTests
{
    [Fact]
    public async Task WalletStatusPrintsJson()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "status", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet status output was not an object.");
        Assert.Equal("local_only", result["verdict"]?.GetValue<string>());
        Assert.StartsWith("did:key:", result["device_did"]?.GetValue<string>(), StringComparison.Ordinal);
        var vault = result["vault"] as JsonObject
            ?? throw new InvalidOperationException("wallet status output omitted vault.");
        Assert.Equal("local", vault["state"]?.GetValue<string>());
        var account = result["account"] as JsonObject
            ?? throw new InvalidOperationException("wallet status output omitted account.");
        Assert.False(account["account_bound"]?.GetValue<bool>());
    }

    [Fact]
    public async Task WalletStatusPrintsHumanOutput()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "status", "--yaml", yamlPath], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Contains("wallet:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("key_cached:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("vault_state:", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WalletStatusPrintsCachedKeyHumanOutput()
    {
        var yamlPath = await CreateProjectAsync();
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-wallet-identity-" + Guid.NewGuid().ToString("N"));
        using var output = new StringWriter();
        using var error = new StringWriter();

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await BindAccountStateAsync(yamlPath, "acct_123");
            await AccountCredentialStore.Default()
                .SetAccountAwkAsync("acct_123", Enumerable.Repeat((byte)4, 32).ToArray());

            var exitCode = await CliApp.RunAsync(["wallet", "status", "--yaml", yamlPath], output, error);

            Assert.Equal(0, exitCode);
            Assert.Equal(string.Empty, error.ToString());
            Assert.Contains("account_id:      acct_123", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("key_cached:      yes", output.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task WalletStatusRequiresYaml()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "status"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletLinkPrintsJsonAndUpdatesStatus()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "wallet",
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
            ?? throw new InvalidOperationException("wallet link output was not an object.");
        Assert.Equal("linked", result["state"]?.GetValue<string>());
        Assert.Equal("https://vault.example.test", result["linked_vault"]?.GetValue<string>());
        Assert.Equal("proj_123", result["linked_project_id"]?.GetValue<string>());

        using var statusOutput = new StringWriter();
        var statusExit = await CliApp.RunAsync(["wallet", "status", "--yaml", yamlPath, "--json"], statusOutput);
        Assert.Equal(0, statusExit);
        var status = JsonNode.Parse(statusOutput.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet status output was not an object.");
        Assert.Equal("linked", status["verdict"]?.GetValue<string>());
    }

    [Fact]
    public async Task WalletUnlinkPrintsJsonAndClearsState()
    {
        var yamlPath = await CreateProjectAsync();
        await CliApp.RunAsync([
            "wallet",
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

        var exitCode = await CliApp.RunAsync(["wallet", "unlink", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet unlink output was not an object.");
        Assert.Equal("local", result["state"]?.GetValue<string>());
        Assert.Null(result["linked_vault"]);
        Assert.Null(result["linked_project_id"]);
    }

    [Fact]
    public async Task WalletLinkRequiresProjectId()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "link", "--yaml", yamlPath, "--vault", "https://vault.example.test"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --project-id", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletPullPrefsRequiresYaml()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "pull-prefs"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletPullPrefsReportsMissingVaultWhenUnlinked()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "pull-prefs", "--yaml", yamlPath], output, error);

        Assert.Equal(1, exitCode);
        Assert.Contains("requires a vault URL", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletPullPrefsRejectsUnknownOption()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "pull-prefs", "--yaml", yamlPath, "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown wallet pull-prefs option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletExportMnemonicUsesDefaultIdentityPath()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-wallet-" + Guid.NewGuid().ToString("N"));
        await WriteIdentityJsonAsync(Path.Combine(tempDir, "identity.json"), words, keepMnemonic: true);
        using var output = new StringWriter();
        using var error = new StringWriter();
        var prior = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", tempDir);
            var exitCode = await CliApp.RunAsync(["wallet", "export-mnemonic", "--yes"], output, error);

            Assert.Equal(0, exitCode);
            Assert.Equal(string.Empty, error.ToString());
            Assert.Contains(words, output.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", prior);
        }
    }

    [Fact]
    public async Task WalletExportMnemonicWarnsWithoutYes()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var identityPath = await WriteIdentityJsonAsync(words, keepMnemonic: true);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "export-mnemonic", "--identity", identityPath],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Contains("ABOUT TO DISPLAY", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(words, output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WalletExportMnemonicPrintsBannerWithYes()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var identityPath = await WriteIdentityJsonAsync(words, keepMnemonic: true);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "export-mnemonic", "--identity", identityPath, "--yes"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Contains("WRITE THIS DOWN NOW", output.ToString(), StringComparison.Ordinal);
        Assert.Contains(words, output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WalletExportMnemonicReportsMissingStoredMnemonic()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var identityPath = await WriteIdentityJsonAsync(words, keepMnemonic: false);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "export-mnemonic", "--identity", identityPath, "--yes"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("no mnemonic stored", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletStageInboxReportsNotBoundJson()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "stage-inbox", "--yaml", yamlPath, "--json"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet stage-inbox output was not an object.");
        Assert.True(result["not_bound"]?.GetValue<bool>());
        Assert.False(result["unauthorized"]?.GetValue<bool>());
        Assert.Equal(0, result["skipped"]?.GetValue<int>());
        var staged = result["staged_paths"] as JsonArray
            ?? throw new InvalidOperationException("wallet stage-inbox output omitted staged_paths.");
        Assert.Empty(staged);
    }

    [Fact]
    public async Task WalletSyncPullOnlyReportsNotBoundJson()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "sync", "--yaml", yamlPath, "--pull-only", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet sync output was not an object.");
        Assert.Equal("pull_only", result["mode"]?.GetValue<string>());
        Assert.True(result["not_bound"]?.GetValue<bool>());
        Assert.Equal(0, result["absorbed_packages"]?.GetValue<int>());
        Assert.Equal(0, result["rejected_count"]?.GetValue<int>());
    }

    [Fact]
    public async Task WalletSyncDefaultCanSkipGroupKeysJson()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "sync", "--yaml", yamlPath, "--no-group-keys", "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet sync output was not an object.");
        Assert.Equal("sync", result["mode"]?.GetValue<string>());
        Assert.True(result["not_bound"]?.GetValue<bool>());
        Assert.Null(result["group_keys"]);
        Assert.Null(result["body_push"]);
    }

    [Fact]
    public async Task WalletSyncPushBodyRequiresPassphrase()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["wallet", "sync", "--yaml", yamlPath, "--push-body"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --passphrase", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletRestoreRequiresTargetDirectory()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "restore", "--yaml", yamlPath, "--passphrase", "secret"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --target-dir", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletRestoreRequiresPassphrase()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["wallet", "restore", "--yaml", yamlPath, "--target-dir", Path.GetTempPath()],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --passphrase", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("--use-cached-account-key", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletRestoreCachedAccountKeyDoesNotRequirePassphrase()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-wallet-restore-" + Guid.NewGuid().ToString("N"));

        var exitCode = await CliApp.RunAsync(
            [
                "wallet",
                "restore",
                "--yaml",
                yamlPath,
                "--target-dir",
                target,
                "--vault",
                "https://vault.example.test",
                "--project-id",
                "proj_123",
                "--use-cached-account-key",
                "--account-id",
                "acct_123",
            ],
            output,
            error);

        Assert.Equal(1, exitCode);
        Assert.Contains("cached account key not found", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
        Assert.False(File.Exists(Path.Combine(target, "tn.yaml")));
    }

    [Fact]
    public async Task WalletRestoreRejectsPassphraseAndCachedAccountKeyTogether()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "wallet",
                "restore",
                "--yaml",
                yamlPath,
                "--target-dir",
                Path.GetTempPath(),
                "--passphrase",
                "secret",
                "--use-cached-account-key",
            ],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("either --passphrase or --use-cached-account-key", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletRestoreRejectsUnknownOption()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "wallet",
                "restore",
                "--yaml",
                yamlPath,
                "--target-dir",
                Path.GetTempPath(),
                "--passphrase",
                "secret",
                "--surprise",
            ],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown wallet restore option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task WalletPublishGroupKeysReportsNoMaterialJson()
    {
        var yamlPath = await CreateProjectAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "wallet",
                "publish-group-keys",
                "--yaml",
                yamlPath,
                "--vault",
                "https://vault.example.test",
                "--group",
                "missing_group",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet publish-group-keys output was not an object.");
        Assert.False(result["published"]?.GetValue<bool>());
        Assert.Null(result["snapshot"]);
    }

    private static async Task<string> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-wallet-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        return tn.YamlPath;
    }

    private static async Task<string> WriteIdentityJsonAsync(string words, bool keepMnemonic)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-wallet-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        await WriteIdentityJsonAsync(identityPath, words, keepMnemonic);
        return identityPath;
    }

    private static async Task WriteIdentityJsonAsync(string identityPath, string words, bool keepMnemonic)
    {
        var identity = TnIdentity.FromMnemonic(words);
        await TnIdentity.SaveJsonAsync(
            identity.Identity,
            identityPath,
            new IdentityJsonOptions
            {
                SeedBase64Url = identity.IdentitySeedBase64Url,
                MnemonicStored = keepMnemonic ? identity.Mnemonic : null,
            });
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
