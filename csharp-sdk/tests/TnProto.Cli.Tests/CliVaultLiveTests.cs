using System.Net.Http.Json;
using System.Text.Json.Nodes;

namespace TnProto.Cli.Tests;

public sealed class CliVaultLiveTests
{
    [Fact]
    public async Task DevVaultWalletSyncPushBodyCommandUsesPassphrase()
    {
        var vaultBase = VaultBaseOrNull();
        if (vaultBase is null)
        {
            return;
        }

        var dev = await DevLoginAsync(vaultBase, "csharp-cli-wallet-sync");
        if (dev is null)
        {
            return;
        }

        var yamlPath = await CreateProjectAsync("csharp-cli-wallet-sync");
        using var connectOutput = new StringWriter();
        using var connectError = new StringWriter();
        var connectExitCode = await CliApp.RunAsync(
            [
                "vault",
                "connect",
                "--yaml",
                yamlPath,
                "--vault",
                vaultBase,
                "--bearer",
                dev.Token,
                "--json",
            ],
            connectOutput,
            connectError);

        Assert.Equal(0, connectExitCode);
        Assert.Equal(string.Empty, connectError.ToString());
        var connect = JsonNode.Parse(connectOutput.ToString()) as JsonObject
            ?? throw new InvalidOperationException("vault connect output was not an object.");
        var project = connect["project"] as JsonObject
            ?? throw new InvalidOperationException("vault connect output omitted project.");
        var projectId = project["id"]?.GetValue<string>()
            ?? throw new InvalidOperationException("vault connect output omitted project.id.");

        using var syncOutput = new StringWriter();
        using var syncError = new StringWriter();
        var syncExitCode = await CliApp.RunAsync(
            [
                "wallet",
                "sync",
                "--yaml",
                yamlPath,
                "--vault",
                vaultBase,
                "--bearer",
                dev.Token,
                "--project-id",
                projectId,
                "--push-only",
                "--push-body",
                "--passphrase",
                dev.Passphrase,
                "--json",
            ],
            syncOutput,
            syncError);

        Assert.Equal(0, syncExitCode);
        Assert.Equal(string.Empty, syncError.ToString());
        var sync = JsonNode.Parse(syncOutput.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet sync output was not an object.");
        Assert.Equal("push_only", sync["mode"]?.GetValue<string>());
        var bodyPush = sync["body_push"] as JsonObject
            ?? throw new InvalidOperationException("wallet sync output omitted body_push.");
        Assert.Equal(projectId, bodyPush["project_id"]?.GetValue<string>());
        Assert.True(bodyPush["body_member_count"]?.GetValue<int>() > 0);
        Assert.True(bodyPush["encrypted_len"]?.GetValue<int>() > 0);

        var restoreDir = NewTempDirectory("tn-csharp-cli-live-restore-");
        using var restoreOutput = new StringWriter();
        using var restoreError = new StringWriter();
        var restoreExitCode = await CliApp.RunAsync(
            [
                "wallet",
                "restore",
                "--yaml",
                yamlPath,
                "--vault",
                vaultBase,
                "--bearer",
                dev.Token,
                "--project-id",
                projectId,
                "--target-dir",
                restoreDir,
                "--passphrase",
                dev.Passphrase,
                "--json",
            ],
            restoreOutput,
            restoreError);

        Assert.Equal(0, restoreExitCode);
        Assert.Equal(string.Empty, restoreError.ToString());
        var restore = JsonNode.Parse(restoreOutput.ToString()) as JsonObject
            ?? throw new InvalidOperationException("wallet restore output was not an object.");
        Assert.Equal(projectId, restore["project_id"]?.GetValue<string>());
        Assert.Equal(restoreDir, restore["target_dir"]?.GetValue<string>());
        var restoredYaml = restore["yaml_path"]?.GetValue<string>()
            ?? throw new InvalidOperationException("wallet restore output omitted yaml_path.");
        Assert.True(File.Exists(restoredYaml));
        Assert.True(File.Exists(Path.Combine(restoreDir, "keys", "local.private")));
    }

    private static async Task<string> CreateProjectAsync(string stem)
    {
        var projectDir = NewTempDirectory("tn-csharp-cli-live-project-");
        var projectName = $"{stem}-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        await using var tn = await Tn.InitProjectAsync(projectName, new TnProjectOptions
        {
            ProjectDirectory = projectDir,
        });
        return tn.YamlPath;
    }

    private static async Task<DevLogin?> DevLoginAsync(string vaultBase, string stem)
    {
        using var http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
        var handle = $"{stem}-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid():N}";
        HttpResponseMessage response;
        try
        {
            response = await http.PostAsJsonAsync(
                $"{vaultBase}/api/v1/dev/login",
                new { handle });
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (TaskCanceledException)
        {
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var raw = await response.Content.ReadFromJsonAsync<JsonObject>();
        var token = raw?["token"]?.GetValue<string>();
        var accountId = raw?["account_id"]?.GetValue<string>();
        var passphrase = raw?["passphrase"]?.GetValue<string>() ?? $"tn-dev-{handle}";
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(accountId))
        {
            throw new InvalidOperationException("dev/login response omitted token or account_id.");
        }

        return new DevLogin(accountId, token, passphrase);
    }

    private static string? VaultBaseOrNull()
    {
        var value = Environment.GetEnvironmentVariable("PLUMB_VAULT");
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.TrimEnd('/');
    }

    private static string NewTempDirectory(string prefix)
    {
        var path = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed record DevLogin(string AccountId, string Token, string Passphrase);
}
