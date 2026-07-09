using System.Net.Http.Json;
using System.Text.Json.Nodes;
using TnProto.Vault;
using TnProto.Wallet;

namespace TnProto.Tests;

public sealed class VaultLiveTests
{
    [Fact]
    public async Task DevVaultPassphrasePushRestoreAndWrongPassphrase()
    {
        var vaultBase = VaultBaseOrNull();
        if (vaultBase is null)
        {
            return;
        }

        var dev = await DevLoginAsync(vaultBase, "csharp-live");
        if (dev is null)
        {
            return;
        }

        await using var tn = await CreateProjectAsync("csharp-live");
        var connection = await tn.Vault.ConnectAsync(new VaultConnectOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
        });

        var push = await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
            ProjectId = connection.Project.Id,
            Passphrase = dev.Passphrase,
        });

        Assert.Equal(connection.Project.Id, push.ProjectId);
        Assert.True(push.BodyMemberCount > 0);
        Assert.True(push.EncryptedLength > 0);

        var restoreDir = NewTempDirectory("tn-csharp-live-restore-");
        var restore = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
            ProjectId = connection.Project.Id,
            Passphrase = dev.Passphrase,
            TargetDirectory = restoreDir,
        });

        Assert.Equal(connection.Project.Id, restore.ProjectId);
        Assert.True(File.Exists(restore.YamlPath));
        Assert.True(File.Exists(Path.Combine(restoreDir, "keys", "local.private")));

        var wrongRestoreDir = NewTempDirectory("tn-csharp-live-wrong-");
        var error = await Assert.ThrowsAnyAsync<Exception>(() => tn.Wallet.RestoreAsync(new WalletRestoreOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
            ProjectId = connection.Project.Id,
            Passphrase = "definitely not the account passphrase",
            TargetDirectory = wrongRestoreDir,
        }));
        Assert.Contains(
            error.Message,
            ["unwrap", "decrypt", "AEAD"],
            StringComparer.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(wrongRestoreDir, "tn.yaml")));
    }

    [Fact]
    public async Task DevVaultWalletSyncPushBodyUsesPassphrase()
    {
        var vaultBase = VaultBaseOrNull();
        if (vaultBase is null)
        {
            return;
        }

        var dev = await DevLoginAsync(vaultBase, "csharp-wallet-sync");
        if (dev is null)
        {
            return;
        }

        await using var tn = await CreateProjectAsync("csharp-wallet-sync");
        var connection = await tn.Vault.ConnectAsync(new VaultConnectOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
        });

        var sync = await tn.Wallet.SyncAsync(new WalletSyncOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
            ProjectId = connection.Project.Id,
            PushOnly = true,
            PushBody = true,
            Passphrase = dev.Passphrase,
        });

        Assert.True(sync.Pushed);
        Assert.Null(sync.Pull);
        Assert.Null(sync.GroupKeys);
        Assert.NotNull(sync.BodyPush);
        Assert.Equal(connection.Project.Id, sync.BodyPush.ProjectId);
        Assert.True(sync.BodyPush.BodyMemberCount > 0);
        Assert.True(sync.BodyPush.EncryptedLength > 0);

        var restoreDir = NewTempDirectory("tn-csharp-wallet-sync-restore-");
        var restore = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
        {
            VaultBaseUrl = vaultBase,
            BearerToken = dev.Token,
            ProjectId = connection.Project.Id,
            Passphrase = dev.Passphrase,
            TargetDirectory = restoreDir,
        });

        Assert.Equal(connection.Project.Id, restore.ProjectId);
        Assert.True(File.Exists(restore.YamlPath));
    }

    private static async Task<Tn> CreateProjectAsync(string stem)
    {
        var projectDir = NewTempDirectory("tn-csharp-live-project-");
        var projectName = $"{stem}-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        return await Tn.InitProjectAsync(projectName, new TnProjectOptions
        {
            ProjectDirectory = projectDir,
        });
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
