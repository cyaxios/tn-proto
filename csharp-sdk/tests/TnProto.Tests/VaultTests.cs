using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TnProto.Account;
using TnProto.Vault;
using TnProto.Wallet;

namespace TnProto.Tests;

public sealed class VaultTests
{
    [Fact]
    public async Task LinkStateAsyncReportsFreshProjectAsLocal()
    {
        await using var tn = await CreateProjectAsync();

        var state = await tn.Vault.LinkStateAsync();

        Assert.Equal(VaultLinkState.Local, state.State);
        Assert.Equal("local", state.StateName);
        Assert.Null(state.LinkedVault);
        Assert.Null(state.LinkedProjectId);
        Assert.False(state.VaultEnabled);
        Assert.False(state.Autosync);
    }

    [Fact]
    public async Task LinkAsyncWritesCeremonyAndVaultYamlState()
    {
        await using var tn = await CreateProjectAsync();

        var result = await tn.Vault.LinkAsync("https://vault.example.test/", "proj_123");
        var state = await tn.Vault.LinkStateAsync();
        var yaml = await File.ReadAllTextAsync(tn.YamlPath);

        Assert.Equal(VaultLinkState.Linked, result.State);
        Assert.Equal("https://vault.example.test", result.LinkedVault);
        Assert.Equal("proj_123", result.LinkedProjectId);
        Assert.Equal(VaultLinkState.Linked, state.State);
        Assert.Equal("https://vault.example.test", state.LinkedVault);
        Assert.Equal("proj_123", state.LinkedProjectId);
        Assert.True(state.VaultEnabled);
        Assert.True(state.Autosync);
        Assert.Equal(600, state.SyncIntervalSeconds);
        Assert.Contains("mode: linked", yaml, StringComparison.Ordinal);
        Assert.Contains("linked_vault: https://vault.example.test", yaml, StringComparison.Ordinal);
        Assert.Contains("linked_project_id: proj_123", yaml, StringComparison.Ordinal);
        Assert.Contains("enabled: true", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnlinkAsyncClearsLocalVaultState()
    {
        await using var tn = await CreateProjectAsync();
        await tn.Vault.LinkAsync("https://vault.example.test", "proj_123");

        var result = await tn.Vault.UnlinkAsync();
        var state = await tn.Vault.LinkStateAsync();
        var yaml = await File.ReadAllTextAsync(tn.YamlPath);

        Assert.Equal(VaultLinkState.Local, result.State);
        Assert.Null(result.LinkedVault);
        Assert.Null(result.LinkedProjectId);
        Assert.Equal(VaultLinkState.Local, state.State);
        Assert.Null(state.LinkedVault);
        Assert.Null(state.LinkedProjectId);
        Assert.False(state.VaultEnabled);
        Assert.False(state.Autosync);
        Assert.Contains("mode: local", yaml, StringComparison.Ordinal);
        Assert.Contains("enabled: false", yaml, StringComparison.Ordinal);
        Assert.Contains("linked_project_id: ''", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SetLinkStateAsyncRequiresVaultAndProjectIdWhenLinking()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Vault.SetLinkStateAsync(VaultLinkState.Linked));

        Assert.Equal("options", error.ParamName);
    }

    [Fact]
    public async Task PushBodyWithPassphraseAsyncRequiresPassphrase()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                ProjectId = "proj_123",
            }));

        Assert.Equal("options", error.ParamName);
        Assert.Contains("Passphrase", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PushBodyWithPassphraseAsyncRequiresVaultUrlOrLinkedVault()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
            {
                Passphrase = "correct horse battery staple",
                ProjectId = "proj_123",
            }));

        Assert.Equal("options", error.ParamName);
        Assert.Contains("vault URL", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RestoreBodyWithPassphraseAsyncRequiresPassphrase()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Vault.RestoreBodyWithPassphraseAsync(new VaultRestoreBodyWithPassphraseOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                ProjectId = "proj_123",
            }));

        Assert.Equal("options", error.ParamName);
        Assert.Contains("Passphrase", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RestoreBodyWithPassphraseAsyncRequiresVaultUrlOrLinkedVault()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Vault.RestoreBodyWithPassphraseAsync(new VaultRestoreBodyWithPassphraseOptions
            {
                Passphrase = "correct horse battery staple",
                ProjectId = "proj_123",
            }));

        Assert.Equal("options", error.ParamName);
        Assert.Contains("vault URL", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PushBodyWithPassphraseAsyncUploadsEncryptedBodyThroughFakeVault()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);

        var result = await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });

        Assert.Equal("proj_123", result.ProjectId);
        Assert.True(result.BodyMemberCount >= 3);
        Assert.True(result.EncryptedLength > 0);
        Assert.True(result.WrappedKeyCreated);
        Assert.Equal("*", result.IfMatch);
        Assert.Equal("Bearer jwt-123", vault.LastAuthorization);
        Assert.Equal("*", vault.LastIfMatch);
        Assert.NotNull(vault.WrappedKeyPut);
        Assert.NotNull(vault.EncryptedBlobPut);
        var ciphertextB64 = vault.EncryptedBlobPut?["ciphertext_b64"]?.GetValue<string>();
        var nonceB64 = vault.EncryptedBlobPut?["nonce_b64"]?.GetValue<string>();
        var saltB64 = vault.EncryptedBlobPut?["salt_b64"]?.GetValue<string>();
        Assert.False(string.IsNullOrWhiteSpace(ciphertextB64));
        Assert.False(string.IsNullOrWhiteSpace(nonceB64));
        Assert.False(string.IsNullOrWhiteSpace(saltB64));
        Assert.Equal(Convert.FromBase64String(ciphertextB64!)[..12], Convert.FromBase64String(nonceB64!));
        Assert.Equal(16, Convert.FromBase64String(saltB64!).Length);
    }

    [Fact]
    public async Task RestoreBodyWithPassphraseAsyncReadsDecryptedBodyMetadataThroughFakeVault()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);

        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });

        var result = await tn.Vault.RestoreBodyWithPassphraseAsync(new VaultRestoreBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });

        Assert.Equal("proj_123", result.ProjectId);
        Assert.True(result.BodyMemberCount >= 3);
        Assert.True(result.TotalBodyBytes > 0);
        Assert.Contains("body/tn.yaml", result.BodyMemberNames);
        Assert.Contains("body/keys/local.private", result.BodyMemberNames);
        Assert.Contains("body/keys/local.public", result.BodyMemberNames);
        Assert.NotNull(result.WrappedKey);
        Assert.NotNull(result.EncryptedBlobResponse);
        Assert.Equal("Bearer jwt-123", vault.LastAuthorization);
    }

    [Fact]
    public async Task WalletRestoreAsyncInstallsBodyIntoTargetDirectory()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);
        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-" + Guid.NewGuid().ToString("N"));

        var result = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
            TargetDirectory = target,
        });

        Assert.Equal("proj_123", result.ProjectId);
        Assert.Equal(Path.GetFullPath(target), result.TargetDirectory);
        Assert.Equal(Path.Combine(Path.GetFullPath(target), "tn.yaml"), result.YamlPath);
        Assert.Equal(Path.Combine(Path.GetFullPath(target), "keys"), result.KeysDirectory);
        Assert.True(File.Exists(result.YamlPath));
        Assert.True(File.Exists(Path.Combine(result.KeysDirectory, "local.private")));
        Assert.True(File.Exists(Path.Combine(result.KeysDirectory, "local.public")));
        Assert.Contains("body/tn.yaml", result.BodyMemberNames);
        Assert.Contains(result.YamlPath, result.WrittenPaths);
        Assert.NotNull(result.WrappedKey);
        Assert.NotNull(result.EncryptedBlobResponse);
    }

    [Fact]
    public async Task WalletRestoreAsyncCanUseCachedAccountKey()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);
        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-identity-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-cached-" + Guid.NewGuid().ToString("N"));

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await BindAccountStateAsync(tn.YamlPath, "acct_123");
            await AccountCredentialStore.Default().SetAccountAwkAsync("acct_123", AccountAwkBytes());

            var result = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                VaultBaseUrl = vault.BaseUrl,
                BearerToken = "jwt-123",
                ProjectId = "proj_123",
                UseCachedAccountKey = true,
                TargetDirectory = target,
            });

            Assert.Equal("proj_123", result.ProjectId);
            Assert.Equal(Path.Combine(Path.GetFullPath(target), "tn.yaml"), result.YamlPath);
            Assert.True(File.Exists(result.YamlPath));
            Assert.True(File.Exists(Path.Combine(result.KeysDirectory, "local.private")));
            Assert.NotNull(result.WrappedKey);
            Assert.NotNull(result.EncryptedBlobResponse);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task WalletRestoreAsyncCachedAccountKeyCanUseExplicitAccountId()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);
        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-identity-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-explicit-cache-" + Guid.NewGuid().ToString("N"));

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await AccountCredentialStore.Default().SetAccountAwkAsync("acct_456", AccountAwkBytes());

            var result = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                VaultBaseUrl = vault.BaseUrl,
                BearerToken = "jwt-123",
                ProjectId = "proj_123",
                UseCachedAccountKey = true,
                AccountId = "acct_456",
                TargetDirectory = target,
            });

            Assert.Equal("proj_123", result.ProjectId);
            Assert.True(File.Exists(result.YamlPath));
            Assert.True(File.Exists(Path.Combine(result.KeysDirectory, "local.public")));
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task WalletRestoreAsyncCachedAccountKeyUsesLinkedVaultAndProjectFallback()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);
        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });
        await tn.Vault.LinkAsync(vault.BaseUrl, "proj_123");
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-identity-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-linked-cache-" + Guid.NewGuid().ToString("N"));

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await BindAccountStateAsync(tn.YamlPath, "acct_123");
            await AccountCredentialStore.Default().SetAccountAwkAsync("acct_123", AccountAwkBytes());

            var result = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                BearerToken = "jwt-123",
                UseCachedAccountKey = true,
                TargetDirectory = target,
            });

            Assert.Equal("proj_123", result.ProjectId);
            Assert.True(File.Exists(result.YamlPath));
            Assert.Equal("Bearer jwt-123", vault.LastAuthorization);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task WalletRestoreAsyncCachedAccountKeyRequiresCachedMaterial()
    {
        await using var tn = await CreateProjectAsync();
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-identity-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-missing-cache-" + Guid.NewGuid().ToString("N"));

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await BindAccountStateAsync(tn.YamlPath, "acct_123");

            var error = await Assert.ThrowsAsync<TnException>(() => tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                ProjectId = "proj_123",
                UseCachedAccountKey = true,
                TargetDirectory = target,
            }));

            Assert.Contains("cached account key not found", error.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(target, "tn.yaml")));
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task WalletRestoreAsyncCachedAccountKeyRejectsMalformedCachedMaterialBeforeNetwork()
    {
        await using var tn = await CreateProjectAsync();
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-identity-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-bad-cache-" + Guid.NewGuid().ToString("N"));

        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await BindAccountStateAsync(tn.YamlPath, "acct_123");
            await AccountCredentialStore.Default()
                .SetAsync(AccountCredentialStore.AwkKeyName("acct_123"), new byte[31]);

            var error = await Assert.ThrowsAsync<TnException>(() => tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                ProjectId = "proj_123",
                UseCachedAccountKey = true,
                TargetDirectory = target,
            }));

            Assert.Contains("cached account key not found", error.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(target, "tn.yaml")));
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task WalletRestoreAsyncWrongPassphraseDoesNotInstallPartialState()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);
        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-wrong-" + Guid.NewGuid().ToString("N"));

        await Assert.ThrowsAsync<TnException>(() =>
            tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                VaultBaseUrl = vault.BaseUrl,
                BearerToken = "jwt-123",
                ProjectId = "proj_123",
                Passphrase = "wrong passphrase",
                TargetDirectory = target,
            }));

        Assert.False(File.Exists(Path.Combine(target, "tn.yaml")));
        Assert.False(Directory.Exists(Path.Combine(target, "keys")));
    }

    [Fact]
    public async Task WalletRestoreAsyncRefusesDifferentExistingFilesWithoutOverwrite()
    {
        const string passphrase = "correct horse battery staple";
        var credential = BuildCredentialWrap(passphrase);
        await using var tn = await CreateProjectAsync();
        using var vault = await FakeBodyPushVault.StartAsync(credential);
        await tn.Vault.PushBodyWithPassphraseAsync(new VaultPushBodyWithPassphraseOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
        });
        var target = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-restore-conflict-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(target);
        await File.WriteAllTextAsync(Path.Combine(target, "tn.yaml"), "different");

        await Assert.ThrowsAsync<TnException>(() =>
            tn.Wallet.RestoreAsync(new WalletRestoreOptions
            {
                VaultBaseUrl = vault.BaseUrl,
                BearerToken = "jwt-123",
                ProjectId = "proj_123",
                Passphrase = passphrase,
                TargetDirectory = target,
            }));

        var restored = await tn.Wallet.RestoreAsync(new WalletRestoreOptions
        {
            VaultBaseUrl = vault.BaseUrl,
            BearerToken = "jwt-123",
            ProjectId = "proj_123",
            Passphrase = passphrase,
            TargetDirectory = target,
            Overwrite = true,
        });

        Assert.Equal(Path.Combine(Path.GetFullPath(target), "tn.yaml"), restored.YamlPath);
        Assert.Contains(restored.YamlPath, restored.WrittenPaths);
        Assert.NotEqual("different", await File.ReadAllTextAsync(restored.YamlPath));
    }

    private static Task<Tn> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-" + Guid.NewGuid().ToString("N"));
        return Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir });
    }

    private static JsonObject BuildCredentialWrap(string passphrase)
    {
        var salt = Enumerable.Range(0, 16).Select(i => (byte)(i + 1)).ToArray();
        var awk = AccountAwkBytes();
        var nonce = Enumerable.Range(0, 12).Select(i => (byte)(i + 65)).ToArray();
        var credentialKey = Rfc2898DeriveBytes.Pbkdf2(
            passphrase,
            salt,
            10_000,
            HashAlgorithmName.SHA256,
            32);
        var wrapped = AesGcmEncryptConcatTag(
            credentialKey,
            nonce,
            awk,
            Encoding.ASCII.GetBytes("tn-vault-awk-wrap-v1"));

        return new JsonObject
        {
            ["id"] = "cred_123",
            ["is_primary"] = true,
            ["kdf"] = "pbkdf2-sha256",
            ["kdf_params"] = new JsonObject
            {
                ["salt_b64"] = Convert.ToBase64String(salt),
                ["iterations"] = 10_000,
            },
            ["wrapped_account_key_b64"] = Convert.ToBase64String(wrapped),
            ["wrap_nonce_b64"] = Convert.ToBase64String(nonce),
        };
    }

    private static byte[] AccountAwkBytes()
    {
        return Enumerable.Range(0, 32).Select(i => (byte)(i + 33)).ToArray();
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

    private static byte[] AesGcmEncryptConcatTag(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return [.. ciphertext, .. tag];
    }

    private sealed class FakeBodyPushVault : IDisposable
    {
        private readonly System.Net.Sockets.TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;
        private readonly JsonObject _credential;
        private readonly int _port;
        private JsonObject? _wrappedKey;
        private JsonObject? _encryptedBlob;

        private FakeBodyPushVault(System.Net.Sockets.TcpListener listener, JsonObject credential, int port)
        {
            _listener = listener;
            _credential = credential;
            _port = port;
            BaseUrl = $"http://127.0.0.1:{port}";
            _loop = Task.Run(ListenAsync);
        }

        public string BaseUrl { get; }

        public JsonObject? WrappedKeyPut { get; private set; }

        public JsonObject? EncryptedBlobPut { get; private set; }

        public string? LastAuthorization { get; private set; }

        public string? LastIfMatch { get; private set; }

        public static Task<FakeBodyPushVault> StartAsync(JsonObject credential)
        {
            var port = FreePort();
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, port);
            listener.Start();
            return Task.FromResult(new FakeBodyPushVault(listener, credential, port));
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            try
            {
                _loop.Wait(TimeSpan.FromSeconds(2));
            }
            catch (AggregateException)
            {
            }

            _cts.Dispose();
        }

        private async Task ListenAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                System.Net.Sockets.TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        await HandleAsync(client).ConfigureAwait(false);
                    }
                });
            }
        }

        private async Task HandleAsync(System.Net.Sockets.TcpClient client)
        {
            var stream = client.GetStream();
            var request = await ReadRequestAsync(stream).ConfigureAwait(false);
            LastAuthorization = request.Headers.TryGetValue("Authorization", out var auth)
                ? auth
                : LastAuthorization;

            if (request.Method == "GET" && request.Path == "/api/v1/account/credentials")
            {
                await WriteJsonAsync(stream, new JsonArray(_credential.DeepClone())).ConfigureAwait(false);
                return;
            }

            if (request.Method == "GET" && request.Path == "/api/v1/projects/proj_123/wrapped-key")
            {
                if (_wrappedKey is null)
                {
                    await WriteStatusAsync(stream, 404, "Not Found").ConfigureAwait(false);
                    return;
                }

                await WriteJsonAsync(stream, _wrappedKey.DeepClone()).ConfigureAwait(false);
                return;
            }

            if (request.Method == "PUT" && request.Path == "/api/v1/projects/proj_123/wrapped-key")
            {
                WrappedKeyPut = JsonNode.Parse(request.Body) as JsonObject
                    ?? throw new InvalidOperationException("wrapped-key request body was not JSON object");
                _wrappedKey = WrappedKeyPut.DeepClone() as JsonObject
                    ?? throw new InvalidOperationException("wrapped-key clone was not JSON object");
                await WriteJsonAsync(stream, WrappedKeyPut.DeepClone()).ConfigureAwait(false);
                return;
            }

            if (request.Method == "GET" && request.Path == "/api/v1/projects/proj_123/encrypted-blob")
            {
                if (_encryptedBlob is null)
                {
                    await WriteStatusAsync(stream, 404, "Not Found").ConfigureAwait(false);
                    return;
                }

                await WriteJsonAsync(stream, _encryptedBlob.DeepClone()).ConfigureAwait(false);
                return;
            }

            if (request.Method == "PUT" && request.Path == "/api/v1/projects/proj_123/encrypted-blob-account")
            {
                LastIfMatch = request.Headers.GetValueOrDefault("If-Match");
                EncryptedBlobPut = JsonNode.Parse(request.Body) as JsonObject
                    ?? throw new InvalidOperationException("encrypted-blob request body was not JSON object");
                _encryptedBlob = EncryptedBlobPut.DeepClone() as JsonObject
                    ?? throw new InvalidOperationException("encrypted-blob clone was not JSON object");
                await WriteJsonAsync(stream, new JsonObject
                {
                    ["project_id"] = "proj_123",
                    ["generation"] = 1,
                    ["stored"] = true,
                }).ConfigureAwait(false);
                return;
            }

            await WriteStatusAsync(stream, 404, "Not Found").ConfigureAwait(false);
        }

        private static async Task<HttpRequest> ReadRequestAsync(NetworkStream stream)
        {
            var buffer = new List<byte>();
            var temp = new byte[1];
            while (true)
            {
                var read = await stream.ReadAsync(temp).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                buffer.Add(temp[0]);
                if (buffer.Count >= 4
                    && buffer[^4] == '\r'
                    && buffer[^3] == '\n'
                    && buffer[^2] == '\r'
                    && buffer[^1] == '\n')
                {
                    break;
                }
            }

            var headerText = Encoding.ASCII.GetString(buffer.ToArray());
            var lines = headerText.Split("\r\n", StringSplitOptions.None);
            var requestLine = lines[0].Split(' ');
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in lines.Skip(1))
            {
                if (string.IsNullOrEmpty(line))
                {
                    continue;
                }

                var colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon > 0)
                {
                    headers[line[..colon]] = line[(colon + 1)..].Trim();
                }
            }

            var contentLength = headers.TryGetValue("Content-Length", out var lengthText)
                && int.TryParse(lengthText, out var length)
                    ? length
                    : 0;
            var body = new byte[contentLength];
            var offset = 0;
            while (offset < contentLength)
            {
                var read = await stream.ReadAsync(body.AsMemory(offset, contentLength - offset)).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                offset += read;
            }

            return new HttpRequest(
                requestLine[0],
                requestLine[1].Split('?')[0],
                headers,
                Encoding.UTF8.GetString(body, 0, offset));
        }

        private static async Task WriteJsonAsync(NetworkStream stream, JsonNode node)
        {
            var bytes = Encoding.UTF8.GetBytes(node.ToJsonString());
            var header = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(header).ConfigureAwait(false);
            await stream.WriteAsync(bytes).ConfigureAwait(false);
        }

        private static async Task WriteStatusAsync(NetworkStream stream, int statusCode, string reason)
        {
            var header = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {statusCode} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(header).ConfigureAwait(false);
        }

        private static int FreePort()
        {
            using var socket = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            return ((IPEndPoint)socket.LocalEndpoint).Port;
        }

        private sealed record HttpRequest(
            string Method,
            string Path,
            IReadOnlyDictionary<string, string> Headers,
            string Body);
    }
}
