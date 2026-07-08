using System.Text.Json.Nodes;
using System.Net;
using System.Text;
using TnProto.Wallet;

namespace TnProto.Tests;

public sealed class WalletTests
{
    [Fact]
    public async Task StatusAsyncReportsFreshProjectAsLocalOnly()
    {
        await using var tn = await CreateProjectAsync();

        var status = await tn.Wallet.StatusAsync();

        Assert.Equal(WalletVerdict.LocalOnly, status.Verdict);
        Assert.Equal("local_only", status.VerdictName);
        Assert.False(status.Account.AccountBound);
        Assert.Equal("local", status.Vault.StateName);
        Assert.Null(status.PendingClaim);
        Assert.Empty(status.Warnings);
    }

    [Fact]
    public async Task StatusAsyncReportsPendingClaim()
    {
        await using var tn = await CreateProjectAsync();
        await WritePendingClaimAsync(tn, DateTimeOffset.UtcNow.AddHours(1));

        var status = await tn.Wallet.StatusAsync();

        Assert.Equal(WalletVerdict.PendingClaim, status.Verdict);
        Assert.Equal("pending_claim", status.VerdictName);
        Assert.NotNull(status.PendingClaim);
        Assert.False(status.PendingClaim.Expired);
        Assert.Equal("vault_123", status.PendingClaim.VaultId);
    }

    [Fact]
    public async Task StatusAsyncReportsExpiredPendingClaimAsRepair()
    {
        await using var tn = await CreateProjectAsync();
        await WritePendingClaimAsync(tn, DateTimeOffset.UtcNow.AddHours(-1));

        var status = await tn.Wallet.StatusAsync();

        Assert.Equal(WalletVerdict.NeedsRepair, status.Verdict);
        Assert.NotNull(status.PendingClaim);
        Assert.True(status.PendingClaim.Expired);
        Assert.Contains("pending claim is expired", status.Warnings);
    }

    [Fact]
    public async Task StatusAsyncReportsLinkedVault()
    {
        await using var tn = await CreateProjectAsync();
        await tn.Vault.LinkAsync("https://vault.example.test", "proj_123");

        var status = await tn.Wallet.StatusAsync();

        Assert.Equal(WalletVerdict.Linked, status.Verdict);
        Assert.Equal("linked", status.VerdictName);
        Assert.Equal("https://vault.example.test", status.Vault.LinkedVault);
        Assert.Equal("proj_123", status.Vault.LinkedProjectId);
    }

    [Fact]
    public async Task StageInboxAsyncReturnsNotBoundWhenAccountIsNotBound()
    {
        await using var tn = await CreateProjectAsync();

        var result = await tn.Wallet.StageInboxAsync(new WalletStageInboxOptions
        {
            VaultBaseUrl = "https://vault.example.test",
        });

        Assert.True(result.NotBound);
        Assert.Empty(result.StagedPaths);
    }

    [Fact]
    public async Task StageInboxAsyncDownloadsUnconsumedPackages()
    {
        await using var tn = await CreateProjectAsync();
        await MarkAccountBoundAsync(tn);
        await tn.Vault.LinkAsync("https://vault.example.test", "proj_123");
        using var http = new HttpClient(new FakeHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/account/inbox")
            {
                return Task.FromResult(JsonResponse(
                    """
                    {
                      "items": [
                        {"publisher_identity":"did:key:zPublisher","ceremony_id":"local_abc","ts":"20260101T010203Z"},
                        {"publisher_identity":"did:key:zSkip","ceremony_id":"local_abc","ts":"20260101T010204Z","consumed_at":"2026-01-01T00:00:00Z"}
                      ]
                    }
                    """));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent("tnpkg bytes"u8.ToArray()),
            });
        }));

        var result = await tn.Wallet.StageInboxAsync(new WalletStageInboxOptions
        {
            HttpClient = http,
            BearerToken = "jwt-123",
        });

        var path = Assert.Single(result.StagedPaths);
        Assert.False(result.NotBound);
        Assert.False(result.Unauthorized);
        Assert.Equal(1, result.Skipped);
        Assert.EndsWith(Path.Combine("did_key_zPublisher", "local_abc", "20260101T010203Z.tnpkg"), path, StringComparison.Ordinal);
        Assert.Equal("tnpkg bytes"u8.ToArray(), await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task StageInboxAsyncReturnsUnauthorizedForVaultAuthFailure()
    {
        await using var tn = await CreateProjectAsync();
        await MarkAccountBoundAsync(tn);
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("""{"error":"unauthorized"}""", Encoding.UTF8, "application/json"),
        })));

        var result = await tn.Wallet.StageInboxAsync(new WalletStageInboxOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.True(result.Unauthorized);
        Assert.Empty(result.StagedPaths);
    }

    [Fact]
    public async Task PullAndAbsorbAsyncAppliesExistingInboxPackages()
    {
        await using var recipient = await CreateProjectAsync();
        await MarkAccountBoundAsync(recipient);
        var packagePath = await CreateRecipientPackageAsync(recipient.Did);
        var inboxPath = Path.Combine(
            Path.GetDirectoryName(recipient.YamlPath)!,
            ".tn",
            "inbox",
            "did_key_zProducer",
            "local_abc",
            "20260101T010203Z.tnpkg");
        Directory.CreateDirectory(Path.GetDirectoryName(inboxPath)!);
        File.Copy(packagePath, inboxPath);
        using var http = new HttpClient(new FakeHandler(request =>
        {
            Assert.Equal("/api/v1/account/inbox", request.RequestUri?.AbsolutePath);
            return Task.FromResult(JsonResponse("""{"items":[]}"""));
        }));

        var result = await recipient.Wallet.PullAndAbsorbAsync(new WalletPullOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.False(result.Stage.NotBound);
        Assert.False(result.Stage.Unauthorized);
        Assert.Empty(result.Stage.StagedPaths);
        Assert.Equal(1, result.AbsorbedPackageCount);
        Assert.Equal(1UL, result.AcceptedCount);
        Assert.Equal(0, result.RejectedCount);
        Assert.Empty(result.RejectedPaths);
    }

    [Fact]
    public async Task PullAndAbsorbAsyncReportsDuplicateInboxPackagesAsDeduped()
    {
        await using var recipient = await CreateProjectAsync();
        await MarkAccountBoundAsync(recipient);
        var packagePath = await CreateRecipientPackageAsync(recipient.Did);
        var inboxPath = Path.Combine(
            Path.GetDirectoryName(recipient.YamlPath)!,
            ".tn",
            "inbox",
            "did_key_zProducer",
            "local_abc",
            "20260101T010203Z.tnpkg");
        Directory.CreateDirectory(Path.GetDirectoryName(inboxPath)!);
        File.Copy(packagePath, inboxPath);
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(JsonResponse("""{"items":[]}"""))));
        var options = new WalletPullOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        };

        _ = await recipient.Wallet.PullAndAbsorbAsync(options);
        var duplicate = await recipient.Wallet.PullAndAbsorbAsync(options);

        Assert.Equal(1, duplicate.AbsorbedPackageCount);
        Assert.Equal(0UL, duplicate.AcceptedCount);
        Assert.True(duplicate.DedupedCount > 0);
        Assert.Equal(0, duplicate.RejectedCount);
    }

    [Fact]
    public async Task PullAndAbsorbAsyncReturnsNotBoundWithoutAbsorbing()
    {
        await using var tn = await CreateProjectAsync();

        var result = await tn.Wallet.PullAndAbsorbAsync(new WalletPullOptions
        {
            VaultBaseUrl = "https://vault.example.test",
        });

        Assert.True(result.Stage.NotBound);
        Assert.Equal(0, result.AbsorbedPackageCount);
    }

    [Fact]
    public async Task PullPrefsAsyncFetchesAndPersistsAccountPreferences()
    {
        await using var tn = await CreateProjectAsync();
        await SeedPrefsStateAsync(tn);
        string? authorization = null;
        using var http = new HttpClient(new FakeHandler(request =>
        {
            Assert.Equal("/api/v1/account/prefs", request.RequestUri?.AbsolutePath);
            authorization = request.Headers.Authorization?.ToString();
            return Task.FromResult(JsonResponse(
                """
                {
                  "default_new_ceremony_mode": "linked",
                  "prefs_version": 7
                }
                """));
        }));

        var result = await tn.Wallet.PullPrefsAsync(new WalletPullPrefsOptions
        {
            VaultBaseUrl = "https://vault.example.test/",
            BearerToken = "jwt-123",
            HttpClient = http,
        });
        var state = JsonNode.Parse(await File.ReadAllTextAsync(SyncStatePath(tn))) as JsonObject
            ?? throw new InvalidOperationException("state was not JSON object");
        var prefs = state["prefs"] as JsonObject
            ?? throw new InvalidOperationException("state prefs was not JSON object");

        Assert.Equal("https://vault.example.test", result.VaultBaseUrl);
        Assert.Equal("linked", result.DefaultNewCeremonyMode);
        Assert.Equal(7UL, result.PrefsVersion);
        Assert.Equal("Bearer jwt-123", authorization);
        Assert.Equal("linked", prefs["default_new_ceremony_mode"]?.GetValue<string>());
        Assert.Equal("keepme", prefs["some_future_field"]?.GetValue<string>());
        Assert.Equal(7UL, state["prefs_version"]?.GetValue<ulong>());
    }

    [Fact]
    public async Task PullPrefsAsyncFallsBackToLinkedVault()
    {
        await using var tn = await CreateProjectAsync();
        await tn.Vault.LinkAsync("https://vault.example.test", "proj_123");
        using var http = new HttpClient(new FakeHandler(request =>
        {
            Assert.Equal("https://vault.example.test/api/v1/account/prefs", request.RequestUri?.ToString());
            return Task.FromResult(JsonResponse(
                """
                {
                  "default_new_ceremony_mode": "per-recipient",
                  "prefs_version": "9"
                }
                """));
        }));

        var result = await tn.Wallet.PullPrefsAsync(new WalletPullPrefsOptions
        {
            HttpClient = http,
        });

        Assert.Equal("per-recipient", result.DefaultNewCeremonyMode);
        Assert.Equal(9UL, result.PrefsVersion);
    }

    [Fact]
    public async Task PullPrefsAsyncRequiresVaultUrlOrLinkedVault()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<TnException>(() =>
            tn.Wallet.PullPrefsAsync());

        Assert.Contains("requires a vault URL", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PublishGroupKeysAsyncPostsGroupKeySnapshot()
    {
        await using var tn = await CreateProjectAsync();
        await tn.Admin.EnsureGroupAsync("partners", ["partner_id"]);
        byte[]? postedBody = null;
        string? contentType = null;
        string? requestPath = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            requestPath = request.RequestUri?.AbsolutePath;
            contentType = request.Content?.Headers.ContentType?.MediaType;
            postedBody = await request.Content!.ReadAsByteArrayAsync();
            return JsonResponse(
                """
                {
                  "stored_path": "inbox/group-keys.tnpkg",
                  "byte_size": 123,
                  "manifest_signature_b64": "sig-123"
                }
                """);
        }));

        var result = await tn.Wallet.PublishGroupKeysAsync(new WalletPublishGroupKeysOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            BearerToken = "jwt-123",
            HttpClient = http,
            Groups = ["partners"],
            Timestamp = "20260101T010203000000Z",
        });

        Assert.True(result.Published);
        Assert.Null(result.PackagePath);
        Assert.Equal(["partners"], result.RequestedGroups);
        Assert.NotNull(result.Snapshot);
        Assert.Equal("inbox/group-keys.tnpkg", result.Snapshot.StoredPath);
        Assert.Equal("application/octet-stream", contentType);
        Assert.NotNull(postedBody);
        Assert.True(postedBody.Length > 0);
        Assert.Contains("/api/v1/inbox/did%3Akey%3A", requestPath, StringComparison.Ordinal);
        Assert.EndsWith("/20260101T010203000000Z.tnpkg", requestPath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PublishGroupKeysAsyncSkipsWhenNoGroupsExist()
    {
        await using var tn = await CreateProjectAsync();
        using var http = new HttpClient(new FakeHandler(_ =>
            throw new InvalidOperationException("no group material should avoid HTTP upload")));

        var result = await tn.Wallet.PublishGroupKeysAsync(new WalletPublishGroupKeysOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
            Groups = ["missing_group"],
        });

        Assert.False(result.Published);
        Assert.Null(result.Snapshot);
    }

    [Fact]
    public async Task SyncAsyncPullOnlyStopsAfterPull()
    {
        await using var tn = await CreateProjectAsync();
        await MarkAccountBoundAsync(tn);
        using var http = new HttpClient(new FakeHandler(request =>
        {
            Assert.Equal("/api/v1/account/inbox", request.RequestUri?.AbsolutePath);
            return Task.FromResult(JsonResponse("""{"items":[]}"""));
        }));

        var result = await tn.Wallet.SyncAsync(new WalletSyncOptions
        {
            PullOnly = true,
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.NotNull(result.Pull);
        Assert.Null(result.GroupKeys);
        Assert.Null(result.BodyPush);
        Assert.False(result.Pushed);
    }

    [Fact]
    public async Task SyncAsyncPullsAndPublishesGroupKeys()
    {
        await using var tn = await CreateProjectAsync();
        await MarkAccountBoundAsync(tn);
        await tn.Admin.EnsureGroupAsync("partners", ["partner_id"]);
        var calls = new List<string>();
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            calls.Add($"{request.Method} {request.RequestUri?.AbsolutePath}");
            if (request.RequestUri?.AbsolutePath == "/api/v1/account/inbox")
            {
                return JsonResponse("""{"items":[]}""");
            }

            if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath.StartsWith("/api/v1/inbox/", StringComparison.Ordinal) == true)
            {
                var body = await request.Content!.ReadAsByteArrayAsync();
                Assert.True(body.Length > 0);
                return JsonResponse(
                    """
                    {
                      "stored_path": "inbox/group-keys.tnpkg",
                      "byte_size": 123,
                      "manifest_signature_b64": "sig-123"
                    }
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var result = await tn.Wallet.SyncAsync(new WalletSyncOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
            Groups = ["partners"],
            Timestamp = "20260101T010203000000Z",
        });

        Assert.NotNull(result.Pull);
        Assert.NotNull(result.GroupKeys);
        Assert.True(result.GroupKeys.Published);
        Assert.Null(result.BodyPush);
        Assert.Contains("GET /api/v1/account/inbox", calls);
        Assert.Contains(calls, call => call.StartsWith("POST /api/v1/inbox/", StringComparison.Ordinal));
    }

    private static Task<Tn> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-" + Guid.NewGuid().ToString("N"));
        return Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir });
    }

    private static async Task WritePendingClaimAsync(Tn tn, DateTimeOffset expiresAt)
    {
        var syncDir = Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "sync");
        Directory.CreateDirectory(syncDir);
        var state = new JsonObject
        {
            ["pending_claim"] = new JsonObject
            {
                ["vault_id"] = "vault_123",
                ["expires_at"] = expiresAt.ToString("O"),
                ["claim_url"] = "https://vault.example.test/claim/vault_123#k=abc",
                ["password_b64"] = "abc",
            },
        };
        await File.WriteAllTextAsync(Path.Combine(syncDir, "state.json"), state.ToJsonString());
    }

    private static async Task SeedPrefsStateAsync(Tn tn)
    {
        var syncDir = Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "sync");
        Directory.CreateDirectory(syncDir);
        var state = new JsonObject
        {
            ["account_id"] = "acct_123",
            ["account_bound"] = true,
            ["prefs"] = new JsonObject
            {
                ["default_new_ceremony_mode"] = "local",
                ["some_future_field"] = "keepme",
            },
        };
        await File.WriteAllTextAsync(Path.Combine(syncDir, "state.json"), state.ToJsonString());
    }

    private static string SyncStatePath(Tn tn)
    {
        return Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "sync", "state.json");
    }

    private static async Task MarkAccountBoundAsync(Tn tn)
    {
        var syncDir = Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "sync");
        Directory.CreateDirectory(syncDir);
        var state = new JsonObject
        {
            ["account_id"] = "acct_123",
            ["account_bound"] = true,
        };
        await File.WriteAllTextAsync(Path.Combine(syncDir, "state.json"), state.ToJsonString());
    }

    private static async Task<string> CreateRecipientPackageAsync(string recipientDid)
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-wallet-producer-" + Guid.NewGuid().ToString("N"));
        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        var packagePath = Path.Combine(producerDir, "recipient.tnpkg");
        await producer.Packages.BundleForRecipientAsync(
            recipientDid,
            packagePath,
            new Packages.BundleForRecipientOptions { Groups = ["default"] });
        return packagePath;
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return handler(request);
        }
    }
}
