using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using TnProto.Vault;

namespace TnProto.Tests;

public sealed class VaultHttpTests
{
    [Fact]
    public async Task AuthenticateAsyncRunsDidChallengeAndCachesBearerToken()
    {
        var seed = Enumerable.Repeat((byte)42, 32).ToArray();
        var identity = TnIdentity.FromSeed(seed);
        JsonObject? challengeBody = null;
        JsonObject? verifyBody = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                challengeBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync()) as JsonObject;
                return JsonResponse("""{"nonce":"nonce-123"}""");
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                verifyBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync()) as JsonObject;
                return JsonResponse("""{"token":"jwt-123"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        var token = await client.AuthenticateAsync(identity.Did, seed);

        Assert.Equal("jwt-123", token);
        Assert.Equal("jwt-123", client.BearerToken);
        Assert.Equal(identity.Did, challengeBody?["did"]?.GetValue<string>());
        Assert.Equal(identity.Did, verifyBody?["did"]?.GetValue<string>());
        Assert.Equal("nonce-123", verifyBody?["nonce"]?.GetValue<string>());
        var signature = verifyBody?["signature"]?.GetValue<string>()
            ?? throw new InvalidOperationException("verify request omitted signature");
        Assert.True(TnIdentity.VerifyDid(identity.Did, Encoding.UTF8.GetBytes("nonce-123"), signature));
    }

    [Fact]
    public async Task CreateProjectAsyncPostsProjectBody()
    {
        JsonObject? requestBody = null;
        string? auth = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            auth = request.Headers.Authorization?.ToString();
            requestBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync()) as JsonObject;
            return JsonResponse("""{"id":"proj_123","name":"Payments","ceremony_id":"local_abc"}""");
        }));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test/",
            BearerToken = "token-123",
            HttpClient = http,
        });

        var project = await client.CreateProjectAsync("Payments", "local_abc");

        Assert.Equal("https://vault.example.test", client.BaseUrl);
        Assert.Equal("Bearer token-123", auth);
        Assert.Equal("Payments", requestBody?["name"]?.GetValue<string>());
        Assert.Equal("local_abc", requestBody?["ceremony_id"]?.GetValue<string>());
        Assert.Equal("proj_123", project.Id);
        Assert.Equal("Payments", project.Name);
        Assert.Equal("local_abc", project.CeremonyId);
    }

    [Fact]
    public async Task ListProjectsAsyncParsesIdFallbacks()
    {
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(JsonResponse(
            """[{"_id":"proj_123","name":"Payments"},{"id":"proj_456"}]"""))));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        var projects = await client.ListProjectsAsync();

        Assert.Equal(2, projects.Count);
        Assert.Equal("proj_123", projects[0].Id);
        Assert.Equal("Payments", projects[0].Name);
        Assert.Equal("proj_456", projects[1].Id);
        Assert.Equal("proj_456", projects[1].Name);
    }

    [Fact]
    public async Task EnsureProjectAsyncFallsBackToListOnConflict()
    {
        var calls = new List<string>();
        using var http = new HttpClient(new FakeHandler(request =>
        {
            calls.Add($"{request.Method} {request.RequestUri?.AbsolutePath}");
            if (request.Method == HttpMethod.Post)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Conflict)
                {
                    Content = new StringContent("""{"error":"exists"}""", Encoding.UTF8, "application/json"),
                });
            }

            return Task.FromResult(JsonResponse("""[{"id":"proj_123","name":"Payments"}]"""));
        }));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        var project = await client.EnsureProjectAsync("Payments");

        Assert.Equal("proj_123", project.Id);
        Assert.Equal(["POST /api/v1/projects", "GET /api/v1/projects"], calls);
    }

    [Fact]
    public async Task CreateProjectAsyncRejectsMalformedProjectResponse()
    {
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(JsonResponse("""{"name":"missing id"}"""))));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        var error = await Assert.ThrowsAsync<VaultException>(() => client.CreateProjectAsync("Payments"));

        Assert.Contains("missing id", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConnectAsyncEnsuresProjectAndLinksLocalYaml()
    {
        await using var tn = await CreateProjectAsync();
        JsonObject? requestBody = null;
        string? auth = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                return JsonResponse("""{"nonce":"nonce-123"}""");
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                return JsonResponse("""{"token":"jwt-123"}""");
            }

            auth = request.Headers.Authorization?.ToString();
            requestBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync()) as JsonObject;
            return JsonResponse("""{"id":"proj_123","name":"Payments"}""");
        }));

        var result = await tn.Vault.ConnectAsync(new VaultConnectOptions
        {
            VaultBaseUrl = "https://vault.example.test/",
            HttpClient = http,
        });

        Assert.Equal("Bearer jwt-123", auth);
        Assert.Equal("payments", requestBody?["name"]?.GetValue<string>());
        Assert.StartsWith("local_", requestBody?["ceremony_id"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.Equal("https://vault.example.test", result.VaultBaseUrl);
        Assert.Equal("proj_123", result.Project.Id);
        Assert.True(result.NewlyLinked);
        Assert.Equal("linked", result.State.StateName);
        Assert.Equal("https://vault.example.test", result.State.LinkedVault);
        Assert.Equal("proj_123", result.State.LinkedProjectId);
    }

    [Fact]
    public async Task InitUploadAsyncPostsEncryptedPackageAndPersistsClaimSurfaces()
    {
        await using var tn = await CreateProjectAsync();
        byte[]? postedBody = null;
        string? contentType = null;
        string? projectHeader = null;
        string? publisherHeader = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            postedBody = await request.Content!.ReadAsByteArrayAsync();
            contentType = request.Content.Headers.ContentType?.MediaType;
            projectHeader = request.Headers.TryGetValues("X-Project-Name", out var projectValues)
                ? projectValues.Single()
                : null;
            publisherHeader = request.Headers.TryGetValues("X-Publisher-Did", out var publisherValues)
                ? publisherValues.Single()
                : null;
            return JsonResponse($$"""{"vault_id":"vault_123","expires_at":"{{DateTimeOffset.UtcNow.AddHours(1):O}}"}""");
        }));

        var result = await tn.Vault.InitUploadAsync(new VaultInitUploadOptions
        {
            VaultBaseUrl = "https://vault.example.test/",
            HttpClient = http,
        });

        Assert.Equal("vault_123", result.VaultId);
        Assert.False(result.Reused);
        Assert.StartsWith("https://vault.example.test/claim/vault_123#k=", result.ClaimUrl, StringComparison.Ordinal);
        Assert.DoesNotContain("=", result.PasswordBase64Url, StringComparison.Ordinal);
        Assert.Equal("application/octet-stream", contentType);
        Assert.Equal("payments", projectHeader);
        Assert.Equal(tn.Did, publisherHeader);
        Assert.NotNull(postedBody);
        Assert.True(postedBody.Length > 0);

        var syncDir = Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "sync");
        var state = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(syncDir, "state.json"))) as JsonObject
            ?? throw new InvalidOperationException("sync state was not an object.");
        var pending = state["pending_claim"] as JsonObject
            ?? throw new InvalidOperationException("sync state omitted pending_claim.");
        Assert.Equal("vault_123", pending["vault_id"]?.GetValue<string>());
        Assert.Equal(result.ClaimUrl, pending["claim_url"]?.GetValue<string>());
        Assert.Equal(result.PasswordBase64Url, pending["password_b64"]?.GetValue<string>());
        Assert.Equal(result.ClaimUrl + Environment.NewLine, await File.ReadAllTextAsync(Path.Combine(syncDir, "claim_url.txt")));

        var outbox = Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "admin", "outbox");
        var eventPath = Directory.GetFiles(outbox, "claim_url_issued_*_vault_123.json").Single();
        var adminEvent = JsonNode.Parse(await File.ReadAllTextAsync(eventPath)) as JsonObject
            ?? throw new InvalidOperationException("claim event was not an object.");
        Assert.Equal("tn.vault.claim_url_issued", adminEvent["event_type"]?.GetValue<string>());
        Assert.Equal("https://vault.example.test/claim/vault_123#<redacted>", adminEvent["claim_url_redacted"]?.GetValue<string>());
    }

    [Fact]
    public async Task InitUploadAsyncReusesNonExpiredPendingClaim()
    {
        await using var tn = await CreateProjectAsync();
        var syncDir = Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, ".tn", "sync");
        Directory.CreateDirectory(syncDir);
        await File.WriteAllTextAsync(
            Path.Combine(syncDir, "state.json"),
            $$"""
            {
              "pending_claim": {
                "vault_id": "vault_existing",
                "expires_at": "{{DateTimeOffset.UtcNow.AddHours(1):O}}",
                "claim_url": "https://vault.example.test/claim/vault_existing#k=abc",
                "password_b64": "abc"
              }
            }
            """);
        using var http = new HttpClient(new FakeHandler(_ =>
            throw new InvalidOperationException("pending claim reuse should not hit HTTP")));

        var result = await tn.Vault.InitUploadAsync(new VaultInitUploadOptions
        {
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.True(result.Reused);
        Assert.Equal("vault_existing", result.VaultId);
        Assert.Equal("https://vault.example.test/claim/vault_existing#k=abc", result.ClaimUrl);
    }

    [Fact]
    public async Task ListAccountInboxAsyncParsesArrayAndDownloadsPackage()
    {
        var calls = new List<string>();
        using var http = new HttpClient(new FakeHandler(request =>
        {
            calls.Add($"{request.Method} {request.RequestUri?.AbsolutePath}");
            if (request.RequestUri?.AbsolutePath == "/api/v1/account/inbox")
            {
                return Task.FromResult(JsonResponse(
                    """[{"publisher_identity":"did:key:zPublisher","ceremony_id":"local_abc","ts":"20260101T010203Z"}]"""));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent("tnpkg bytes"u8.ToArray()),
            });
        }));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            BearerToken = "jwt-123",
            HttpClient = http,
        });

        var items = await client.ListAccountInboxAsync();
        var item = Assert.Single(items);
        var body = await client.DownloadAccountInboxPackageAsync(
            item.PublisherIdentity,
            item.CeremonyId,
            item.Timestamp);

        Assert.Equal("did:key:zPublisher", item.PublisherIdentity);
        Assert.Equal("local_abc", item.CeremonyId);
        Assert.Equal("20260101T010203Z", item.Timestamp);
        Assert.Equal("tnpkg bytes"u8.ToArray(), body);
        Assert.Equal(
            [
                "GET /api/v1/account/inbox",
                "GET /api/v1/account/inbox/did%3Akey%3AzPublisher/local_abc/20260101T010203Z.tnpkg",
            ],
            calls);
    }

    [Fact]
    public async Task DownloadAccountInboxPackageAsyncReturnsNullForStaleReferences()
    {
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound))));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        var body = await client.DownloadAccountInboxPackageAsync(
            "did:key:zPublisher",
            "local_abc",
            "20260101T010203Z");

        Assert.Null(body);
    }

    [Fact]
    public async Task PostInboxSnapshotAsyncPostsPackageBytesAndParsesResponse()
    {
        byte[]? postedBody = null;
        string? contentType = null;
        string? auth = null;
        string? path = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            path = request.RequestUri?.AbsolutePath;
            auth = request.Headers.Authorization?.ToString();
            contentType = request.Content?.Headers.ContentType?.MediaType;
            postedBody = await request.Content!.ReadAsByteArrayAsync();
            return JsonResponse(
                """
                {
                  "stored_path": "inbox/did_key_zPublisher/local_abc/20260101.tnpkg",
                  "byte_size": 11,
                  "manifest_signature_b64": "sig-123",
                  "head_row_hash": "hash-123"
                }
                """);
        }));
        using var client = new VaultHttpProjectClient(new VaultHttpClientOptions
        {
            BaseUrl = "https://vault.example.test",
            BearerToken = "jwt-123",
            HttpClient = http,
        });

        var snapshot = await client.PostInboxSnapshotAsync(
            "did:key:zPublisher",
            "local_abc",
            "20260101T010203Z",
            "tnpkg bytes"u8.ToArray());

        Assert.Equal("POST /api/v1/inbox/did%3Akey%3AzPublisher/snapshots/local_abc/20260101T010203Z.tnpkg", $"POST {path}");
        Assert.Equal("Bearer jwt-123", auth);
        Assert.Equal("application/octet-stream", contentType);
        Assert.Equal("tnpkg bytes"u8.ToArray(), postedBody);
        Assert.Equal("inbox/did_key_zPublisher/local_abc/20260101.tnpkg", snapshot.StoredPath);
        Assert.Equal(11UL, snapshot.ByteSize);
        Assert.Equal("sig-123", snapshot.ManifestSignatureBase64);
        Assert.Equal("hash-123", snapshot.HeadRowHash);
    }

    private static Task<Tn> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-vault-http-" + Guid.NewGuid().ToString("N"));
        return Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir });
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
