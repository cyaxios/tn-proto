using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace TnProto.Tests;

public sealed class ApiKeyBootstrapTests
{
    [Fact]
    public async Task BootstrapAsyncFetchesAndInstallsProjectSeed()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-api-key-bootstrap-" + Guid.NewGuid().ToString("N"));
        var sourceDir = Path.Combine(tempDir, "source");
        var targetDir = Path.Combine(tempDir, "target");
        var seed = Enumerable.Range(0, 32).Select(i => (byte)(200 - i)).ToArray();
        var keyIdBytes = Enumerable.Range(20, 16).Select(i => (byte)i).ToArray();
        var apiKey = BuildApiKey(seed, keyIdBytes);

        await using var source = await Tn.InitProjectAsync(
            "source",
            new TnProjectOptions
            {
                ProjectDirectory = sourceDir,
                DevicePrivateBytes = seed,
            });
        var packagePath = Path.Combine(tempDir, "source.project.tnpkg");
        await source.Packages.ExportProjectSeedAsync(packagePath);
        var packageBytes = await File.ReadAllBytesAsync(packagePath);

        using var http = new HttpClient(new FakeHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                return Task.FromResult(JsonResponse("""{"nonce":"nonce-bootstrap"}"""));
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                return Task.FromResult(JsonResponse("""{"token":"jwt-api-key"}"""));
            }

            return Task.FromResult(JsonResponse(
                $$"""{"sealed_bundle_b64":"{{Convert.ToBase64String(packageBytes)}}","kind":"project_seed"}"""));
        }));

        var result = await TnApiKeyBootstrap.BootstrapAsync(new TnApiKeyBootstrapOptions
        {
            ApiKey = apiKey,
            VaultBaseUrl = "https://vault.example.test",
            ProjectName = "restored",
            ProjectDirectory = targetDir,
            HttpClient = http,
        });

        Assert.NotNull(result);
        await using var restored = result.Project;
        Assert.True(result.Succeeded);
        Assert.False(result.Receipt.Rejected);
        Assert.Equal("project_seed", result.Kind);
        Assert.Equal(source.Did, restored.Did);
        Assert.Equal(seed, await File.ReadAllBytesAsync(Path.Combine(
            targetDir,
            ".tn",
            "restored",
            "keys",
            "local.private")));
        Assert.Contains(
            "project_name: source",
            await File.ReadAllTextAsync(Path.Combine(targetDir, ".tn", "restored", "tn.yaml")),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task BootstrapAsyncReturnsRejectedReceiptForWrongRecipientSeed()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-api-key-bootstrap-wrong-recipient-" + Guid.NewGuid().ToString("N"));
        var sourceDir = Path.Combine(tempDir, "source");
        var targetDir = Path.Combine(tempDir, "target");
        var sourceSeed = Enumerable.Range(0, 32).Select(i => (byte)(10 + i)).ToArray();
        var apiKeySeed = Enumerable.Range(0, 32).Select(i => (byte)(90 + i)).ToArray();
        var keyIdBytes = Enumerable.Range(120, 16).Select(i => (byte)i).ToArray();
        var apiKey = BuildApiKey(apiKeySeed, keyIdBytes);

        await using var source = await Tn.InitProjectAsync(
            "source",
            new TnProjectOptions
            {
                ProjectDirectory = sourceDir,
                DevicePrivateBytes = sourceSeed,
            });
        var packagePath = Path.Combine(tempDir, "source.project.tnpkg");
        await source.Packages.ExportProjectSeedAsync(packagePath);
        var packageBytes = await File.ReadAllBytesAsync(packagePath);

        using var http = new HttpClient(new FakeHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                return Task.FromResult(JsonResponse("""{"nonce":"nonce-bootstrap"}"""));
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                return Task.FromResult(JsonResponse("""{"token":"jwt-api-key"}"""));
            }

            return Task.FromResult(JsonResponse(
                $$"""{"sealed_bundle_b64":"{{Convert.ToBase64String(packageBytes)}}","kind":"project_seed"}"""));
        }));

        var result = await TnApiKeyBootstrap.BootstrapAsync(new TnApiKeyBootstrapOptions
        {
            ApiKey = apiKey,
            VaultBaseUrl = "https://vault.example.test",
            ProjectName = "restored",
            ProjectDirectory = targetDir,
            HttpClient = http,
        });

        Assert.NotNull(result);
        await using var restored = result.Project;
        Assert.False(result.Succeeded);
        Assert.True(result.Receipt.Rejected);
        Assert.Contains("this runtime identity", result.Receipt.LegacyReason, StringComparison.Ordinal);
        Assert.Equal(apiKeySeed, await File.ReadAllBytesAsync(Path.Combine(
            targetDir,
            ".tn",
            "restored",
            "keys",
            "local.private")));
        Assert.NotEqual(source.Did, restored.Did);
    }

    [Fact]
    public async Task FetchSealedBundleAsyncRunsChallengeVerifyAndDownloadsBundle()
    {
        var seed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var keyIdBytes = Enumerable.Range(100, 16).Select(i => (byte)i).ToArray();
        var apiKey = BuildApiKey(seed, keyIdBytes);
        var identity = TnIdentity.FromSeed(seed);
        var sealedBytes = "sealed tnpkg bytes"u8.ToArray();
        var calls = new List<string>();
        JsonObject? challengeBody = null;
        JsonObject? verifyBody = null;
        string? sealedBundleAuth = null;

        using var http = new HttpClient(new FakeHandler(async request =>
        {
            calls.Add($"{request.Method} {request.RequestUri?.AbsolutePath}");
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                challengeBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync()) as JsonObject;
                return JsonResponse("""{"nonce":"nonce-abc"}""");
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                verifyBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync()) as JsonObject;
                return JsonResponse("""{"token":"jwt-api-key"}""");
            }

            sealedBundleAuth = request.Headers.Authorization?.ToString();
            return JsonResponse(
                $$"""{"sealed_bundle_b64":"{{Convert.ToBase64String(sealedBytes)}}","kind":"project_seed"}""");
        }));

        var result = await TnApiKeyBootstrap.FetchSealedBundleAsync(new TnApiKeyBootstrapOptions
        {
            ApiKey = apiKey,
            VaultBaseUrl = "https://vault.example.test/",
            HttpClient = http,
        });

        Assert.NotNull(result);
        Assert.Equal(identity.Did, result.ApiKey.Did);
        Assert.Equal("https://vault.example.test", result.VaultBaseUrl);
        Assert.Equal("jwt-api-key", result.Token);
        Assert.Equal(sealedBytes, result.SealedBytes);
        Assert.Equal("project_seed", result.Kind);
        Assert.Equal(identity.Did, challengeBody?["did"]?.GetValue<string>());
        Assert.Equal(identity.Did, verifyBody?["did"]?.GetValue<string>());
        Assert.Equal("nonce-abc", verifyBody?["nonce"]?.GetValue<string>());
        var signature = verifyBody?["signature"]?.GetValue<string>()
            ?? throw new InvalidOperationException("verify request omitted signature");
        Assert.True(TnIdentity.VerifyDid(identity.Did, Encoding.UTF8.GetBytes("nonce-abc"), signature));
        Assert.Equal("Bearer jwt-api-key", sealedBundleAuth);
        Assert.Equal(
            [
                "POST /api/v1/auth/challenge",
                "POST /api/v1/auth/verify",
                $"GET /api/v1/api-keys/{Base64UrlNoPadding(keyIdBytes)}/sealed-bundle",
            ],
            calls);
    }

    [Fact]
    public async Task FetchSealedBundleAsyncReturnsNullForMalformedKeyWithoutHttp()
    {
        using var http = new HttpClient(new FakeHandler(_ =>
            throw new InvalidOperationException("malformed api key should not hit HTTP")));

        var result = await TnApiKeyBootstrap.FetchSealedBundleAsync(new TnApiKeyBootstrapOptions
        {
            ApiKey = "tn_apikey_bad",
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.Null(result);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Gone)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task FetchSealedBundleAsyncReturnsNullForVaultRejection(HttpStatusCode statusCode)
    {
        var apiKey = BuildApiKey(new byte[32], Enumerable.Repeat((byte)1, 16).ToArray());
        using var http = new HttpClient(new FakeHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                return Task.FromResult(JsonResponse("""{"nonce":"nonce-abc"}"""));
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                return Task.FromResult(JsonResponse("""{"token":"jwt-api-key"}"""));
            }

            return Task.FromResult(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent("""{"error":"rejected"}""", Encoding.UTF8, "application/json"),
            });
        }));

        var result = await TnApiKeyBootstrap.FetchSealedBundleAsync(new TnApiKeyBootstrapOptions
        {
            ApiKey = apiKey,
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchSealedBundleAsyncReturnsNullForMalformedBundleResponse()
    {
        var apiKey = BuildApiKey(new byte[32], Enumerable.Repeat((byte)1, 16).ToArray());
        using var http = new HttpClient(new FakeHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/challenge")
            {
                return Task.FromResult(JsonResponse("""{"nonce":"nonce-abc"}"""));
            }

            if (request.RequestUri?.AbsolutePath == "/api/v1/auth/verify")
            {
                return Task.FromResult(JsonResponse("""{"token":"jwt-api-key"}"""));
            }

            return Task.FromResult(JsonResponse("""{"sealed_bundle_b64":"not base64"}"""));
        }));

        var result = await TnApiKeyBootstrap.FetchSealedBundleAsync(new TnApiKeyBootstrapOptions
        {
            ApiKey = apiKey,
            VaultBaseUrl = "https://vault.example.test",
            HttpClient = http,
        });

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchSealedBundleAsyncThrowsForMissingVaultUrl()
    {
        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            TnApiKeyBootstrap.FetchSealedBundleAsync(new TnApiKeyBootstrapOptions
            {
                ApiKey = BuildApiKey(new byte[32], new byte[16]),
            }));

        Assert.Equal("options", error.ParamName);
    }

    private static string BuildApiKey(byte[] seed, byte[] keyId)
    {
        return $"tn_apikey_{Base64UrlNoPadding(seed)}_{Base64UrlNoPadding(keyId)}";
    }

    private static string Base64UrlNoPadding(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
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
