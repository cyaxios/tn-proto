using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using TnProto.Account;

namespace TnProto.Tests;

public sealed class AccountTests
{
    [Fact]
    public async Task StatusAsyncReportsNotLoggedInForFreshProject()
    {
        await using var tn = await CreateProjectAsync();

        var status = await tn.Account.StatusAsync();

        Assert.Equal(tn.Did, status.DeviceDid);
        Assert.Null(status.AccountId);
        Assert.False(status.AccountBound);
        Assert.False(status.KeyCached);
        Assert.Equal(AccountVerdict.NotLoggedIn, status.Verdict);
        Assert.Equal("not_logged_in", status.VerdictName);
    }

    [Fact]
    public async Task ConnectCodeAsyncPostsSignedCodeAndPersistsAccountBinding()
    {
        await using var tn = await CreateProjectAsync();
        string? requestPath = null;
        JsonObject? requestBody = null;
        using var http = new HttpClient(new FakeHandler(async request =>
        {
            requestPath = request.RequestUri?.AbsolutePath;
            var body = await request.Content!.ReadAsStringAsync();
            requestBody = JsonNode.Parse(body) as JsonObject;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"account_id":"acct_123","project_id":"proj_456","project_name":"Payments"}""",
                    Encoding.UTF8,
                    "application/json"),
            };
        }));

        var result = await tn.Account.ConnectCodeAsync(
            "ABC123",
            new AccountConnectOptions
            {
                VaultBaseUrl = "https://vault.example.test/",
                HttpClient = http,
            });

        Assert.Equal("/api/v1/account/connect-codes/redeem", requestPath);
        Assert.Equal("ABC123", requestBody?["code"]?.GetValue<string>());
        Assert.Equal(tn.Did, requestBody?["did"]?.GetValue<string>());
        var signature = requestBody?["signature_b64"]?.GetValue<string>()
            ?? throw new InvalidOperationException("request omitted signature_b64");
        Assert.Equal(64, Convert.FromBase64String(signature).Length);
        Assert.Equal("acct_123", result.AccountId);
        Assert.Equal("proj_456", result.ProjectId);
        Assert.Equal("Payments", result.ProjectName);
        Assert.Equal("https://vault.example.test", result.Vault);

        var state = await tn.Account.StateAsync();
        Assert.True(state.AccountBound);
        Assert.Equal("acct_123", state.AccountId);
    }

    [Fact]
    public async Task ConnectCodeAsyncRejectsVaultErrorWithoutPersistingState()
    {
        await using var tn = await CreateProjectAsync();
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"expired"}""", Encoding.UTF8, "application/json"),
        })));

        var error = await Assert.ThrowsAsync<TnException>(() => tn.Account.ConnectCodeAsync(
            "expired",
            new AccountConnectOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                HttpClient = http,
            }));

        Assert.Contains("failed (400)", error.Message, StringComparison.Ordinal);
        var state = await tn.Account.StateAsync();
        Assert.False(state.AccountBound);
        Assert.Null(state.AccountId);
    }

    [Fact]
    public async Task LogoutAsyncClearsExistingAccountBinding()
    {
        await using var tn = await CreateProjectAsync();
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"account_id":"acct_123"}""", Encoding.UTF8, "application/json"),
        })));
        await tn.Account.ConnectCodeAsync(
            "ABC123",
            new AccountConnectOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                HttpClient = http,
            });

        var logout = await tn.Account.LogoutAsync();
        var state = await tn.Account.StateAsync();

        Assert.True(logout.WasBound);
        Assert.Equal("acct_123", logout.AccountId);
        Assert.False(state.AccountBound);
        Assert.Null(state.AccountId);
    }

    [Fact]
    public async Task ConnectCodeAsyncRejectsMissingVaultUrl()
    {
        await using var tn = await CreateProjectAsync();

        var error = await Assert.ThrowsAsync<ArgumentException>(() => tn.Account.ConnectCodeAsync(
            "ABC123",
            new AccountConnectOptions()));

        Assert.Equal("options", error.ParamName);
    }

    [Fact]
    public async Task AccountCredentialStoreRoundTripsAndDeletesAccountAwk()
    {
        var storePath = Path.Combine(Path.GetTempPath(), "tn-csharp-account-store-" + Guid.NewGuid().ToString("N"), "credentials.json");
        var store = new AccountCredentialStore(storePath);
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        await store.SetAccountAwkAsync("acct_123", key);
        var loaded = await store.GetAccountAwkAsync("acct_123");

        Assert.NotNull(loaded);
        Assert.Equal(key, loaded);
        Assert.Contains("\"awk:acct_123\"", await File.ReadAllTextAsync(storePath));

        await store.DeleteAccountAwkAsync("acct_123");

        Assert.Null(await store.GetAccountAwkAsync("acct_123"));
    }

    [Fact]
    public async Task AccountCredentialStoreRejectsNonThirtyTwoByteAccountAwk()
    {
        var storePath = Path.Combine(Path.GetTempPath(), "tn-csharp-account-store-" + Guid.NewGuid().ToString("N"), "credentials.json");
        var store = new AccountCredentialStore(storePath);

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            store.SetAccountAwkAsync("acct_123", new byte[31]));

        Assert.Equal("awk", error.ParamName);
    }

    [Fact]
    public async Task AccountCredentialStoreTreatsMalformedAccountAwkAsMissing()
    {
        var storePath = Path.Combine(Path.GetTempPath(), "tn-csharp-account-store-" + Guid.NewGuid().ToString("N"), "credentials.json");
        var store = new AccountCredentialStore(storePath);

        await store.SetAsync(AccountCredentialStore.AwkKeyName("acct_123"), new byte[31]);

        Assert.Null(await store.GetAccountAwkAsync("acct_123"));
    }

    [Fact]
    public async Task StatusAsyncReportsBackedUpWhenAccountAwkIsCached()
    {
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-account-identity-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await using var tn = await CreateBoundProjectAsync("acct_123");

            await AccountCredentialStore.Default()
                .SetAccountAwkAsync("acct_123", Enumerable.Repeat((byte)7, 32).ToArray());

            var status = await tn.Account.StatusAsync();

            Assert.True(status.AccountBound);
            Assert.Equal("acct_123", status.AccountId);
            Assert.True(status.KeyCached);
            Assert.Equal(AccountVerdict.BackedUp, status.Verdict);
            Assert.Equal("backed_up", status.VerdictName);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    [Fact]
    public async Task StatusAsyncIgnoresMalformedCachedAccountAwk()
    {
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var identityDir = Path.Combine(Path.GetTempPath(), "tn-csharp-account-identity-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", identityDir);
            await using var tn = await CreateBoundProjectAsync("acct_123");

            await AccountCredentialStore.Default()
                .SetAsync(AccountCredentialStore.AwkKeyName("acct_123"), new byte[31]);

            var status = await tn.Account.StatusAsync();

            Assert.True(status.AccountBound);
            Assert.Equal("acct_123", status.AccountId);
            Assert.False(status.KeyCached);
            Assert.Equal(AccountVerdict.LinkedNoKey, status.Verdict);
            Assert.Equal("linked_no_key", status.VerdictName);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
        }
    }

    private static Task<Tn> CreateProjectAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-account-" + Guid.NewGuid().ToString("N"));
        return Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir });
    }

    private static async Task<Tn> CreateBoundProjectAsync(string accountId)
    {
        var tn = await CreateProjectAsync();
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($$"""{"account_id":"{{accountId}}"}""", Encoding.UTF8, "application/json"),
        })));
        await tn.Account.ConnectCodeAsync(
            "ABC123",
            new AccountConnectOptions
            {
                VaultBaseUrl = "https://vault.example.test",
                HttpClient = http,
            });
        return tn;
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
