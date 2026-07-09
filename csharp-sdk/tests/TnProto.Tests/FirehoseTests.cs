using System.Net;
using System.Text;
using TnProto.Firehose;

namespace TnProto.Tests;

public sealed class FirehoseTests
{
    [Fact]
    public async Task StatsAsyncFetchesTenantStatsWithoutBearerToken()
    {
        string? path = null;
        string? accept = null;
        string? auth = null;
        using var http = new HttpClient(new FakeHandler(request =>
        {
            path = request.RequestUri?.AbsolutePath;
            accept = request.Headers.Accept.ToString();
            auth = request.Headers.Authorization?.ToString();
            return Task.FromResult(JsonResponse("""{"tenant":"acct_123","objects":2}"""));
        }));
        using var client = new FirehoseClient(new FirehoseClientOptions
        {
            BaseUrl = "https://firehose.example.test/",
            HttpClient = http,
        });

        var stats = await client.StatsAsync("acct_123");

        Assert.Equal("https://firehose.example.test", client.BaseUrl);
        Assert.Equal("/stats/acct_123", path);
        Assert.Equal("application/json", accept);
        Assert.Null(auth);
        Assert.Equal("acct_123", stats["tenant"]?.GetValue<string>());
        Assert.Equal(2, stats["objects"]?.GetValue<int>());
    }

    [Fact]
    public async Task ListAsyncRequiresBearerAndUsesDidOverride()
    {
        string? path = null;
        string? auth = null;
        using var http = new HttpClient(new FakeHandler(request =>
        {
            path = request.RequestUri?.AbsolutePath;
            auth = request.Headers.Authorization?.ToString();
            return Task.FromResult(JsonResponse("""{"items":[{"name":"snap.tnpkg"}]}"""));
        }));
        using var client = new FirehoseClient(new FirehoseClientOptions
        {
            BaseUrl = "https://firehose.example.test",
            BearerToken = "fh-token",
            HttpClient = http,
        });

        var listing = await client.ListAsync("tenant-a", did: "did:key:zReader");

        Assert.Equal("Bearer fh-token", auth);
        Assert.Equal("/api/v1/inbox/did%3Akey%3AzReader/incoming", path);
        Assert.Equal("snap.tnpkg", listing["items"]?[0]?["name"]?.GetValue<string>());
    }

    [Fact]
    public async Task ListAsyncRejectsMissingBearerToken()
    {
        using var client = new FirehoseClient(new FirehoseClientOptions
        {
            BaseUrl = "https://firehose.example.test",
            HttpClient = new HttpClient(new FakeHandler(_ => throw new InvalidOperationException("should not call HTTP"))),
        });

        var error = await Assert.ThrowsAsync<FirehoseException>(() => client.ListAsync("tenant-a"));

        Assert.Contains("TN_FIREHOSE_TOKEN", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAsyncDownloadsSnapshotBytes()
    {
        string? path = null;
        using var http = new HttpClient(new FakeHandler(request =>
        {
            path = request.RequestUri?.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([1, 2, 3, 4]),
            });
        }));
        using var client = new FirehoseClient(new FirehoseClientOptions
        {
            BaseUrl = "https://firehose.example.test",
            BearerToken = "fh-token",
            HttpClient = http,
        });

        var bytes = await client.GetAsync("did:key:zReader", "ceremony-1", "snap.tnpkg");

        Assert.Equal([1, 2, 3, 4], bytes);
        Assert.Equal("/api/v1/inbox/did%3Akey%3AzReader/snapshots/ceremony-1/snap.tnpkg", path);
    }

    [Fact]
    public async Task StatsAsyncReportsHttpErrors()
    {
        using var http = new HttpClient(new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        {
            Content = new StringContent("worker unavailable", Encoding.UTF8, "text/plain"),
        })));
        using var client = new FirehoseClient(new FirehoseClientOptions
        {
            BaseUrl = "https://firehose.example.test",
            HttpClient = http,
        });

        var error = await Assert.ThrowsAsync<FirehoseException>(() => client.StatsAsync("tenant-a"));

        Assert.Contains("firehose stats returned 503", error.Message, StringComparison.Ordinal);
        Assert.Contains("worker unavailable", error.Message, StringComparison.Ordinal);
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
