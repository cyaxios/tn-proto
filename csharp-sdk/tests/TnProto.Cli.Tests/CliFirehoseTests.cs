using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace TnProto.Cli.Tests;

public sealed class CliFirehoseTests
{
    [Fact]
    public async Task FirehoseCommandsRequireExplicitEnvGate()
    {
        using var env = new EnvScope()
            .Set("TN_FIREHOSE_ENABLED", null)
            .Set("TN_FIREHOSE_URL", "http://127.0.0.1:1")
            .Set("TN_FIREHOSE_TOKEN", null);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["firehose", "stats", "acct_123"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Contains("TN_FIREHOSE_ENABLED=1", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task FirehoseStatsPrintsWorkerJson()
    {
        using var server = await FakeFirehose.StartAsync((request, _) =>
            FakeFirehose.Json("""{"tenant":"acct_123","objects":2}"""));
        using var env = new EnvScope()
            .Set("TN_FIREHOSE_ENABLED", "1")
            .Set("TN_FIREHOSE_URL", server.BaseUrl)
            .Set("TN_FIREHOSE_TOKEN", null);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["firehose", "stats", "acct_123"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Equal("/stats/acct_123", server.LastPath);
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("firehose stats output was not an object.");
        Assert.Equal("acct_123", result["tenant"]?.GetValue<string>());
        Assert.Equal(2, result["objects"]?.GetValue<int>());
    }

    [Fact]
    public async Task FirehoseListRequiresTokenBeforeCallingWorker()
    {
        using var server = await FakeFirehose.StartAsync((_, _) =>
            throw new InvalidOperationException("should not call firehose worker"));
        using var env = new EnvScope()
            .Set("TN_FIREHOSE_ENABLED", "1")
            .Set("TN_FIREHOSE_URL", server.BaseUrl)
            .Set("TN_FIREHOSE_TOKEN", null);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["firehose", "list", "acct_123"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Contains("TN_FIREHOSE_TOKEN", error.ToString(), StringComparison.Ordinal);
        Assert.Null(server.LastPath);
    }

    [Fact]
    public async Task FirehoseListPrintsWorkerJsonAndUsesDidOverride()
    {
        using var server = await FakeFirehose.StartAsync((request, auth) =>
        {
            Assert.Equal("Bearer fh-token", auth);
            return FakeFirehose.Json("""{"items":[{"name":"snapshot.tnpkg"}]}""");
        });
        using var env = new EnvScope()
            .Set("TN_FIREHOSE_ENABLED", "1")
            .Set("TN_FIREHOSE_URL", server.BaseUrl)
            .Set("TN_FIREHOSE_TOKEN", "fh-token");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["firehose", "list", "acct_123", "--did", "did:key:zReader"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Equal("/api/v1/inbox/did%3Akey%3AzReader/incoming", server.LastPath);
        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("firehose list output was not an object.");
        Assert.Equal("snapshot.tnpkg", result["items"]?[0]?["name"]?.GetValue<string>());
    }

    [Fact]
    public async Task FirehoseGetWritesDownloadedBytesToOutPath()
    {
        using var server = await FakeFirehose.StartAsync((_, auth) =>
        {
            Assert.Equal("Bearer fh-token", auth);
            return FakeFirehose.Bytes([1, 2, 3, 4]);
        });
        using var env = new EnvScope()
            .Set("TN_FIREHOSE_ENABLED", "1")
            .Set("TN_FIREHOSE_URL", server.BaseUrl)
            .Set("TN_FIREHOSE_TOKEN", "fh-token");
        var outPath = Path.Combine(Path.GetTempPath(), "tn-csharp-firehose-" + Guid.NewGuid().ToString("N"), "snapshot.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["firehose", "get", "acct_123", "ceremony-1", "snapshot.tnpkg", "--out", outPath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Equal("/api/v1/inbox/acct_123/snapshots/ceremony-1/snapshot.tnpkg", server.LastPath);
        Assert.Equal([1, 2, 3, 4], await File.ReadAllBytesAsync(outPath));
        Assert.Contains("Wrote 4 bytes", output.ToString(), StringComparison.Ordinal);
    }

    private sealed class EnvScope : IDisposable
    {
        private readonly Dictionary<string, string?> previous = [];

        public EnvScope Set(string name, string? value)
        {
            previous.TryAdd(name, Environment.GetEnvironmentVariable(name));
            Environment.SetEnvironmentVariable(name, value);
            return this;
        }

        public void Dispose()
        {
            foreach (var (name, value) in previous)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
        }
    }

    private sealed class FakeFirehose : IDisposable
    {
        private readonly TcpListener listener;
        private readonly Func<Request, string?, Response> handler;
        private readonly CancellationTokenSource cts = new();
        private readonly Task loop;

        private FakeFirehose(TcpListener listener, Func<Request, string?, Response> handler)
        {
            this.listener = listener;
            this.handler = handler;
            BaseUrl = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
            loop = Task.Run(AcceptLoopAsync);
        }

        public string BaseUrl { get; }

        public string? LastPath { get; private set; }

        public static Task<FakeFirehose> StartAsync(Func<Request, string?, Response> handler)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return Task.FromResult(new FakeFirehose(listener, handler));
        }

        public static Response Json(string json) =>
            new(Encoding.UTF8.GetBytes(json), "application/json");

        public static Response Bytes(byte[] bytes) =>
            new(bytes, "application/octet-stream");

        public void Dispose()
        {
            cts.Cancel();
            listener.Stop();
            try
            {
                loop.Wait(TimeSpan.FromSeconds(1));
            }
            catch (AggregateException)
            {
            }

            cts.Dispose();
        }

        private async Task AcceptLoopAsync()
        {
            while (!cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (SocketException)
                {
                    return;
                }

                _ = Task.Run(() => HandleClientAsync(client));
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            using var clientScope = client;
            await using var stream = client.GetStream();
            using var reader = new StreamReader(
                stream,
                Encoding.ASCII,
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 1024,
                leaveOpen: true);
            var requestLine = await reader.ReadLineAsync().ConfigureAwait(false);
            if (requestLine is null)
            {
                return;
            }

            var parts = requestLine.Split(' ');
            var path = parts.Length >= 2 ? parts[1] : "/";
            string? auth = null;
            string? line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync().ConfigureAwait(false)))
            {
                if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                {
                    auth = line["Authorization:".Length..].Trim();
                }
            }

            LastPath = path;
            var response = handler(new Request(path), auth);
            var header =
                "HTTP/1.1 200 OK\r\n" +
                $"Content-Type: {response.ContentType}\r\n" +
                $"Content-Length: {response.Body.Length}\r\n" +
                "Connection: close\r\n\r\n";
            var headerBytes = Encoding.ASCII.GetBytes(header);
            await stream.WriteAsync(headerBytes).ConfigureAwait(false);
            await stream.WriteAsync(response.Body).ConfigureAwait(false);
        }
    }

    private sealed record Request(string Path);

    private sealed record Response(byte[] Body, string ContentType);
}
