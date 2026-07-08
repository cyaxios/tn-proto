using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace TnProto.Cli.Tests;

public sealed class CliBootstrapTests
{
    [Fact]
    public async Task BootstrapApiKeyUsesEnvironmentKeyAndPrintsJsonWithoutLeakingSecret()
    {
        var priorApiKey = Environment.GetEnvironmentVariable("TN_API_KEY");
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-bootstrap-" + Guid.NewGuid().ToString("N"));
        var sourceDir = Path.Combine(tempDir, "source");
        var targetDir = Path.Combine(tempDir, "target");
        var seed = Enumerable.Range(0, 32).Select(i => (byte)(150 - i)).ToArray();
        var keyIdBytes = Enumerable.Range(40, 16).Select(i => (byte)i).ToArray();
        var apiKey = BuildApiKey(seed, keyIdBytes);

        try
        {
            await using var source = await Tn.InitProjectAsync(
                "source",
                new TnProjectOptions
                {
                    ProjectDirectory = sourceDir,
                    DevicePrivateBytes = seed,
                });
            var packagePath = Path.Combine(tempDir, "source.project.tnpkg");
            await source.Packages.ExportProjectSeedAsync(packagePath);
            using var vault = await FakeApiKeyVault.StartAsync(await File.ReadAllBytesAsync(packagePath));
            using var output = new StringWriter();
            using var error = new StringWriter();

            Environment.SetEnvironmentVariable("TN_API_KEY", apiKey);
            var exitCode = await CliApp.RunAsync(
                [
                    "bootstrap",
                    "api-key",
                    "--vault",
                    vault.BaseUrl,
                    "--dir",
                    targetDir,
                    "--project",
                    "restored",
                    "--json",
                ],
                output,
                error);

            Assert.True(
                exitCode == 0,
                error + " requests=" + string.Join(", ", vault.Requests) + " server_error=" + vault.ServerError);
            Assert.Equal(string.Empty, error.ToString());
            Assert.DoesNotContain(apiKey, output.ToString(), StringComparison.Ordinal);
            var result = JsonNode.Parse(output.ToString()) as JsonObject
                ?? throw new InvalidOperationException("bootstrap output was not a JSON object.");
            Assert.True(result["succeeded"]?.GetValue<bool>());
            Assert.Equal(source.Did, result["did"]?.GetValue<string>());
            Assert.Equal(vault.BaseUrl, result["vault"]?.GetValue<string>());
            Assert.Equal("project_seed", result["kind"]?.GetValue<string>());
            var yamlPath = result["yaml_path"]?.GetValue<string>()
                ?? throw new InvalidOperationException("bootstrap output omitted yaml_path.");
            Assert.True(File.Exists(yamlPath));
            Assert.Equal(seed, await File.ReadAllBytesAsync(Path.Combine(
                targetDir,
                ".tn",
                "restored",
                "keys",
                "local.private")));
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_API_KEY", priorApiKey);
        }
    }

    [Fact]
    public async Task BootstrapApiKeyRequiresVault()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["bootstrap", "api-key"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --vault", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task BootstrapApiKeyRequiresKeyOrEnvironment()
    {
        var priorApiKey = Environment.GetEnvironmentVariable("TN_API_KEY");
        using var output = new StringWriter();
        using var error = new StringWriter();
        try
        {
            Environment.SetEnvironmentVariable("TN_API_KEY", null);

            var exitCode = await CliApp.RunAsync(
                ["bootstrap", "api-key", "--vault", "http://127.0.0.1:1"],
                output,
                error);

            Assert.Equal(2, exitCode);
            Assert.Contains("requires --api-key", error.ToString(), StringComparison.Ordinal);
            Assert.Equal(string.Empty, output.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_API_KEY", priorApiKey);
        }
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

    private sealed class FakeApiKeyVault : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;
        private readonly byte[] _packageBytes;
        private readonly List<string> _requests = [];

        private FakeApiKeyVault(HttpListener listener, byte[] packageBytes, int port)
        {
            _listener = listener;
            _packageBytes = packageBytes;
            BaseUrl = $"http://127.0.0.1:{port}";
            _loop = Task.Run(ListenAsync);
        }

        public string BaseUrl { get; }

        public IReadOnlyList<string> Requests => _requests;

        public string? ServerError { get; private set; }

        public static Task<FakeApiKeyVault> StartAsync(byte[] packageBytes)
        {
            var port = FreePort();
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();
            return Task.FromResult(new FakeApiKeyVault(listener, packageBytes, port));
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
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync().WaitAsync(_cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleAsync(context).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        ServerError = ex.ToString();
                    }
                });
            }
        }

        private async Task HandleAsync(HttpListenerContext context)
        {
            var request = context.Request;
            _requests.Add($"{request.HttpMethod} {request.Url?.AbsolutePath}");

            if (request.HttpMethod == "POST" && request.Url?.AbsolutePath == "/api/v1/auth/challenge")
            {
                await WriteJsonAsync(context, """{"nonce":"nonce-cli"}""").ConfigureAwait(false);
                return;
            }

            if (request.HttpMethod == "POST" && request.Url?.AbsolutePath == "/api/v1/auth/verify")
            {
                await WriteJsonAsync(context, """{"token":"jwt-cli"}""").ConfigureAwait(false);
                return;
            }

            if (request.HttpMethod == "GET"
                && (request.Url?.AbsolutePath.StartsWith("/api/v1/api-keys/", StringComparison.Ordinal) ?? false))
            {
                await WriteJsonAsync(
                    context,
                    $$"""{"sealed_bundle_b64":"{{Convert.ToBase64String(_packageBytes)}}","kind":"project_seed"}""")
                    .ConfigureAwait(false);
                return;
            }

            await WriteStatusAsync(context, 404, "Not Found").ConfigureAwait(false);
        }

        private static async Task WriteJsonAsync(HttpListenerContext context, string json)
        {
            var body = Encoding.UTF8.GetBytes(json);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.ContentLength64 = body.Length;
            await context.Response.OutputStream.WriteAsync(body).ConfigureAwait(false);
            context.Response.Close();
        }

        private static async Task WriteStatusAsync(HttpListenerContext context, int status, string reason)
        {
            var body = Encoding.UTF8.GetBytes(reason);
            context.Response.StatusCode = status;
            context.Response.ContentLength64 = body.Length;
            await context.Response.OutputStream.WriteAsync(body).ConfigureAwait(false);
            context.Response.Close();
        }

        private static int FreePort()
        {
            using var socket = new TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            var port = ((IPEndPoint)socket.LocalEndpoint).Port;
            socket.Stop();
            return port;
        }
    }
}
