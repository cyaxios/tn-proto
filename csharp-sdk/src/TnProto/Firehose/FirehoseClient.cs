using System.Net.Http.Headers;
using System.Text.Json.Nodes;

namespace TnProto.Firehose;

/// <summary>
/// Thin direct client for firehose-worker diagnostic endpoints.
/// </summary>
public sealed class FirehoseClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private string? _bearerToken;

    /// <summary>
    /// Create a direct firehose-worker client.
    /// </summary>
    public FirehoseClient(FirehoseClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.BaseUrl))
        {
            throw new ArgumentException("Firehose base URL must not be empty.", nameof(options));
        }

        BaseUrl = options.BaseUrl.TrimEnd('/');
        _http = options.HttpClient ?? new HttpClient();
        _ownsHttp = options.HttpClient is null;
        _http.DefaultRequestHeaders.Accept.Clear();
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        SetBearerToken(options.BearerToken);
    }

    /// <summary>
    /// Normalized firehose worker base URL.
    /// </summary>
    public string BaseUrl { get; }

    /// <summary>
    /// Current bearer token, if configured.
    /// </summary>
    public string? BearerToken => _bearerToken;

    /// <summary>
    /// Replace the bearer token used by inbox list/get routes.
    /// </summary>
    public void SetBearerToken(string? token)
    {
        _bearerToken = string.IsNullOrWhiteSpace(token) ? null : token;
        _http.DefaultRequestHeaders.Authorization = _bearerToken is null
            ? null
            : new AuthenticationHeaderValue("Bearer", _bearerToken);
    }

    /// <summary>
    /// Fetch worker stats for a tenant. Mirrors <c>tn firehose stats &lt;tenant&gt;</c>.
    /// </summary>
    public async Task<JsonNode> StatsAsync(
        string tenant,
        CancellationToken cancellationToken = default)
    {
        RequireSegment(tenant, nameof(tenant));
        using var response = await _http.GetAsync(
            $"{BaseUrl}/stats/{EscapeSegment(tenant)}",
            cancellationToken).ConfigureAwait(false);
        return await ParseJsonResponseAsync("stats", response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// List worker inbox objects for a tenant. Mirrors <c>tn firehose list</c>.
    /// </summary>
    public async Task<JsonNode> ListAsync(
        string tenant,
        string? did = null,
        CancellationToken cancellationToken = default)
    {
        RequireToken("list");
        RequireSegment(tenant, nameof(tenant));
        var inboxDid = string.IsNullOrWhiteSpace(did) ? tenant : did;
        RequireSegment(inboxDid, nameof(did));

        using var response = await _http.GetAsync(
            $"{BaseUrl}/api/v1/inbox/{EscapeSegment(inboxDid)}/incoming",
            cancellationToken).ConfigureAwait(false);
        return await ParseJsonResponseAsync("list", response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Download one firehose inbox snapshot. Mirrors <c>tn firehose get</c>.
    /// </summary>
    public async Task<byte[]> GetAsync(
        string tenant,
        string ceremony,
        string name,
        string? did = null,
        CancellationToken cancellationToken = default)
    {
        RequireToken("get");
        RequireSegment(tenant, nameof(tenant));
        RequireSegment(ceremony, nameof(ceremony));
        RequireSegment(name, nameof(name));
        var inboxDid = string.IsNullOrWhiteSpace(did) ? tenant : did;
        RequireSegment(inboxDid, nameof(did));

        using var response = await _http.GetAsync(
            $"{BaseUrl}/api/v1/inbox/{EscapeSegment(inboxDid)}/snapshots/{EscapeSegment(ceremony)}/{EscapeSegment(name)}",
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await StatusErrorAsync("get", response, cancellationToken).ConfigureAwait(false);
        }

        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private static void RequireSegment(string value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must not be empty.", paramName);
        }
    }

    private void RequireToken(string operation)
    {
        if (_bearerToken is null)
        {
            throw new FirehoseException(
                $"TN_FIREHOSE_TOKEN is required for firehose {operation} inbox routes.");
        }
    }

    private static string EscapeSegment(string value) => Uri.EscapeDataString(value);

    private static async Task<JsonNode> ParseJsonResponseAsync(
        string operation,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw await StatusErrorAsync(operation, response, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false)
                ?? throw new FirehoseException($"firehose {operation} returned empty JSON");
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new FirehoseException($"firehose {operation} returned non-JSON", ex);
        }
    }

    private static async Task<FirehoseException> StatusErrorAsync(
        string operation,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (body.Length > 200)
        {
            body = body[..200];
        }

        return new FirehoseException(
            $"firehose {operation} returned {(int)response.StatusCode}: {body}");
    }
}
