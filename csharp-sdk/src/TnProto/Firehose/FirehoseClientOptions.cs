namespace TnProto.Firehose;

/// <summary>
/// Options for the direct firehose-worker diagnostic client.
/// </summary>
public sealed class FirehoseClientOptions
{
    /// <summary>
    /// Firehose worker base URL, for example <c>https://firehose-worker.example.workers.dev</c>.
    /// </summary>
    public string? BaseUrl { get; set; }

    /// <summary>
    /// Optional bearer token. Required for inbox list/get routes.
    /// </summary>
    public string? BearerToken { get; set; }

    /// <summary>
    /// Optional HTTP client for tests or caller-managed lifetime.
    /// </summary>
    public HttpClient? HttpClient { get; set; }
}
