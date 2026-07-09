using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TnProto.Vault;

/// <summary>
/// Thin HTTP client for vault project create/list behavior.
/// </summary>
public sealed class VaultHttpProjectClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private string? _bearerToken;

    /// <summary>
    /// Create a vault project client.
    /// </summary>
    public VaultHttpProjectClient(VaultHttpClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.BaseUrl))
        {
            throw new ArgumentException("Vault base URL must not be empty.", nameof(options));
        }

        BaseUrl = NormalizeBaseUrl(options.BaseUrl);
        _http = options.HttpClient ?? new HttpClient();
        _ownsHttp = options.HttpClient is null;

        SetBearerToken(options.BearerToken);
    }

    /// <summary>
    /// Normalized vault base URL.
    /// </summary>
    public string BaseUrl { get; }

    /// <summary>
    /// Current bearer token, when authenticated.
    /// </summary>
    public string? BearerToken => _bearerToken;

    /// <summary>
    /// Replace the active bearer token used by authenticated project routes.
    /// </summary>
    public void SetBearerToken(string? token)
    {
        _bearerToken = string.IsNullOrWhiteSpace(token) ? null : token;
        _http.DefaultRequestHeaders.Authorization = _bearerToken is null
            ? null
            : new AuthenticationHeaderValue("Bearer", _bearerToken);
    }

    /// <summary>
    /// Run the vault DID challenge/verify flow and cache the returned bearer token.
    /// </summary>
    public async Task<string> AuthenticateAsync(
        string did,
        byte[] seed,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            throw new ArgumentException("DID must not be empty.", nameof(did));
        }

        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != 32)
        {
            throw new ArgumentException("TN Ed25519 identity seeds must be exactly 32 bytes.", nameof(seed));
        }

        using var challenge = await _http.PostAsJsonAsync(
            $"{BaseUrl}/api/v1/auth/challenge",
            new JsonObject { ["did"] = did },
            cancellationToken).ConfigureAwait(false);
        if (!challenge.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync(
                "POST",
                "/api/v1/auth/challenge",
                challenge,
                cancellationToken).ConfigureAwait(false);
        }

        var challengeJson = await ParseObjectResponseAsync(
            challenge,
            "vault challenge response",
            cancellationToken).ConfigureAwait(false);
        var nonce = NonEmpty(challengeJson["nonce"]?.GetValue<string>())
            ?? throw new VaultException("vault challenge response missing nonce");
        var signature = TnIdentity.Sign(seed, Encoding.UTF8.GetBytes(nonce));

        using var verify = await _http.PostAsJsonAsync(
            $"{BaseUrl}/api/v1/auth/verify",
            new JsonObject
            {
                ["did"] = did,
                ["nonce"] = nonce,
                ["signature"] = signature,
            },
            cancellationToken).ConfigureAwait(false);
        if (!verify.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync(
                "POST",
                "/api/v1/auth/verify",
                verify,
                cancellationToken).ConfigureAwait(false);
        }

        var verifyJson = await ParseObjectResponseAsync(
            verify,
            "vault verify response",
            cancellationToken).ConfigureAwait(false);
        var token = NonEmpty(verifyJson["token"]?.GetValue<string>())
            ?? throw new VaultException("vault verify response missing token");
        SetBearerToken(token);
        return token;
    }

    /// <summary>
    /// Create a vault project.
    /// </summary>
    public async Task<VaultProject> CreateProjectAsync(
        string name,
        string? ceremonyId = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Project name must not be empty.", nameof(name));
        }

        var body = new JsonObject { ["name"] = name };
        if (!string.IsNullOrWhiteSpace(ceremonyId))
        {
            body["ceremony_id"] = ceremonyId;
        }

        using var response = await _http.PostAsJsonAsync(
            $"{BaseUrl}/api/v1/projects",
            body,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("POST", "/api/v1/projects", response, cancellationToken)
                .ConfigureAwait(false);
        }

        return await ParseProjectResponseAsync(response, fallbackName: name, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// List vault projects visible to the authenticated vault identity.
    /// </summary>
    public async Task<IReadOnlyList<VaultProject>> ListProjectsAsync(
        CancellationToken cancellationToken = default)
    {
        using var response = await _http.GetAsync($"{BaseUrl}/api/v1/projects", cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("GET", "/api/v1/projects", response, cancellationToken)
                .ConfigureAwait(false);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var array = await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false) as JsonArray
            ?? throw new VaultException("GET /api/v1/projects returned non-array JSON");
        var projects = new List<VaultProject>(array.Count);
        foreach (var item in array)
        {
            projects.Add(ParseProject(item as JsonObject
                ?? throw new VaultException("vault project list item was not a JSON object")));
        }

        return projects;
    }

    /// <summary>
    /// List authenticated account inbox package metadata.
    /// </summary>
    public async Task<IReadOnlyList<VaultAccountInboxItem>> ListAccountInboxAsync(
        CancellationToken cancellationToken = default)
    {
        const string path = "/api/v1/account/inbox";
        using var response = await _http.GetAsync($"{BaseUrl}{path}", cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("GET", path, response, cancellationToken)
                .ConfigureAwait(false);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var raw = await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        JsonArray items = raw switch
        {
            JsonArray array => array,
            JsonObject obj when obj["items"] is JsonArray array => array,
            JsonObject => throw new VaultException("GET /api/v1/account/inbox response missing items"),
            _ => throw new VaultException("GET /api/v1/account/inbox returned non-array JSON"),
        };

        var parsed = new List<VaultAccountInboxItem>(items.Count);
        foreach (var item in items)
        {
            parsed.Add(ParseAccountInboxItem(item as JsonObject
                ?? throw new VaultException("account inbox item must be a JSON object")));
        }

        return parsed;
    }

    /// <summary>
    /// Fetch authenticated account preferences.
    /// </summary>
    public async Task<VaultAccountPrefs> GetAccountPrefsAsync(
        CancellationToken cancellationToken = default)
    {
        const string path = "/api/v1/account/prefs";
        using var response = await _http.GetAsync($"{BaseUrl}{path}", cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("GET", path, response, cancellationToken)
                .ConfigureAwait(false);
        }

        var obj = await ParseObjectResponseAsync(response, "account prefs response", cancellationToken)
            .ConfigureAwait(false);
        var mode = NonEmpty(obj["default_new_ceremony_mode"]?.GetValue<string>())
            ?? throw new VaultException("GET /api/v1/account/prefs response missing default_new_ceremony_mode");
        var prefsVersion = obj["prefs_version"] switch
        {
            JsonValue value when value.TryGetValue<ulong>(out var parsed) => parsed,
            JsonValue value when value.TryGetValue<string>(out var text)
                && ulong.TryParse(text, out var parsed) => parsed,
            _ => throw new VaultException("GET /api/v1/account/prefs response missing prefs_version"),
        };
        return new VaultAccountPrefs(mode, prefsVersion);
    }

    /// <summary>
    /// Download a package from the authenticated account inbox.
    /// </summary>
    public async Task<byte[]?> DownloadAccountInboxPackageAsync(
        string fromDid,
        string ceremonyId,
        string timestamp,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(fromDid))
        {
            throw new ArgumentException("Publisher DID must not be empty.", nameof(fromDid));
        }

        if (string.IsNullOrWhiteSpace(ceremonyId))
        {
            throw new ArgumentException("Ceremony id must not be empty.", nameof(ceremonyId));
        }

        if (string.IsNullOrWhiteSpace(timestamp))
        {
            throw new ArgumentException("Timestamp must not be empty.", nameof(timestamp));
        }

        var path = $"/api/v1/account/inbox/{Uri.EscapeDataString(fromDid)}/{Uri.EscapeDataString(ceremonyId)}/{Uri.EscapeDataString(timestamp)}.tnpkg";
        using var response = await _http.GetAsync($"{BaseUrl}{path}", cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone)
        {
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("GET", path, response, cancellationToken)
                .ConfigureAwait(false);
        }

        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Publish a signed package snapshot to the authenticated account inbox.
    /// </summary>
    public async Task<VaultInboxSnapshot> PostInboxSnapshotAsync(
        string fromDid,
        string ceremonyId,
        string timestamp,
        byte[] package,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(fromDid))
        {
            throw new ArgumentException("Publisher DID must not be empty.", nameof(fromDid));
        }

        if (string.IsNullOrWhiteSpace(ceremonyId))
        {
            throw new ArgumentException("Ceremony id must not be empty.", nameof(ceremonyId));
        }

        if (string.IsNullOrWhiteSpace(timestamp))
        {
            throw new ArgumentException("Timestamp must not be empty.", nameof(timestamp));
        }

        ArgumentNullException.ThrowIfNull(package);
        var path = $"/api/v1/inbox/{Uri.EscapeDataString(fromDid)}/snapshots/{Uri.EscapeDataString(ceremonyId)}/{Uri.EscapeDataString(timestamp)}.tnpkg";
        using var content = new ByteArrayContent(package);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var response = await _http.PostAsync($"{BaseUrl}{path}", content, cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("POST", path, response, cancellationToken)
                .ConfigureAwait(false);
        }

        var obj = await ParseObjectResponseAsync(response, "inbox snapshot response", cancellationToken)
            .ConfigureAwait(false);
        return ParseInboxSnapshot(obj);
    }

    /// <summary>
    /// Post an encrypted full-keystore package to the unauthenticated pending-claims endpoint.
    /// </summary>
    public async Task<(string VaultId, string ExpiresAt)> PostPendingClaimAsync(
        byte[] body,
        string? projectName = null,
        string? publisherDid = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(body);
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{BaseUrl}/api/v1/pending-claims")
        {
            Content = content,
        };
        if (!string.IsNullOrWhiteSpace(projectName))
        {
            request.Headers.TryAddWithoutValidation("X-Project-Name", projectName);
        }

        if (!string.IsNullOrWhiteSpace(publisherDid))
        {
            request.Headers.TryAddWithoutValidation("X-Publisher-Did", publisherDid);
        }

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await VaultStatusErrorAsync("POST", "/api/v1/pending-claims", response, cancellationToken)
                .ConfigureAwait(false);
        }

        var obj = await ParseObjectResponseAsync(response, "pending-claim response", cancellationToken)
            .ConfigureAwait(false);
        var vaultId = NonEmpty(obj["vault_id"]?.GetValue<string>())
            ?? throw new VaultException("pending-claim response missing vault_id");
        var expiresAt = NonEmpty(obj["expires_at"]?.GetValue<string>())
            ?? throw new VaultException("pending-claim response missing expires_at");
        return (vaultId, expiresAt);
    }

    /// <summary>
    /// Create a vault project, or reuse an existing project with the same name on 409.
    /// </summary>
    public async Task<VaultProject> EnsureProjectAsync(
        string name,
        string? ceremonyId = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await CreateProjectAsync(name, ceremonyId, cancellationToken).ConfigureAwait(false);
        }
        catch (VaultException ex) when (ex.StatusCode == (int)HttpStatusCode.Conflict)
        {
            var projects = await ListProjectsAsync(cancellationToken).ConfigureAwait(false);
            return projects.FirstOrDefault(project => string.Equals(project.Name, name, StringComparison.Ordinal))
                ?? throw new VaultException(
                    $"vault returned 409 for project {name} but list returned no match",
                    ex.StatusCode,
                    ex.Body);
        }
    }

    private static async Task<VaultProject> ParseProjectResponseAsync(
        HttpResponseMessage response,
        string? fallbackName,
        CancellationToken cancellationToken)
    {
        var obj = await ParseObjectResponseAsync(response, "vault project response", cancellationToken)
            .ConfigureAwait(false);
        return ParseProject(obj, fallbackName);
    }

    private static async Task<JsonObject> ParseObjectResponseAsync(
        HttpResponseMessage response,
        string context,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false) as JsonObject
            ?? throw new VaultException($"{context} must be a JSON object");
    }

    private static VaultProject ParseProject(JsonObject obj, string? fallbackName = null)
    {
        var id = NonEmpty(obj["id"]?.GetValue<string>())
            ?? NonEmpty(obj["_id"]?.GetValue<string>())
            ?? throw new VaultException("vault project response missing id");
        var name = NonEmpty(obj["name"]?.GetValue<string>()) ?? fallbackName ?? id;
        var ceremonyId = NonEmpty(obj["ceremony_id"]?.GetValue<string>());
        return new VaultProject(id, name, ceremonyId);
    }

    private static VaultAccountInboxItem ParseAccountInboxItem(JsonObject obj)
    {
        var publisherIdentity = NonEmpty(obj["publisher_identity"]?.GetValue<string>())
            ?? NonEmpty(obj["from_did"]?.GetValue<string>())
            ?? throw new VaultException("account inbox item missing publisher_identity");
        var ceremonyId = NonEmpty(obj["ceremony_id"]?.GetValue<string>())
            ?? throw new VaultException("account inbox item missing ceremony_id");
        var timestamp = NonEmpty(obj["ts"]?.GetValue<string>())
            ?? throw new VaultException("account inbox item missing ts");
        var consumedAt = NonEmpty(obj["consumed_at"]?.GetValue<string>());
        return new VaultAccountInboxItem(publisherIdentity, ceremonyId, timestamp, consumedAt);
    }

    private static VaultInboxSnapshot ParseInboxSnapshot(JsonObject obj)
    {
        var storedPath = NonEmpty(obj["stored_path"]?.GetValue<string>())
            ?? throw new VaultException("inbox snapshot response missing stored_path");
        var byteSize = obj["byte_size"]?.GetValue<ulong>()
            ?? throw new VaultException("inbox snapshot response missing byte_size");
        var manifestSignature = NonEmpty(obj["manifest_signature_b64"]?.GetValue<string>())
            ?? throw new VaultException("inbox snapshot response missing manifest_signature_b64");
        var headRowHash = NonEmpty(obj["head_row_hash"]?.GetValue<string>());
        return new VaultInboxSnapshot(storedPath, byteSize, manifestSignature, headRowHash);
    }

    private static async Task<VaultException> VaultStatusErrorAsync(
        string method,
        string path,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (body.Length > 512)
        {
            body = body[..512];
        }

        return new VaultException(
            $"{method} {path} returned {(int)response.StatusCode}",
            (int)response.StatusCode,
            body);
    }

    private static string NormalizeBaseUrl(string baseUrl)
    {
        return baseUrl.Trim().TrimEnd('/');
    }

    private static string? NonEmpty(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
