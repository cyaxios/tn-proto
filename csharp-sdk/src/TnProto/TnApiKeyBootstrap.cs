using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using TnProto.Packages;

namespace TnProto;

/// <summary>
/// Cold-start bootstrap helpers for <c>tn_apikey_...</c> values.
/// </summary>
public static class TnApiKeyBootstrap
{
    /// <summary>
    /// Fetch and install the recipient-sealed bootstrap bundle from a cold-start API key.
    /// </summary>
    public static async Task<TnApiKeyBootstrapResult?> BootstrapAsync(
        TnApiKeyBootstrapOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var fetched = await FetchSealedBundleAsync(options, cancellationToken).ConfigureAwait(false);
        if (fetched is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(options.ProjectName))
        {
            throw new ArgumentException("Project name must not be empty.", nameof(options));
        }

        var tn = await Tn.InitProjectAsync(
            options.ProjectName,
            new TnProjectOptions
            {
                ProjectDirectory = options.ProjectDirectory,
                Profile = options.Profile,
                DevicePrivateBytes = fetched.ApiKey.Seed,
            },
            cancellationToken).ConfigureAwait(false);

        try
        {
            var tempPath = Path.Combine(
                Path.GetTempPath(),
                $"tn-api-key-bootstrap-{Guid.NewGuid():N}.tnpkg");
            try
            {
                await File.WriteAllBytesAsync(tempPath, fetched.SealedBytes, cancellationToken)
                    .ConfigureAwait(false);
                var receipt = await tn.Packages.AbsorbAsync(tempPath, cancellationToken)
                    .ConfigureAwait(false);
                return new TnApiKeyBootstrapResult(
                    fetched.ApiKey,
                    fetched.VaultBaseUrl,
                    fetched.Token,
                    fetched.Kind,
                    receipt,
                    tn);
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
        catch
        {
            await tn.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Authenticate with the API-key seed and fetch the recipient-sealed bootstrap bundle.
    /// </summary>
    /// <remarks>
    /// This mirrors the Python/TypeScript cold-start flow through the network
    /// fetch step. It returns <c>null</c> for malformed keys, vault rejection,
    /// consumed/revoked keys, malformed responses, and network errors so callers
    /// can safely fall through to another onboarding path.
    /// </remarks>
    public static async Task<TnApiKeySealedBundleResult?> FetchSealedBundleAsync(
        TnApiKeyBootstrapOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(options.VaultBaseUrl))
        {
            throw new ArgumentException("Vault base URL must not be empty.", nameof(options));
        }

        if (!TnApiKey.TryParse(options.ApiKey, out var apiKey))
        {
            return null;
        }

        var vaultBaseUrl = NormalizeBaseUrl(options.VaultBaseUrl);
        using var ownedClient = options.HttpClient is null ? new HttpClient() : null;
        var http = options.HttpClient ?? ownedClient!;

        string token;
        try
        {
            token = await ChallengeVerifyAsync(http, vaultBaseUrl, apiKey, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }

        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"{vaultBaseUrl}/api/v1/api-keys/{apiKey.KeyId}/sealed-bundle");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone)
            {
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var obj = await ParseObjectResponseAsync(response, cancellationToken).ConfigureAwait(false);
            var sealedBundle = NonEmpty(obj["sealed_bundle_b64"]?.GetValue<string>());
            if (sealedBundle is null)
            {
                return null;
            }

            byte[] sealedBytes;
            try
            {
                sealedBytes = Convert.FromBase64String(sealedBundle);
            }
            catch (FormatException)
            {
                return null;
            }

            return new TnApiKeySealedBundleResult(
                apiKey,
                vaultBaseUrl,
                token,
                sealedBytes,
                NonEmpty(obj["kind"]?.GetValue<string>()));
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static async Task<string> ChallengeVerifyAsync(
        HttpClient http,
        string vaultBaseUrl,
        TnApiKey apiKey,
        CancellationToken cancellationToken)
    {
        using var challenge = await http.PostAsJsonAsync(
            $"{vaultBaseUrl}/api/v1/auth/challenge",
            new JsonObject { ["did"] = apiKey.Did },
            cancellationToken).ConfigureAwait(false);
        if (!challenge.IsSuccessStatusCode)
        {
            throw new HttpRequestException("vault challenge failed");
        }

        var challengeJson = await ParseObjectResponseAsync(challenge, cancellationToken).ConfigureAwait(false);
        var nonce = NonEmpty(challengeJson["nonce"]?.GetValue<string>())
            ?? throw new HttpRequestException("vault challenge response missing nonce");
        var signature = TnIdentity.Sign(apiKey.Seed, Encoding.UTF8.GetBytes(nonce));

        using var verify = await http.PostAsJsonAsync(
            $"{vaultBaseUrl}/api/v1/auth/verify",
            new JsonObject
            {
                ["did"] = apiKey.Did,
                ["nonce"] = nonce,
                ["signature"] = signature,
            },
            cancellationToken).ConfigureAwait(false);
        if (!verify.IsSuccessStatusCode)
        {
            throw new HttpRequestException("vault verify failed");
        }

        var verifyJson = await ParseObjectResponseAsync(verify, cancellationToken).ConfigureAwait(false);
        return NonEmpty(verifyJson["token"]?.GetValue<string>())
            ?? throw new HttpRequestException("vault verify response missing token");
    }

    private static async Task<JsonObject> ParseObjectResponseAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false) as JsonObject
            ?? throw new HttpRequestException("vault response must be a JSON object");
    }

    private static string NormalizeBaseUrl(string baseUrl)
    {
        return baseUrl.Trim().TrimEnd('/');
    }

    private static string? NonEmpty(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
