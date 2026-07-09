namespace TnProto.Tests;

public sealed class ApiKeyTests
{
    [Fact]
    public void ParseAcceptsValidFixedLengthApiKey()
    {
        var seed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var keyIdBytes = Enumerable.Range(100, 16).Select(i => (byte)i).ToArray();
        var apiKey = BuildApiKey(seed, keyIdBytes);

        var parsed = TnApiKey.Parse(apiKey);

        Assert.Equal(apiKey, parsed.Raw);
        Assert.Equal(seed, parsed.Seed);
        Assert.Equal(Base64UrlNoPadding(keyIdBytes), parsed.KeyId);
        Assert.Equal(keyIdBytes, parsed.KeyIdBytes);
        Assert.Equal(TnIdentity.FromSeed(seed), parsed.Identity);
        Assert.StartsWith("did:key:z", parsed.Did, StringComparison.Ordinal);
    }

    [Fact]
    public void TryParseAcceptsSeedContainingUnderscore()
    {
        var seed = FindSeedWhoseBase64UrlContains('_');
        var keyIdBytes = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var apiKey = BuildApiKey(seed, keyIdBytes);

        Assert.Contains("_", apiKey, StringComparison.Ordinal);

        Assert.True(TnApiKey.TryParse(apiKey, out var parsed));
        Assert.Equal(seed, parsed.Seed);
        Assert.Equal(keyIdBytes, parsed.KeyIdBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-an-api-key")]
    [InlineData("tn_api_key_not-the-right-prefix")]
    public void TryParseRejectsWrongPrefixOrEmptyInput(string apiKey)
    {
        Assert.False(TnApiKey.TryParse(apiKey, out _));
    }

    [Fact]
    public void TryParseRejectsWrongTotalLength()
    {
        var apiKey = BuildApiKey(new byte[32], new byte[16]);

        Assert.False(TnApiKey.TryParse(apiKey + "a", out _));
        Assert.False(TnApiKey.TryParse(apiKey[..^1], out _));
    }

    [Fact]
    public void TryParseRejectsMissingFixedSeparator()
    {
        var apiKey = BuildApiKey(new byte[32], new byte[16]);
        var chars = apiKey.ToCharArray();
        chars["tn_apikey_".Length + 43] = '-';

        Assert.False(TnApiKey.TryParse(new string(chars), out _));
    }

    [Fact]
    public void TryParseRejectsBadSeedBase64()
    {
        var apiKey = BuildApiKey(new byte[32], new byte[16]);
        var chars = apiKey.ToCharArray();
        chars["tn_apikey_".Length] = '*';

        Assert.False(TnApiKey.TryParse(new string(chars), out _));
    }

    [Fact]
    public void TryParseRejectsBadKeyIdBase64()
    {
        var apiKey = BuildApiKey(new byte[32], new byte[16]);
        var chars = apiKey.ToCharArray();
        chars[^1] = '*';

        Assert.False(TnApiKey.TryParse(new string(chars), out _));
    }

    [Fact]
    public void ParseThrowsForMalformedApiKey()
    {
        var error = Assert.Throws<FormatException>(() => TnApiKey.Parse("tn_apikey_bad"));

        Assert.Contains("tn_apikey", error.Message, StringComparison.Ordinal);
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

    private static byte[] FindSeedWhoseBase64UrlContains(char character)
    {
        for (var i = 0; i < 256; i++)
        {
            var seed = Enumerable.Repeat((byte)i, 32).ToArray();
            if (Base64UrlNoPadding(seed).Contains(character, StringComparison.Ordinal))
            {
                return seed;
            }
        }

        throw new InvalidOperationException("Could not find a seed for the test fixture.");
    }
}
