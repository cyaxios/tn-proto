using System.Text;

namespace TnProto.Tests;

public sealed class CanonicalTests
{
    [Theory]
    [InlineData("{}", "{}", "7b7d")]
    [InlineData("{\"a\":\"hello\"}", "{\"a\":\"hello\"}", "7b2261223a2268656c6c6f227d")]
    [InlineData(
        "{\"b\":1,\"a\":{\"z\":2,\"y\":1}}",
        "{\"a\":{\"y\":1,\"z\":2},\"b\":1}",
        "7b2261223a7b2279223a312c227a223a327d2c2262223a317d")]
    [InlineData(
        "{\"xs\":[1,\"two\",null,true,3.5]}",
        "{\"xs\":[1,\"two\",null,true,3.5]}",
        "7b227873223a5b312c2274776f222c6e756c6c2c747275652c332e355d7d")]
    [InlineData(
        "{\"a\":true,\"b\":false,\"c\":null}",
        "{\"a\":true,\"b\":false,\"c\":null}",
        "7b2261223a747275652c2262223a66616c73652c2263223a6e756c6c7d")]
    public void JsonFromRawAndBytesHexFromRawMatchGoldenVectors(
        string input,
        string expectedJson,
        string expectedHex)
    {
        var canonicalJson = TnCanonical.JsonFromRaw(input);
        var bytes = TnCanonical.BytesFromRaw(input);
        var hex = TnCanonical.BytesHexFromRaw(input);

        Assert.Equal(expectedJson, canonicalJson);
        Assert.Equal(Encoding.UTF8.GetBytes(expectedJson), bytes);
        Assert.Equal(expectedHex, hex);
    }

    [Fact]
    public void JsonSerializesAnonymousObjectsThroughSharedCanonicalizer()
    {
        var canonicalJson = TnCanonical.Json(new
        {
            b = 1,
            a = new
            {
                z = 2,
                y = 1,
            },
        });

        Assert.Equal("{\"a\":{\"y\":1,\"z\":2},\"b\":1}", canonicalJson);
    }

    [Fact]
    public void BytesHexFromRawPreservesUtf8AndSentinelShape()
    {
        Assert.Equal(
            "7b226e616d65223a22636166c3a920e29895227d",
            TnCanonical.BytesHexFromRaw("{\"name\":\"caf\u00e9 \u2615\"}"));
        Assert.Equal(
            "{\"k\":{\"$b64\":\"AAEC\"}}",
            TnCanonical.JsonFromRaw("{\"k\":{\"$b64\":\"AAEC\"}}"));
    }

    [Fact]
    public void InvalidJsonReturnsTnException()
    {
        var error = Assert.Throws<TnException>(() => TnCanonical.JsonFromRaw("{"));

        Assert.Contains("valid JSON", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EmptyRawJsonFailsBeforeNativeCall()
    {
        var error = Assert.Throws<ArgumentException>(() => TnCanonical.JsonFromRaw(""));

        Assert.Equal("valueJson", error.ParamName);
    }
}
