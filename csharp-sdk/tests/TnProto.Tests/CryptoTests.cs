using System.Text.Json;
using System.Text.Json.Nodes;

namespace TnProto.Tests;

public sealed class CryptoTests
{
    [Fact]
    public void SealEnvelopeRawBuildsVerifiablePublicEnvelope()
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var input = new JsonObject
        {
            ["seed_b64"] = Convert.ToBase64String(seed),
            ["event_type"] = "order.created",
            ["level"] = "info",
            ["sequence"] = 1,
            ["prev_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ["timestamp"] = "2026-04-23T12:00:00Z",
            ["event_id"] = "00000000-0000-0000-0000-000000000001",
            ["public_fields"] = new JsonObject
            {
                ["amount"] = 100,
                ["currency"] = "USD",
            },
        };

        var line = TnCrypto.SealEnvelopeRaw(input.ToJsonString());

        Assert.EndsWith("\n", line, StringComparison.Ordinal);
        var envelope = JsonNode.Parse(line) as JsonObject
            ?? throw new InvalidOperationException("seal output was not an object.");
        Assert.Equal("order.created", envelope["event_type"]?.GetValue<string>());
        Assert.Equal(100, envelope["amount"]?.GetValue<int>());
        Assert.Equal("USD", envelope["currency"]?.GetValue<string>());
        Assert.StartsWith("did:key:", envelope["device_identity"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.StartsWith("sha256:", envelope["row_hash"]?.GetValue<string>(), StringComparison.Ordinal);

        var verify = TnCrypto.VerifyEnvelopeRaw(line);

        Assert.True(verify.Valid);
        Assert.True(verify.Signature);
        Assert.Null(verify.Reason);
    }

    [Fact]
    public void SealEnvelopeRawRejectsMissingRequiredFields()
    {
        var error = Assert.Throws<TnException>(() => TnCrypto.SealEnvelopeRaw("""{"seed_b64":"AAAA"}"""));

        Assert.Contains("missing field event_type", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyEnvelopeAcceptsKnownGoodEmittedEnvelope()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await tn.InfoAsync("crypto.verify", new { ok = true });
        var envelope = Assert.IsType<JsonObject>(receipt.Envelope);

        var result = TnCrypto.VerifyEnvelope(envelope);

        Assert.True(result.Valid);
        Assert.True(result.Signature);
        Assert.Null(result.Reason);
    }

    [Fact]
    public async Task VerifyEnvelopeRejectsTamperedRowHash()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await tn.InfoAsync("crypto.verify", new { ok = true });
        var envelope = (JsonObject)Assert.IsType<JsonObject>(receipt.Envelope).DeepClone();
        envelope["row_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        var result = TnCrypto.VerifyEnvelope(envelope);

        Assert.False(result.Valid);
        Assert.False(result.Signature);
        Assert.Contains("signature", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyEnvelopeReportsMissingSignature()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await tn.InfoAsync("crypto.verify", new { ok = true });
        var envelope = (JsonObject)Assert.IsType<JsonObject>(receipt.Envelope).DeepClone();
        envelope.Remove("signature");

        var result = TnCrypto.VerifyEnvelopeRaw(envelope.ToJsonString());

        Assert.False(result.Valid);
        Assert.False(result.Signature);
        Assert.Equal("missing signature", result.Reason);
    }

    [Fact]
    public void VerifyEnvelopeRejectsMalformedJson()
    {
        var error = Assert.Throws<TnException>(() => TnCrypto.VerifyEnvelopeRaw("{"));

        Assert.Contains("valid JSON", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void VerifyEnvelopeRejectsEmptyRawJsonBeforeNativeCall()
    {
        var error = Assert.Throws<ArgumentException>(() => TnCrypto.VerifyEnvelopeRaw(""));

        Assert.Equal("envelopeJson", error.ParamName);
    }
}
