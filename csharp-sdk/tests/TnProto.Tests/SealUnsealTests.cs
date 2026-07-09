using System.Text.Json.Nodes;

namespace TnProto.Tests;

public sealed class SealUnsealTests
{
    private const string ZeroHash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    private static string NewProjectDir()
    {
        return Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
    }

    private static SealOptions NoReceipt()
    {
        return new SealOptions { Receipt = false };
    }

    private static string AdminLogPath(Tn tn)
    {
        var yamlDir = Path.GetDirectoryName(tn.YamlPath)
            ?? throw new InvalidOperationException("yaml path has no directory");
        return Path.Combine(yamlDir, "admin", "default.ndjson");
    }

    /// <summary>
    /// Read a log file the live native runtime still holds open for
    /// append. .NET's plain ReadAllText denies write sharing, which on
    /// Windows collides with the writer's open handle.
    /// </summary>
    private static async Task<string> ReadSharedAsync(string path)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

    [Fact]
    public async Task SealReturnsStandaloneEnvelope()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var sealedObject = await tn.SealAsync(
            "obj.invoice.v1",
            new { amount = 9800, customer = "acme" },
            NoReceipt());

        // Standalone conventions: detached from any chain, always marked.
        Assert.Equal(0, sealedObject.Envelope["sequence"]?.GetValue<int>());
        Assert.Equal("", sealedObject.Envelope["prev_hash"]?.GetValue<string>());
        Assert.Equal(1, sealedObject.TnSealed);
        Assert.Equal("obj.invoice.v1", sealedObject.EventType);
        Assert.Equal(tn.Did, sealedObject.DeviceIdentity);
        Assert.False(string.IsNullOrEmpty(sealedObject.RowHash));

        // Fields ride encrypted, never in the clear.
        Assert.False(sealedObject.Envelope.ContainsKey("amount"));
        Assert.False(sealedObject.Envelope.ContainsKey("customer"));
        var defaultBlock = sealedObject.Envelope["default"] as JsonObject;
        Assert.NotNull(defaultBlock);
        Assert.False(string.IsNullOrEmpty(defaultBlock["ciphertext"]?.GetValue<string>()));

        // ToString IS the wire line: verbatim, newline-free, reparseable.
        Assert.Equal(sealedObject.RawJson, sealedObject.ToString());
        Assert.False(sealedObject.RawJson.EndsWith('\n'));
        var reparsed = SealedObject.FromJson(sealedObject.ToString());
        Assert.Equal(sealedObject.RowHash, reparsed.RowHash);
        Assert.Equal(sealedObject.RawJson, reparsed.RawJson);
    }

    [Fact]
    public async Task SealRejectsReservedField()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var error = await Assert.ThrowsAsync<TnException>(() =>
            tn.SealAsync("obj.test.v1", new { tn_sealed = 1 }, NoReceipt()));

        Assert.Contains("tn_sealed", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SealDoesNotDisturbChain()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        await tn.SealAsync("obj.chain.v1", new { x = 1 }, NoReceipt());

        // Chains are per-event_type: log the SAME type the seal used. Had
        // seal advanced that chain, this row would be sequence 2 with a
        // real prev_hash instead of the genesis link.
        var receipt = await tn.LogAsync("obj.chain.v1", new { y = 2 });

        Assert.NotNull(receipt.Envelope);
        Assert.Equal(1, receipt.Envelope["sequence"]?.GetValue<int>());
        Assert.Equal(ZeroHash, receipt.Envelope["prev_hash"]?.GetValue<string>());
    }

    [Fact]
    public async Task UnsealRoundtripOwnCeremony()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var sealedObject = await tn.SealAsync(
            "obj.invoice.v1",
            new { amount = 9800, customer = "acme" },
            NoReceipt());

        var result = await tn.UnsealAsync(sealedObject);

        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Empty(result.HiddenGroups);
        Assert.Empty(result.SealedBlocks);

        // Fields carry exactly the sealed fields; the tn_sealed wire
        // marker never leaks into user fields.
        Assert.Equal(2, result.Fields.Count);
        Assert.Equal(9800, result.Fields["amount"]?.GetValue<int>());
        Assert.Equal("acme", result.Fields["customer"]?.GetValue<string>());
        Assert.False(result.Fields.ContainsKey("tn_sealed"));

        // The wire-faithful envelope keeps the marker; plaintext is
        // reported per opened group.
        Assert.Equal(1, result.Envelope["tn_sealed"]?.GetValue<int>());
        var defaultPlaintext = Assert.Contains("default", result.Plaintext);
        Assert.Equal(9800, defaultPlaintext["amount"]?.GetValue<int>());
    }

    [Fact]
    public async Task UnsealTamperedRaisesTnVerifyException()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var sealedObject = await tn.SealAsync("obj.invoice.v1", new { amount = 1 }, NoReceipt());
        var tampered = sealedObject.RawJson.Replace(
            "\"tn_sealed\":1",
            "\"tn_sealed\":2",
            StringComparison.Ordinal);
        Assert.NotEqual(sealedObject.RawJson, tampered);

        var error = await Assert.ThrowsAsync<TnVerifyException>(() => tn.UnsealAsync(tampered));

        // A tampered public value flips the recomputed row hash; the
        // signature over the untouched row_hash string still verifies.
        Assert.Equal(["row_hash"], error.FailedChecks);
        Assert.Equal(0, error.Sequence);
        Assert.Equal("obj.invoice.v1", error.EventType);
    }

    [Fact]
    public async Task UnsealMalformedRaisesTnUnsealException()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        await Assert.ThrowsAsync<TnUnsealException>(() =>
            tn.UnsealAsync("not a sealed object at all"));
        await Assert.ThrowsAsync<TnUnsealException>(() =>
            tn.UnsealAsync("[1,2,3]"));
        await Assert.ThrowsAsync<TnUnsealException>(() =>
            tn.UnsealAsync("{\"just\":\"json\"}"));
    }

    [Fact]
    public async Task UnsealVerifyFalseReturnsDespiteTamper()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var sealedObject = await tn.SealAsync("obj.invoice.v1", new { amount = 1 }, NoReceipt());
        var tampered = sealedObject.RawJson.Replace(
            "\"tn_sealed\":1",
            "\"tn_sealed\":2",
            StringComparison.Ordinal);

        var result = await tn.UnsealAsync(tampered, new UnsealOptions { Verify = false });

        // verify:false skips the gate and reports both checks unverified.
        Assert.False(result.Valid.Signature);
        Assert.False(result.Valid.RowHash);
        // The ciphertext itself is untouched, so the block still opens.
        Assert.Equal(1, result.Fields["amount"]?.GetValue<int>());
    }

    [Fact]
    public async Task UnsealNoKeyReturnsPublicFrame()
    {
        string wire;
        await using (var publisher = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() }))
        {
            var sealedObject = await publisher.SealAsync(
                "obj.memo.v1",
                new { body = "private" },
                NoReceipt());
            wire = sealedObject.RawJson;
        }

        // A different ceremony holds no fitting key: no exception, the
        // verified public frame comes back with the block left sealed.
        await using var stranger = await Tn.InitProjectAsync(
            "sealing_other",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var result = await stranger.UnsealAsync(wire);

        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Equal(["default"], result.HiddenGroups);
        Assert.Empty(result.Plaintext);
        Assert.False(result.Fields.ContainsKey("body"));

        var block = Assert.Single(result.SealedBlocks);
        Assert.Equal("default", block.Name);
        Assert.False(string.IsNullOrEmpty(block.CiphertextB64));
        Assert.Contains("body", block.FieldHashes.Keys);
        Assert.Equal("", block.AadB64);
    }

    [Fact]
    public async Task SealReceiptTogglesAdminRow()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });
        var adminLog = AdminLogPath(tn);

        await tn.SealAsync("obj.invoice.v1", new { amount = 1 }, NoReceipt());
        var afterSilent = File.Exists(adminLog) ? await ReadSharedAsync(adminLog) : "";
        Assert.DoesNotContain("tn.object.sealed", afterSilent, StringComparison.Ordinal);

        var sealedObject = await tn.SealAsync("obj.invoice.v1", new { amount = 2 });
        var receiptLine = (await ReadSharedAsync(adminLog))
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => JsonNode.Parse(line) as JsonObject)
            .Single(row => row?["event_type"]?.GetValue<string>() == "tn.object.sealed");

        Assert.NotNull(receiptLine);
        // The receipt payload rides encrypted in the default group; the
        // field-hash tokens name what it commits to.
        var fieldHashes = receiptLine["default"]?["field_hashes"] as JsonObject;
        Assert.NotNull(fieldHashes);
        Assert.True(fieldHashes.ContainsKey("object_id"));
        Assert.True(fieldHashes.ContainsKey("object_type"));
        Assert.True(fieldHashes.ContainsKey("groups"));
        // Unused but proves the sealed object itself never landed there.
        Assert.NotEqual(
            sealedObject.RowHash,
            receiptLine["row_hash"]?.GetValue<string>());
    }

    [Fact]
    public async Task SealAadRoundtripsAndTamperFails()
    {
        await using var tn = await Tn.InitProjectAsync(
            "sealing",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var sealedObject = await tn.SealAsync(
            "obj.case.v1",
            new { note = "sealed note" },
            new SealOptions
            {
                Receipt = false,
                Aad = new Dictionary<string, object?> { ["case"] = "A-17" },
            });

        // The effective marker is echoed, signed, under the public tn_aad
        // field as a canonical JSON string.
        var echo = sealedObject.Envelope["tn_aad"]?.GetValue<string>();
        Assert.NotNull(echo);
        var binding = JsonNode.Parse(echo) as JsonObject;
        Assert.Equal("A-17", binding?["default"]?["case"]?.GetValue<string>());

        var result = await tn.UnsealAsync(sealedObject);
        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Equal("sealed note", result.Fields["note"]?.GetValue<string>());

        // The echo feeds the row hash: tampering it far from the seal
        // call fails verification loudly.
        var tampered = sealedObject.RawJson.Replace("A-17", "B-99", StringComparison.Ordinal);
        Assert.NotEqual(sealedObject.RawJson, tampered);
        var error = await Assert.ThrowsAsync<TnVerifyException>(() => tn.UnsealAsync(tampered));
        Assert.Contains("row_hash", error.FailedChecks);
    }
}
