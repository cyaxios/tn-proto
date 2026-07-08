using System.Text.Json.Nodes;

namespace TnProto.Tests;

public sealed class IdentityTests
{
    [Fact]
    public async Task LoadOrCreateCreatesSeedFileOnFirstUse()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var seedPath = Path.Combine(tempDir, "identity", "local.private");

        var result = await TnIdentity.LoadOrCreateAsync(seedPath);

        Assert.True(result.Created);
        Assert.Equal(Path.GetFullPath(seedPath), result.Path);
        Assert.True(File.Exists(seedPath));
        Assert.Equal(32, new FileInfo(seedPath).Length);
        Assert.Equal(await File.ReadAllBytesAsync(seedPath), result.Identity.Seed);
    }

    [Fact]
    public async Task LoadOrCreateLoadsExistingSeedOnSecondUse()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var seedPath = Path.Combine(tempDir, "local.private");

        var created = await TnIdentity.LoadOrCreateAsync(seedPath);
        var loaded = await TnIdentity.LoadOrCreateAsync(seedPath);

        Assert.True(created.Created);
        Assert.False(loaded.Created);
        Assert.Equal(created.Identity, loaded.Identity);
    }

    [Fact]
    public async Task LoadAsyncDerivesIdentityFromExistingRawSeed()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var seedPath = Path.Combine(tempDir, "local.private");
        var seed = Enumerable.Repeat((byte)21, 32).ToArray();
        Directory.CreateDirectory(tempDir);
        await File.WriteAllBytesAsync(seedPath, seed);

        var loaded = await TnIdentity.LoadAsync(seedPath);

        Assert.Equal(TnIdentity.FromSeed(seed), loaded);
    }

    [Fact]
    public async Task LoadAsyncRejectsMalformedSeedFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var seedPath = Path.Combine(tempDir, "local.private");
        Directory.CreateDirectory(tempDir);
        await File.WriteAllBytesAsync(seedPath, new byte[31]);

        var error = await Assert.ThrowsAsync<ArgumentException>(() => TnIdentity.LoadAsync(seedPath));

        Assert.Equal("seed", error.ParamName);
    }

    [Fact]
    public void DefaultIdentityPathHonorsTnIdentityDir()
    {
        var prior = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var overrideDir = Path.Combine(Path.GetTempPath(), "tn-csharp-identity-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", overrideDir);

            Assert.Equal(
                Path.GetFullPath(Path.Combine(overrideDir, "identity.json")),
                TnIdentity.DefaultIdentityPath());
            Assert.Equal(Path.GetFullPath(overrideDir), TnIdentity.DefaultIdentityDirectory());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", prior);
        }
    }

    [Fact]
    public void DefaultIdentityPathHonorsXdgDataHomeWhenIdentityDirIsUnset()
    {
        var priorIdentityDir = Environment.GetEnvironmentVariable("TN_IDENTITY_DIR");
        var priorXdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        var xdg = Path.Combine(Path.GetTempPath(), "tn-csharp-xdg-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", null);
            Environment.SetEnvironmentVariable("XDG_DATA_HOME", xdg);

            Assert.Equal(
                Path.GetFullPath(Path.Combine(xdg, "tn", "identity.json")),
                TnIdentity.DefaultIdentityPath());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TN_IDENTITY_DIR", priorIdentityDir);
            Environment.SetEnvironmentVariable("XDG_DATA_HOME", priorXdg);
        }
    }

    [Fact]
    public async Task SaveJsonAsyncWritesPythonTypeScriptIdentitySchema()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        var identity = TnIdentity.FromSeed(Enumerable.Repeat((byte)13, 32).ToArray());

        var savedPath = await TnIdentity.SaveJsonAsync(
            identity,
            identityPath,
            new IdentityJsonOptions
            {
                LinkedVault = "https://vault.example.test",
                LinkedAccountId = "acct_csharp",
            });

        Assert.Equal(Path.GetFullPath(identityPath), savedPath);

        var doc = JsonNode.Parse(await File.ReadAllTextAsync(identityPath))!.AsObject();
        Assert.Equal(1, doc["version"]!.GetValue<int>());
        Assert.Equal(identity.Did, doc["did"]!.GetValue<string>());
        Assert.Equal("none", doc["device_priv_enc_method"]!.GetValue<string>());
        Assert.Equal("https://vault.example.test", doc["linked_vault"]!.GetValue<string>());
        Assert.Equal("acct_csharp", doc["linked_account_id"]!.GetValue<string>());
        Assert.NotNull(doc["prefs"]);

        var privateSeed = doc["device_priv_b64_enc"]!.GetValue<string>();
        var publicKey = doc["device_pub_b64"]!.GetValue<string>();
        var seed = doc["seed_b64"]!.GetValue<string>();
        Assert.DoesNotContain("=", privateSeed);
        Assert.DoesNotContain("+", privateSeed);
        Assert.DoesNotContain("/", privateSeed);
        Assert.DoesNotContain("=", publicKey);
        Assert.DoesNotContain("=", seed);

        var loaded = await TnIdentity.LoadJsonAsync(identityPath);

        Assert.Equal(identity, loaded.Identity);
        Assert.Equal(Path.GetFullPath(identityPath), loaded.Path);
        Assert.Equal(1, loaded.Version);
        Assert.Equal("none", loaded.DevicePrivateEncryptionMethod);
        Assert.Equal(seed, loaded.SeedBase64Url);
        Assert.Equal("https://vault.example.test", loaded.LinkedVault);
        Assert.Equal("acct_csharp", loaded.LinkedAccountId);
    }

    [Fact]
    public async Task LoadJsonAsyncRejectsMismatchedDid()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        var identity = TnIdentity.FromSeed(Enumerable.Repeat((byte)14, 32).ToArray());
        await TnIdentity.SaveJsonAsync(identity, identityPath);

        var doc = JsonNode.Parse(await File.ReadAllTextAsync(identityPath))!.AsObject();
        doc["did"] = "did:key:zMismatch";
        await File.WriteAllTextAsync(identityPath, doc.ToJsonString());

        var error = await Assert.ThrowsAsync<TnException>(() => TnIdentity.LoadJsonAsync(identityPath));

        Assert.Contains("did", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoadOrCreateHonorsCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            TnIdentity.LoadOrCreateAsync(
                Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"), "local.private"),
                cts.Token));
    }

    [Fact]
    public void FromSeedDerivesStableDid()
    {
        var seed = Enumerable.Repeat((byte)7, 32).ToArray();

        var first = TnIdentity.FromSeed(seed);
        var second = TnIdentity.FromSeed(seed);

        Assert.Equal(first, second);
        Assert.Equal(seed, first.Seed);
        Assert.Equal(32, first.PublicKey.Length);
        Assert.StartsWith("did:key:z", first.Did, StringComparison.Ordinal);
    }

    [Fact]
    public void FromSeedDerivesDifferentDidForDifferentSeed()
    {
        var first = TnIdentity.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray());
        var second = TnIdentity.FromSeed(Enumerable.Repeat((byte)8, 32).ToArray());

        Assert.NotEqual(first.Did, second.Did);
        Assert.NotEqual(first.PublicKeyBase64, second.PublicKeyBase64);
    }

    [Fact]
    public void GenerateReturnsFreshIdentityMaterial()
    {
        var identity = TnIdentity.Generate();

        Assert.Equal(32, identity.Seed.Length);
        Assert.Equal(32, identity.PublicKey.Length);
        Assert.StartsWith("did:key:z", identity.Did, StringComparison.Ordinal);
    }

    [Fact]
    public void FromSeedRejectsWrongSeedLengthBeforeNativeCall()
    {
        var error = Assert.Throws<ArgumentException>(() => TnIdentity.FromSeed(new byte[31]));

        Assert.Equal("seed", error.ParamName);
    }

    [Fact]
    public void FromSeedBase64RejectsMalformedBase64BeforeNativeCall()
    {
        var error = Assert.Throws<FormatException>(() => TnIdentity.FromSeedBase64("not base64"));

        Assert.Contains("base-64", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FromMnemonicDerivesStableIdentity()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        var first = TnIdentity.FromMnemonic(words);
        var second = TnIdentity.FromMnemonic(words);

        Assert.Equal(first, second);
        Assert.Equal(words, first.Mnemonic);
        Assert.Equal(32, first.Identity.Seed.Length);
        Assert.Equal(32, first.Identity.PublicKey.Length);
        Assert.StartsWith("did:key:z", first.Identity.Did, StringComparison.Ordinal);
        Assert.Equal(86, first.IdentitySeedBase64Url.Length);
        Assert.DoesNotContain("=", first.IdentitySeedBase64Url);
    }

    [Fact]
    public void FromMnemonicUsesPassphraseInDerivation()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        var withoutPassphrase = TnIdentity.FromMnemonic(words);
        var withPassphrase = TnIdentity.FromMnemonic(words, "TREZOR");

        Assert.NotEqual(withoutPassphrase.Identity.Did, withPassphrase.Identity.Did);
        Assert.NotEqual(withoutPassphrase.IdentitySeedBase64Url, withPassphrase.IdentitySeedBase64Url);
    }

    [Fact]
    public void FromMnemonicRejectsInvalidChecksum()
    {
        var error = Assert.Throws<TnException>(() =>
            TnIdentity.FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));

        Assert.Contains("mnemonic", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveJsonAsyncCanPersistMnemonicDerivedIdentitySeed()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        var restored = TnIdentity.FromMnemonic(words);

        await TnIdentity.SaveJsonAsync(
            restored.Identity,
            identityPath,
            new IdentityJsonOptions
            {
                SeedBase64Url = restored.IdentitySeedBase64Url,
                MnemonicStored = restored.Mnemonic,
            });

        var loaded = await TnIdentity.LoadJsonAsync(identityPath);

        Assert.Equal(restored.Identity, loaded.Identity);
        Assert.Equal(restored.IdentitySeedBase64Url, loaded.SeedBase64Url);
        Assert.Equal(words, loaded.MnemonicStored);
    }

    [Fact]
    public async Task ExportMnemonicAsyncReturnsPersistedMnemonic()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        var restored = TnIdentity.FromMnemonic(words);
        await TnIdentity.SaveJsonAsync(
            restored.Identity,
            identityPath,
            new IdentityJsonOptions
            {
                SeedBase64Url = restored.IdentitySeedBase64Url,
                MnemonicStored = restored.Mnemonic,
            });

        var exported = await TnIdentity.ExportMnemonicAsync(identityPath);

        Assert.Equal(words, exported);
    }

    [Fact]
    public async Task ExportMnemonicAsyncRejectsWhenMnemonicWasNotPersisted()
    {
        const string words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        var restored = TnIdentity.FromMnemonic(words);
        await TnIdentity.SaveJsonAsync(
            restored.Identity,
            identityPath,
            new IdentityJsonOptions { SeedBase64Url = restored.IdentitySeedBase64Url });

        var error = await Assert.ThrowsAsync<TnException>(() => TnIdentity.ExportMnemonicAsync(identityPath));

        Assert.Contains("no mnemonic stored", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportMnemonicAsyncRejectsWhitespaceMnemonic()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var identityPath = Path.Combine(tempDir, "identity.json");
        var identity = TnIdentity.FromSeed(Enumerable.Repeat((byte)15, 32).ToArray());
        await TnIdentity.SaveJsonAsync(
            identity,
            identityPath,
            new IdentityJsonOptions { MnemonicStored = "   " });

        var error = await Assert.ThrowsAsync<TnException>(() => TnIdentity.ExportMnemonicAsync(identityPath));

        Assert.Contains("no mnemonic stored", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SignAndVerifyDidAcceptsMatchingIdentityAndMessage()
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var identity = TnIdentity.FromSeed(seed);
        var message = "hello identity"u8.ToArray();

        var signature = TnIdentity.Sign(seed, message);

        Assert.NotEmpty(signature);
        Assert.DoesNotContain("=", signature);
        Assert.True(TnIdentity.VerifyDid(identity.Did, message, signature));
    }

    [Fact]
    public void VerifyDidRejectsTamperedMessage()
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var identity = TnIdentity.FromSeed(seed);
        var signature = TnIdentity.Sign(seed, "hello identity"u8.ToArray());

        var valid = TnIdentity.VerifyDid(identity.Did, "HELLO identity"u8.ToArray(), signature);

        Assert.False(valid);
    }

    [Fact]
    public void VerifyDidRejectsWrongDidWithoutThrowing()
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var other = TnIdentity.FromSeed(Enumerable.Repeat((byte)10, 32).ToArray());
        var signature = TnIdentity.Sign(seed, "hello identity"u8.ToArray());

        var valid = TnIdentity.VerifyDid(other.Did, "hello identity"u8.ToArray(), signature);

        Assert.False(valid);
    }

    [Fact]
    public void SignBase64UsesTheSameSignatureAsRawSeed()
    {
        var seed = Enumerable.Repeat((byte)12, 32).ToArray();
        var message = "same message"u8.ToArray();

        var rawSignature = TnIdentity.Sign(seed, message);
        var base64Signature = TnIdentity.SignBase64(Convert.ToBase64String(seed), message);

        Assert.Equal(rawSignature, base64Signature);
    }

    [Fact]
    public void VerifyDidRejectsMalformedSignature()
    {
        var identity = TnIdentity.FromSeed(Enumerable.Repeat((byte)9, 32).ToArray());

        var error = Assert.Throws<TnException>(() =>
            TnIdentity.VerifyDid(identity.Did, "hello identity"u8.ToArray(), "not a signature"));

        Assert.Contains("base64", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SignRejectsWrongSeedLengthBeforeNativeCall()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            TnIdentity.Sign(new byte[31], "hello"u8.ToArray()));

        Assert.Equal("seed", error.ParamName);
    }
}
