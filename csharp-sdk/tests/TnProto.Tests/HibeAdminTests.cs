using System.Text.Json.Nodes;

namespace TnProto.Tests;

/// <summary>
/// End-to-end coverage for the hibe admin capability surfaced through
/// <c>AdminClient.GrantReaderAsync</c> / <c>AdminClient.RotateIdPathAsync</c>:
/// a hibe authority ceremony seals content, grants a reader kit, the reader
/// absorbs it and opens the content; rotation moves future seals to a new
/// identity path without re-initializing the runtime.
/// </summary>
public sealed class HibeAdminTests
{
    // BBG HIBE authority material (PublicParams + MasterKey, max depth 4),
    // generated once with crypto/tn-hibe (`tn_hibe::setup(4, OsRng)`) and
    // committed like the tn-core golden fixtures: setup is randomized, so
    // regeneration would change the bytes, but the pair stays valid forever
    // because it is self-consistent. The C# SDK has no in-process pairing
    // crypto, so tests source authority material from this fixture instead
    // of minting it (Python/Rust mint theirs via tn.init(cipher="hibe") /
    // tn_hibe::setup).
    private const string FixtureMpkB64 =
        "AQSX8dOnMZfXlCaVY4xPqawPw2iMT5d0uQWhTjo/FxusWGxV6D/5ehrv+zrwCtsixruZiT9o6bmh" +
        "w4o9DB5saJ7ttvHPY/WL1FnfRpuIay1Wmv93SBbpR4BfFsBuVoWZqditVTsYV/bxQxKWMWr1OLRi" +
        "8mHMrvYIiyr0kgqhDRGora5zAnRICsRmWp/NdLx3SYkZtvR6ed7WnE0kRnHZK3gDobHVGH5fqSt3" +
        "dK88RU8tpFDs4kvVXR01AMzieNn87a+SasgfsnnfGvPbXP2zWiOI+k84xql80AKdZCTVaFTkNaYi" +
        "SsQbwHkueCAm61L6om8McsL/EnVvo5Ij+xLio5AI9/FK0snwSO1PQ+TAbpAUupsVmTFwujAIkc50" +
        "TYvLq/agWBcycNP/R0giSPpKta9XTZSXPNbWG02kDNkpr6+ItwcuAO2RaA70nsd4ffxuWrUFMu4F" +
        "eFBBvNojVQFZRn+qqI2nAp14m5kpp4+ZHDK5RKt0/iNci18h3TkM3UubsRyEm5L5VCAAVMUKlhJ/" +
        "TROGUhGu50qwjDtMH62zD1UZnBGPvnqQCBAu86WiNk7LiCQXnlt9/SGpHVy9vP5EfPFEsfTcIGkM" +
        "q97WF7/wNDrc5awjPbU2wOrmNFTCV2785tGvoa/MIeGFgTUzX5ebtcIfa02olqlZDKjYvj6I3V8N" +
        "sTrxTUNPq+MCyaoSa1cBmbMMCS8T/v4AnnJkeIFWZq+EJSnIOgb8yE7A0Cd/MIpiEpFu6iftIEo/" +
        "DuLRb1UErdSKJ0EmHY15AVuVGOrnzsQH8H3pnB0z2B8NfxfoOGAJWjCsdvAIvtchqeie1nFupAcH" +
        "pdFk1CIhnaGSaY/jY14sLJhQpeHa4XuAiQYkqo6Qfy4xw52MYznPzVd2VRgXK1k=";

    private const string FixtureMskB64 =
        "AZVQdVTcfWVrHYap8Vy7yGwB47sOFxN5EOrCcFP+rnuyh82IimBt7CketgqgCCkNyhIFj42OiP2g" +
        "c2PfkoU/3n5Su1b5zLvpkLyGWDdyoqN2YWQHKsf/j5TVfs7Qh2f3OQ==";

    private const string FixtureIdPath = "acme/objects";

    private static string NewProjectDir()
    {
        return Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
    }

    /// <summary>
    /// Open a hibe authority ceremony: bootstrap a project for the device
    /// key + keystore layout, drop the fixture authority material into the
    /// keystore, rewrite <c>tn.yaml</c> as a hibe ceremony (the same shape
    /// the tn-core tests hand-write), and re-open it.
    /// </summary>
    private static async Task<Tn> OpenHibeAuthorityAsync(string projectDir, string project)
    {
        string did;
        await using (var boot = await Tn.InitProjectAsync(
            project,
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            did = boot.Did;
        }

        var projectRoot = Path.Combine(projectDir, ".tn", project);
        var keysDir = Path.Combine(projectRoot, "keys");
        await File.WriteAllBytesAsync(
            Path.Combine(keysDir, "default.hibe.mpk"),
            Convert.FromBase64String(FixtureMpkB64));
        await File.WriteAllBytesAsync(
            Path.Combine(keysDir, "default.hibe.msk"),
            Convert.FromBase64String(FixtureMskB64));
        // No trailing newline: the file carries exactly the path bytes.
        await File.WriteAllBytesAsync(
            Path.Combine(keysDir, "default.hibe.idpath"),
            System.Text.Encoding.UTF8.GetBytes(FixtureIdPath));

        var yaml =
            "ceremony: {id: cer_hibe_cs, mode: local, cipher: hibe, protocol_events_location: main_log}\n"
            + "keystore: {path: ./keys}\n"
            + $"device: {{device_identity: \"{did}\"}}\n"
            + "public_fields: []\n"
            + "default_policy: private\n"
            + "groups:\n"
            + " default:\n"
            + "   policy: private\n"
            + "   cipher: hibe\n"
            + "   index_epoch: 0\n"
            + "fields: {}\n"
            + "llm_classifier: {enabled: false, provider: \"\", model: \"\"}\n";
        var yamlPath = Path.Combine(projectRoot, "tn.yaml");
        await File.WriteAllTextAsync(yamlPath, yaml);

        return await Tn.InitAsync(yamlPath);
    }

    private static string AuthorityKeysDir(Tn authority)
    {
        var yamlDir = Path.GetDirectoryName(authority.YamlPath)
            ?? throw new InvalidOperationException("yaml path has no directory");
        return Path.Combine(yamlDir, "keys");
    }

    [Fact]
    public async Task GrantReaderKitAbsorbsAndOpensSealedContent()
    {
        await using var authority = await OpenHibeAuthorityAsync(NewProjectDir(), "hibe_auth");
        var sealedObject = await authority.SealAsync(
            "obj.gov.v1",
            new { secret = "for-granted-readers-only" },
            new SealOptions { Receipt = false });

        // Reader: its own (btn) project; the real did:key makes the kit
        // recipient-sealed on export and unsealable on absorb.
        await using var reader = await Tn.InitProjectAsync(
            "hibe_reader",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var kitPath = Path.Combine(Path.GetDirectoryName(authority.YamlPath)!, "reader.tnpkg");
        var grant = await authority.Admin.GrantReaderAsync("default", reader.Did, kitPath);

        Assert.Equal("default", grant.Group);
        Assert.Equal(reader.Did, grant.ReaderDid);
        Assert.Equal(FixtureIdPath, grant.IdPath);
        Assert.True(File.Exists(grant.KitPath));

        // The authority-side grant registry records who got which path.
        var grantsPath = Path.Combine(AuthorityKeysDir(authority), "default.hibe.grants");
        var grants = JsonNode.Parse(await File.ReadAllTextAsync(grantsPath)) as JsonArray;
        Assert.NotNull(grants);
        var row = Assert.Single(grants!) as JsonObject;
        Assert.Equal(reader.Did, row!["reader_did"]?.GetValue<string>());
        Assert.Equal(FixtureIdPath, row["id_path"]?.GetValue<string>());

        var receipt = await reader.Packages.AbsorbAsync(grant.KitPath);
        Assert.Equal("kit_bundle", receipt.Kind);

        var opened = await reader.UnsealAsync(sealedObject);
        Assert.Empty(opened.HiddenGroups);
        Assert.Equal("for-granted-readers-only", opened.Fields["secret"]?.GetValue<string>());
    }

    [Fact]
    public async Task GrantReaderCustomAncestorIdPathDerivesDown()
    {
        await using var authority = await OpenHibeAuthorityAsync(NewProjectDir(), "hibe_auth");
        var sealedObject = await authority.SealAsync(
            "obj.gov.v1",
            new { secret = "s3" },
            new SealOptions { Receipt = false });

        await using var reader = await Tn.InitProjectAsync(
            "hibe_dept",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });

        var kitPath = Path.Combine(Path.GetDirectoryName(authority.YamlPath)!, "dept.tnpkg");
        // Grant the ANCESTOR path: the reader's key derives down locally to
        // the group's deeper sealing path.
        var grant = await authority.Admin.GrantReaderAsync(
            "default",
            reader.Did,
            kitPath,
            idPath: "acme");
        Assert.Equal("acme", grant.IdPath);

        await reader.Packages.AbsorbAsync(grant.KitPath);
        var opened = await reader.UnsealAsync(sealedObject);
        Assert.Equal("s3", opened.Fields["secret"]?.GetValue<string>());
    }

    [Fact]
    public async Task RotateIdPathMovesFutureSealsWithoutReinit()
    {
        await using var authority = await OpenHibeAuthorityAsync(NewProjectDir(), "hibe_auth");

        var sealedBefore = await authority.SealAsync(
            "obj.gov.v1",
            new { epoch = "one" },
            new SealOptions { Receipt = false });

        // A reader granted BEFORE the rotation (keyed to the old path).
        await using var oldReader = await Tn.InitProjectAsync(
            "hibe_old_reader",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });
        var oldKit = Path.Combine(Path.GetDirectoryName(authority.YamlPath)!, "old.tnpkg");
        await authority.Admin.GrantReaderAsync("default", oldReader.Did, oldKit);
        await oldReader.Packages.AbsorbAsync(oldKit);

        var rotation = await authority.Admin.RotateIdPathAsync("default", "acme/objects~r1");
        Assert.Equal("default", rotation.Group);
        Assert.Equal(FixtureIdPath, rotation.PreviousPath);
        Assert.Equal("acme/objects~r1", rotation.NewPath);

        // The SAME authority handle — no re-init — must seal under the new
        // path (the cached-cipher hazard).
        var sealedAfter = await authority.SealAsync(
            "obj.gov.v1",
            new { epoch = "two" },
            new SealOptions { Receipt = false });

        // Keystore artifacts follow the Python layout: idpath swapped,
        // outgoing path heads the history (LF, trailing newline), fresh sk.
        var keysDir = AuthorityKeysDir(authority);
        Assert.Equal(
            "acme/objects~r1",
            await File.ReadAllTextAsync(Path.Combine(keysDir, "default.hibe.idpath")));
        Assert.Equal(
            "acme/objects\n",
            await File.ReadAllTextAsync(Path.Combine(keysDir, "default.hibe.idpath.history")));

        // Pre-rotation grantee: keeps the old epoch, locked out of the new.
        var beforeView = await oldReader.UnsealAsync(sealedBefore);
        Assert.Equal("one", beforeView.Fields["epoch"]?.GetValue<string>());
        var afterView = await oldReader.UnsealAsync(sealedAfter);
        Assert.Equal(["default"], afterView.HiddenGroups);

        // A reader granted AFTER the rotation opens the new epoch only.
        await using var newReader = await Tn.InitProjectAsync(
            "hibe_new_reader",
            new TnProjectOptions { ProjectDirectory = NewProjectDir() });
        var newKit = Path.Combine(Path.GetDirectoryName(authority.YamlPath)!, "new.tnpkg");
        var grant = await authority.Admin.GrantReaderAsync("default", newReader.Did, newKit);
        Assert.Equal("acme/objects~r1", grant.IdPath);
        await newReader.Packages.AbsorbAsync(newKit);
        var newAfter = await newReader.UnsealAsync(sealedAfter);
        Assert.Equal("two", newAfter.Fields["epoch"]?.GetValue<string>());
        var newBefore = await newReader.UnsealAsync(sealedBefore);
        Assert.Equal(["default"], newBefore.HiddenGroups);

        // The authority itself still opens BOTH epochs (msk + recorded
        // path history), including after a fresh init from disk.
        var authorityBefore = await authority.UnsealAsync(sealedBefore);
        Assert.Equal("one", authorityBefore.Fields["epoch"]?.GetValue<string>());
        var authorityAfter = await authority.UnsealAsync(sealedAfter);
        Assert.Equal("two", authorityAfter.Fields["epoch"]?.GetValue<string>());
    }

    [Fact]
    public async Task RotateIdPathRejectsSamePath()
    {
        await using var authority = await OpenHibeAuthorityAsync(NewProjectDir(), "hibe_auth");

        var error = await Assert.ThrowsAsync<TnException>(() =>
            authority.Admin.RotateIdPathAsync("default", FixtureIdPath));

        Assert.Contains("new path equals the current path", error.Message, StringComparison.Ordinal);
    }
}
