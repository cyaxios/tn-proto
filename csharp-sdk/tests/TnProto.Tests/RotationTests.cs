using TnProto.Rotation;

namespace TnProto.Tests;

public sealed class RotationTests
{
    [Fact]
    public async Task RotateAsyncEmitsReplacementBundleForSurvivingRecipient()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var outDir = Path.Combine(projectDir, "rotated");

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "alice.btn.mykit"),
            "did:key:zCSharpRecipientAlice");

        var result = await tn.Rotation.RotateAsync(new RotateOptions
        {
            Groups = ["payments"],
            OutPath = outDir,
        });

        var rotated = Assert.Single(result.Rotated);
        Assert.Equal("payments", rotated.Group);
        Assert.True(rotated.Generation >= 1);
        Assert.Equal(Path.GetFullPath(outDir), result.OutDirectory);

        var artifact = Assert.Single(result.Artifacts);
        Assert.Equal("did:key:zCSharpRecipientAlice", artifact.RecipientDid);
        Assert.Equal(["payments"], artifact.Groups);
        Assert.True(File.Exists(artifact.Path));

        var info = await tn.Packages.InspectAsync(artifact.Path);
        Assert.True(info.ContainsReaderKeys);
        Assert.Equal("did:key:zCSharpRecipientAlice", info.RecipientIdentity);
    }

    [Fact]
    public async Task RotateAsyncRejectsSinglePackageOutputForMultipleRecipients()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "alice.btn.mykit"),
            "did:key:zCSharpRecipientAlice");
        await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "bob.btn.mykit"),
            "did:key:zCSharpRecipientBob");

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Rotation.RotateAsync(new RotateOptions
            {
                Groups = ["payments"],
                OutPath = Path.Combine(projectDir, "single.tnpkg"),
            }));

        Assert.Contains("single .tnpkg", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RotateAsyncDoesNotEmitReplacementBundleForRevokedRecipient()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var aliceDir = Path.Combine(Path.GetTempPath(), "tn-csharp-alice-" + Guid.NewGuid().ToString("N"));
        var bobDir = Path.Combine(Path.GetTempPath(), "tn-csharp-bob-" + Guid.NewGuid().ToString("N"));
        var outDir = Path.Combine(projectDir, "rotated");

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await using var alice = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = aliceDir });
        await using var bob = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = bobDir });

        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        var aliceRecipient = await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "alice.btn.mykit"),
            alice.Did);
        await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "bob.btn.mykit"),
            bob.Did);

        await tn.Admin.RevokeRecipientAsync("payments", aliceRecipient.LeafIndex);

        var result = await tn.Rotation.RotateAsync(new RotateOptions
        {
            Groups = ["payments"],
            OutPath = outDir,
            SealForRecipient = true,
        });

        var artifact = Assert.Single(result.Artifacts);
        Assert.Equal(bob.Did, artifact.RecipientDid);
        Assert.Equal(["payments"], artifact.Groups);
        Assert.True(File.Exists(artifact.Path));

        var info = await tn.Packages.InspectAsync(artifact.Path);
        Assert.True(info.Sealed);
        Assert.True(info.IsAddressedTo(bob.Did));
        Assert.False(info.IsAddressedTo(alice.Did));
    }

    [Fact]
    public async Task RotateAsyncWithNoRecipientsReturnsNoArtifacts()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var result = await tn.Rotation.RotateAsync();

        Assert.Single(result.Rotated);
        Assert.Empty(result.Artifacts);
        Assert.Null(result.OutDirectory);
    }
}
