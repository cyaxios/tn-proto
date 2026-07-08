using TnProto.Packages;

namespace TnProto.Tests;

public sealed class PackageTests
{
    [Fact]
    public async Task ExportAdminSnapshotAsyncAndAbsorbAsyncRoundTrip()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await producer.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await producer.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(producerDir, "reader.btn.mykit"),
            "did:key:zCSharpPackageRecipient");
        await producer.InfoAsync("payment.created", new { order_id = "PKG-CSHARP-100" });

        var packagePath = Path.Combine(producerDir, "admin-snapshot.tnpkg");
        var export = await producer.Packages.ExportAdminSnapshotAsync(packagePath);

        Assert.Equal(Path.GetFullPath(packagePath), export.Path);
        Assert.True(File.Exists(packagePath));

        var info = await producer.Packages.InspectAsync(packagePath);

        Assert.Equal("admin_log_snapshot", info.Kind);
        Assert.Equal("admin_snapshot", info.Category);
        Assert.Equal("admin", info.Scope);
        Assert.True(info.Verified);
        Assert.Equal("verified", info.Signature.Status);
        Assert.True(info.IsPublishedBy(producer.Did));
        Assert.Null(info.RecipientIdentity);
        Assert.False(info.ContainsSecretMaterial);
        Assert.False(info.ContainsReaderKeys);
        Assert.False(info.Sealed);
        Assert.Contains("body/admin.ndjson", info.BodyEntryNames);

        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("admin_log_snapshot", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.True(receipt.AcceptedCount > 0 || receipt.NoOp);
        Assert.False(receipt.Rejected);
        Assert.Equal(0UL, receipt.ConflictCount);

        var duplicate = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.True(duplicate.IsNoOp || duplicate.DedupedCount > 0 || duplicate.NoOp);
        Assert.False(duplicate.Rejected);
    }

    [Fact]
    public async Task AbsorbAsyncReportsMalformedPackageAsRejected()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var packagePath = Path.Combine(projectDir, "bad.tnpkg");
        Directory.CreateDirectory(projectDir);
        await File.WriteAllTextAsync(packagePath, "not a package");

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await tn.Packages.AbsorbAsync(packagePath);

        Assert.True(receipt.Rejected);
        Assert.Equal("rejected", receipt.LegacyStatus);
        Assert.Contains("not a valid", receipt.LegacyReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InspectAsyncRejectsMalformedPackage()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var packagePath = Path.Combine(projectDir, "bad.tnpkg");
        Directory.CreateDirectory(projectDir);
        await File.WriteAllTextAsync(packagePath, "not a package");

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<TnException>(() => tn.Packages.InspectAsync(packagePath));

        Assert.Contains("malformed", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportKitBundleAsyncAndAbsorbAsyncRoundTrip()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });

        var packagePath = Path.Combine(producerDir, "reader-kits.tnpkg");
        var export = await producer.Packages.ExportKitBundleAsync(
            packagePath,
            groups: ["default"],
            toDid: "did:key:zCSharpPackageRecipient");

        Assert.Equal(Path.GetFullPath(packagePath), export.Path);
        Assert.True(File.Exists(packagePath));

        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.Equal("enrolment_applied", receipt.LegacyStatus);
        Assert.True(receipt.AcceptedCount > 0);
        Assert.Contains(receipt.ReplacedKitPaths, path => path.EndsWith("default.btn.mykit", StringComparison.OrdinalIgnoreCase));

        var duplicate = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", duplicate.Kind);
        Assert.True(duplicate.IsNoOp);
        Assert.Equal(0UL, duplicate.AcceptedCount);
        Assert.True(duplicate.DedupedCount > 0);
        Assert.Empty(duplicate.ReplacedKitPaths);
    }

    [Fact]
    public async Task BundleForRecipientAsyncMintsFreshKitBundleAndAbsorbs()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });

        var packagePath = Path.Combine(producerDir, "recipient-default.tnpkg");
        var result = await producer.Packages.BundleForRecipientAsync(
            "did:key:zCSharpPackageRecipient",
            packagePath,
            new BundleForRecipientOptions { Groups = ["default"] });

        Assert.Equal(Path.GetFullPath(packagePath), result.Path);
        Assert.Equal("did:key:zCSharpPackageRecipient", result.RecipientDid);
        Assert.Equal(["default"], result.Groups);
        Assert.True(File.Exists(packagePath));

        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.Equal("enrolment_applied", receipt.LegacyStatus);
        Assert.Equal(1UL, receipt.AcceptedCount);
    }

    [Fact]
    public async Task ExportRecipientHandoffAsyncWritesSnapshotAndBundle()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));
        var outDir = Path.Combine(producerDir, "handoff");

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await producer.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var result = await producer.Packages.ExportRecipientHandoffAsync(new RecipientHandoffOptions
        {
            RecipientDid = consumer.Did,
            OutDirectory = outDir,
            Groups = ["payments"],
        });

        Assert.Equal(Path.Combine(Path.GetFullPath(outDir), "admin-snapshot.tnpkg"), result.AdminSnapshotPath);
        Assert.Equal(Path.Combine(Path.GetFullPath(outDir), "reader-bundle.tnpkg"), result.ReaderBundlePath);
        Assert.Equal(consumer.Did, result.RecipientDid);
        Assert.Equal(["payments"], result.Groups);
        Assert.True(File.Exists(result.AdminSnapshotPath));
        Assert.True(File.Exists(result.ReaderBundlePath));
        Assert.Equal("admin_log_snapshot", result.AdminSnapshot.Kind);
        Assert.Equal("kit_bundle", result.ReaderBundle.Kind);
        Assert.True(result.AdminSnapshot.Verified);
        Assert.True(result.ReaderBundle.Verified);
        Assert.False(result.AdminSnapshot.ContainsSecretMaterial);
        Assert.False(result.ReaderBundle.ContainsSecretMaterial);
        Assert.True(result.ReaderBundle.ContainsReaderKeys);

        var adminReceipt = await consumer.Packages.AbsorbAsync(result.AdminSnapshotPath);
        var bundleReceipt = await consumer.Packages.AbsorbAsync(result.ReaderBundlePath);

        Assert.False(adminReceipt.Rejected);
        Assert.Equal("kit_bundle", bundleReceipt.Kind);
        Assert.True(bundleReceipt.Accepted);
    }

    [Fact]
    public async Task ExportRecipientHandoffAsyncCanSealReaderBundle()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));
        var outDir = Path.Combine(producerDir, "sealed-handoff");

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await producer.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var result = await producer.Packages.ExportRecipientHandoffAsync(new RecipientHandoffOptions
        {
            RecipientDid = consumer.Did,
            OutDirectory = outDir,
            Groups = ["payments"],
            SealForRecipient = true,
        });

        Assert.True(result.AdminSnapshot.Verified);
        Assert.True(result.ReaderBundle.Verified);
        Assert.True(result.ReaderBundle.Sealed);
        Assert.False(result.ReaderBundle.ContainsSecretMaterial);
        Assert.False(result.ReaderBundle.ContainsReaderKeys);
        Assert.Equal(consumer.Did, result.ReaderBundle.RecipientIdentity);
        Assert.Contains("body/encrypted.bin", result.ReaderBundle.BodyEntryNames);

        var adminReceipt = await consumer.Packages.AbsorbAsync(result.AdminSnapshotPath);
        var bundleReceipt = await consumer.Packages.AbsorbAsync(result.ReaderBundlePath);

        Assert.False(adminReceipt.Rejected);
        Assert.Equal("kit_bundle", bundleReceipt.Kind);
        Assert.True(bundleReceipt.Accepted);
    }

    [Fact]
    public async Task BundleForRecipientAsyncDefaultsToAvailableGroups()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var result = await tn.Packages.BundleForRecipientAsync(
            "did:key:zCSharpPackageRecipient",
            Path.Combine(projectDir, "recipient-default.tnpkg"));

        Assert.Contains("default", result.Groups);
    }

    [Fact]
    public async Task BundleForRecipientAsyncCanSealForIntendedRecipient()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var recipientDir = Path.Combine(Path.GetTempPath(), "tn-csharp-recipient-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var recipient = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = recipientDir });

        var packagePath = Path.Combine(producerDir, "recipient-default-sealed.tnpkg");
        var result = await producer.Packages.BundleForRecipientAsync(
            recipient.Did,
            packagePath,
            new BundleForRecipientOptions
            {
                Groups = ["default"],
                SealForRecipient = true,
            });

        Assert.Equal(recipient.Did, result.RecipientDid);
        Assert.Equal(["default"], result.Groups);
        Assert.True(File.Exists(packagePath));

        var receipt = await recipient.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.Equal("enrolment_applied", receipt.LegacyStatus);
        Assert.Equal(1UL, receipt.AcceptedCount);
    }

    [Fact]
    public async Task InspectAsyncReportsSealedRecipientBundleMetadata()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var recipientDir = Path.Combine(Path.GetTempPath(), "tn-csharp-recipient-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var recipient = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = recipientDir });

        var packagePath = Path.Combine(producerDir, "sealed-handoff.tnpkg");
        await producer.Packages.BundleForRecipientAsync(
            recipient.Did,
            packagePath,
            new BundleForRecipientOptions
            {
                Groups = ["default"],
                SealForRecipient = true,
            });

        var info = await producer.Packages.InspectAsync(packagePath);

        Assert.Equal("kit_bundle", info.Kind);
        Assert.Equal("kit_bundle", info.Category);
        Assert.True(info.Verified);
        Assert.True(info.Sealed);
        Assert.False(info.ContainsSecretMaterial);
        Assert.False(info.ContainsReaderKeys);
        Assert.Equal(recipient.Did, info.RecipientIdentity);
        Assert.True(info.IsAddressedTo(recipient.Did));
        Assert.Contains("body/encrypted.bin", info.BodyEntryNames);
    }

    [Fact]
    public async Task BundleForRecipientAsyncSealedBundleRejectsWrongRecipient()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var intendedDir = Path.Combine(Path.GetTempPath(), "tn-csharp-intended-" + Guid.NewGuid().ToString("N"));
        var otherDir = Path.Combine(Path.GetTempPath(), "tn-csharp-other-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var intended = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = intendedDir });
        await using var other = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = otherDir });

        var packagePath = Path.Combine(producerDir, "recipient-default-sealed.tnpkg");
        await producer.Packages.BundleForRecipientAsync(
            intended.Did,
            packagePath,
            new BundleForRecipientOptions
            {
                Groups = ["default"],
                SealForRecipient = true,
            });

        var receipt = await other.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Rejected);
        Assert.Contains("sealed-box wrap", receipt.LegacyReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BundleForRecipientAsyncSealingRejectsKeylessPlaceholderDid()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });

        var packagePath = Path.Combine(producerDir, "recipient-keyless-sealed.tnpkg");
        var error = await Assert.ThrowsAsync<TnException>(() =>
            producer.Packages.BundleForRecipientAsync(
                "did:key:zCSharpPackageRecipient",
                packagePath,
                new BundleForRecipientOptions
                {
                    Groups = ["default"],
                    SealForRecipient = true,
                }));

        Assert.Contains("recipient sealing", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(packagePath));
    }

    [Fact]
    public async Task CompileEnrolmentAsyncWritesRecipientKitBundleAndAbsorbs()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });

        var packagePath = Path.Combine(producerDir, "compiled-enrolment.tnpkg");
        var result = await producer.Packages.CompileEnrolmentAsync(new CompileEnrolmentOptions
        {
            Group = "default",
            RecipientDid = "did:key:zCompileRecipient",
            OutPath = packagePath,
        });

        Assert.Equal(Path.GetFullPath(packagePath), result.Path);
        Assert.Equal("did:key:zCompileRecipient", result.RecipientDid);
        Assert.Equal(["default"], result.Groups);
        Assert.Equal(64, result.ManifestSha256.Length);
        Assert.Equal(64, result.PackageSha256.Length);
        Assert.True(File.Exists(packagePath));

        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
    }

    [Fact]
    public async Task CompileEnrolmentAsyncCanSealForIntendedRecipient()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var recipientDir = Path.Combine(Path.GetTempPath(), "tn-csharp-recipient-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var recipient = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = recipientDir });

        var packagePath = Path.Combine(producerDir, "compiled-enrolment-sealed.tnpkg");
        var result = await producer.Packages.CompileEnrolmentAsync(new CompileEnrolmentOptions
        {
            Group = "default",
            RecipientDid = recipient.Did,
            OutPath = packagePath,
            SealForRecipient = true,
        });

        Assert.Equal(recipient.Did, result.RecipientDid);
        Assert.Equal(["default"], result.Groups);
        Assert.Equal(64, result.ManifestSha256.Length);
        Assert.Equal(64, result.PackageSha256.Length);

        var receipt = await recipient.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.Equal("enrolment_applied", receipt.LegacyStatus);
    }

    [Fact]
    public async Task CompileEnrolmentAsyncRejectsEmptyFieldsBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var emptyGroup = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.CompileEnrolmentAsync(new CompileEnrolmentOptions
            {
                Group = "",
                RecipientDid = "did:key:zCompileRecipient",
                OutPath = Path.Combine(projectDir, "compiled-enrolment.tnpkg"),
            }));
        var emptyRecipient = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.CompileEnrolmentAsync(new CompileEnrolmentOptions
            {
                Group = "default",
                RecipientDid = "",
                OutPath = Path.Combine(projectDir, "compiled-enrolment.tnpkg"),
            }));
        var emptyPath = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.CompileEnrolmentAsync(new CompileEnrolmentOptions
            {
                Group = "default",
                RecipientDid = "did:key:zCompileRecipient",
                OutPath = "",
            }));

        Assert.Equal("options", emptyGroup.ParamName);
        Assert.Equal("options", emptyRecipient.ParamName);
        Assert.Equal("options", emptyPath.ParamName);
    }

    [Fact]
    public async Task OfferAsyncCompilesBundleForPeer()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });

        var packagePath = Path.Combine(producerDir, "offer.tnpkg");
        var receipt = await producer.Packages.OfferAsync(new OfferOptions
        {
            Group = "default",
            PeerDid = "did:key:zOfferPeer",
            OutPath = packagePath,
        });

        Assert.Equal(Path.GetFullPath(packagePath), receipt.Path);
        Assert.Equal("offered", receipt.Status);
        Assert.Equal("default", receipt.Group);
        Assert.Equal("did:key:zOfferPeer", receipt.PeerDid);
        Assert.Equal(64, receipt.PackageSha256.Length);
        Assert.True(File.Exists(packagePath));

        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var absorb = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", absorb.Kind);
        Assert.True(absorb.Accepted);
    }

    [Fact]
    public async Task OfferAsyncCanSealForIntendedPeer()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var peerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-peer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var peer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = peerDir });

        var packagePath = Path.Combine(producerDir, "offer-sealed.tnpkg");
        var receipt = await producer.Packages.OfferAsync(new OfferOptions
        {
            Group = "default",
            PeerDid = peer.Did,
            OutPath = packagePath,
            SealForRecipient = true,
        });

        Assert.Equal(peer.Did, receipt.PeerDid);
        Assert.Equal("offered", receipt.Status);

        var absorb = await peer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", absorb.Kind);
        Assert.True(absorb.Accepted);
    }

    [Fact]
    public async Task OfferAsyncRejectsEmptyFieldsBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var emptyGroup = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.OfferAsync(new OfferOptions
            {
                Group = "",
                PeerDid = "did:key:zOfferPeer",
                OutPath = Path.Combine(projectDir, "offer.tnpkg"),
            }));
        var emptyPeer = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.OfferAsync(new OfferOptions
            {
                Group = "default",
                PeerDid = "",
                OutPath = Path.Combine(projectDir, "offer.tnpkg"),
            }));
        var emptyPath = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.OfferAsync(new OfferOptions
            {
                Group = "default",
                PeerDid = "did:key:zOfferPeer",
                OutPath = "",
            }));

        Assert.Equal("options", emptyGroup.ParamName);
        Assert.Equal("options", emptyPeer.ParamName);
        Assert.Equal("options", emptyPath.ParamName);
    }

    [Fact]
    public async Task BundleForRecipientAsyncRejectsEmptyRecipientDidBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.BundleForRecipientAsync("", Path.Combine(projectDir, "recipient-default.tnpkg")));

        Assert.Equal("recipientDid", error.ParamName);
    }

    [Fact]
    public async Task ExportRecipientHandoffAsyncRejectsEmptyFieldsBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var emptyRecipient = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.ExportRecipientHandoffAsync(new RecipientHandoffOptions
            {
                RecipientDid = "",
                OutDirectory = Path.Combine(projectDir, "handoff"),
            }));
        var emptyDirectory = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.ExportRecipientHandoffAsync(new RecipientHandoffOptions
            {
                RecipientDid = "did:key:zCSharpPackageRecipient",
                OutDirectory = "",
            }));

        Assert.Equal("options", emptyRecipient.ParamName);
        Assert.Equal("options", emptyDirectory.ParamName);
    }

    [Fact]
    public async Task BundleForRecipientAsyncRejectsUnknownGroup()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<TnException>(() =>
            tn.Packages.BundleForRecipientAsync(
                "did:key:zCSharpPackageRecipient",
                Path.Combine(projectDir, "recipient-missing.tnpkg"),
                new BundleForRecipientOptions { Groups = ["missing"] }));

        Assert.Contains("missing", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportAdminSnapshotAsyncRejectsEmptyPathBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.ExportAdminSnapshotAsync(""));

        Assert.Equal("outPath", error.ParamName);
    }

    [Fact]
    public async Task ExportKitBundleAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.ExportKitBundleAsync(Path.Combine(projectDir, "reader-kits.tnpkg"), groups: [""]));

        Assert.Equal("groups", error.ParamName);
    }

    [Fact]
    public async Task AbsorbAsyncRejectsEmptyPathBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Packages.AbsorbAsync(""));

        Assert.Equal("sourcePath", error.ParamName);
    }
}
