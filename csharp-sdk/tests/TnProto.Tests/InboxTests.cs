using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TnProto.Inbox;

namespace TnProto.Tests;

public sealed class InboxTests
{
    [Fact]
    public async Task ListLocalAsyncReturnsSortedInviteZips()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var inboxDir = Path.Combine(projectDir, "inbox");
        Directory.CreateDirectory(inboxDir);
        var second = Path.Combine(inboxDir, "tn-invite-b.zip");
        var first = Path.Combine(inboxDir, "tn-invite-a.zip");
        await File.WriteAllTextAsync(second, "b");
        await File.WriteAllTextAsync(first, "a");
        await File.WriteAllTextAsync(Path.Combine(inboxDir, "not-an-invite.zip"), "ignored");

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var found = await tn.Inbox.ListLocalAsync(inboxDir);
        var missing = await tn.Inbox.ListLocalAsync(Path.Combine(projectDir, "missing"));

        Assert.Equal([Path.GetFullPath(first), Path.GetFullPath(second)], found);
        Assert.Empty(missing);
    }

    [Fact]
    public async Task InspectAsyncParsesInviteManifestAndVerifiesKitHash()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(projectDir);
        var invitePath = Path.Combine(projectDir, "tn-invite-demo.zip");
        var kitBytes = Encoding.UTF8.GetBytes("reader kit bytes");
        var kitHash = "sha256:" + Sha256Hex(kitBytes);
        await WriteInviteZipAsync(
            invitePath,
            "payments.btn.mykit",
            kitBytes,
            new
            {
                invitation_id = "invite-csharp-1",
                from_account_did = "did:key:zSender",
                from_email = "sender@example.test",
                project_id = "proj_csharp",
                project_name = "CSharp Payments",
                group_name = "payments",
                leaf_index = 7,
                kit_sha256 = kitHash,
                created_at = "2026-07-02T00:00:00Z",
                note = "hello",
                provenance = "csharp-test",
                future_field = new { kept = true },
            });

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var info = await tn.Inbox.InspectAsync(invitePath);

        Assert.Equal("payments", info.GroupName);
        Assert.Equal("payments.btn.mykit", info.KitEntryName);
        Assert.Equal((ulong)kitBytes.Length, info.KitLength);
        Assert.Equal(Sha256Hex(kitBytes), info.KitSha256Actual);
        Assert.True(info.KitHashVerified);
        Assert.Equal("verified", info.KitHash.Status);
        Assert.Equal(kitHash, info.KitHash.Expected);
        Assert.Equal("invite-csharp-1", info.Manifest.InvitationId);
        Assert.Equal("did:key:zSender", info.Manifest.FromAccountDid);
        Assert.Equal("sender@example.test", info.Manifest.FromEmail);
        Assert.Equal("proj_csharp", info.Manifest.ProjectId);
        Assert.Equal("CSharp Payments", info.Manifest.ProjectName);
        Assert.Equal("payments", info.Manifest.GroupName);
        Assert.Equal("hello", info.Manifest.Note);
        Assert.Equal("csharp-test", info.Manifest.Provenance);
        Assert.Equal(true, info.Manifest.Raw["future_field"]?["kept"]?.GetValue<bool>());
    }

    [Fact]
    public async Task InspectAsyncRejectsBadKitHash()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(projectDir);
        var invitePath = Path.Combine(projectDir, "tn-invite-bad.zip");
        await WriteInviteZipAsync(
            invitePath,
            "default.btn.mykit",
            Encoding.UTF8.GetBytes("reader kit bytes"),
            new
            {
                group_name = "default",
                kit_sha256 = "sha256:0000",
            });

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<TnException>(() => tn.Inbox.InspectAsync(invitePath));

        Assert.Contains("kit hash mismatch", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AcceptAsyncInstallsKitAndBacksUpExistingKit()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(projectDir);
        var firstInvite = Path.Combine(projectDir, "tn-invite-first.zip");
        var secondInvite = Path.Combine(projectDir, "tn-invite-second.zip");
        var firstKit = Encoding.UTF8.GetBytes("first reader kit");
        var secondKit = Encoding.UTF8.GetBytes("second reader kit");

        await WriteInviteZipAsync(
            firstInvite,
            "payments.btn.mykit",
            firstKit,
            new
            {
                from_account_did = "did:key:zSender",
                from_email = "sender@example.test",
                group_name = "payments",
                leaf_index = 7,
                kit_sha256 = "sha256:" + Sha256Hex(firstKit),
            });
        await WriteInviteZipAsync(
            secondInvite,
            "payments.btn.mykit",
            secondKit,
            new
            {
                from_account_did = "did:key:zSender",
                from_email = "sender@example.test",
                group_name = "payments",
                leaf_index = 8,
                kit_sha256 = "sha256:" + Sha256Hex(secondKit),
            });

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var first = await tn.Inbox.AcceptAsync(firstInvite);

        Assert.Equal("payments", first.GroupName);
        Assert.Equal("sender@example.test", first.FromEmail);
        Assert.Equal("payments", first.Info.GroupName);
        Assert.Equal("payments.btn.mykit", first.Info.KitEntryName);
        Assert.Null(first.BackupPath);
        Assert.Equal(firstKit, await File.ReadAllBytesAsync(first.KitPath));

        var second = await tn.Inbox.AcceptAsync(secondInvite);

        Assert.Equal("payments", second.GroupName);
        Assert.NotNull(second.BackupPath);
        Assert.True(File.Exists(second.BackupPath));
        Assert.Equal(firstKit, await File.ReadAllBytesAsync(second.BackupPath!));
        Assert.Equal(secondKit, await File.ReadAllBytesAsync(second.KitPath));
        Assert.False(string.IsNullOrWhiteSpace(second.AbsorbedAt));

        Assert.False(string.IsNullOrWhiteSpace(second.AbsorbedAt));
    }

    [Fact]
    public async Task AcceptAsyncRejectsBadHashBeforeMutatingKeystore()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(projectDir);
        var invitePath = Path.Combine(projectDir, "tn-invite-bad.zip");
        await WriteInviteZipAsync(
            invitePath,
            "payments.btn.mykit",
            Encoding.UTF8.GetBytes("reader kit bytes"),
            new
            {
                group_name = "payments",
                kit_sha256 = "sha256:0000",
            });

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<TnException>(() => tn.Inbox.AcceptAsync(invitePath));

        Assert.Contains("kit hash mismatch", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(projectDir, ".tn", "payments", "keys", "payments.btn.mykit")));
    }

    [Fact]
    public async Task InspectAsyncRejectsEmptyPathBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() => tn.Inbox.InspectAsync(""));

        Assert.Equal("path", error.ParamName);
    }

    [Fact]
    public async Task AcceptAsyncRejectsEmptyPathBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() => tn.Inbox.AcceptAsync(""));

        Assert.Equal("path", error.ParamName);
    }

    [Fact]
    public async Task MintInviteAsyncWritesInspectablePythonTypescriptShapedZip()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var invitePath = Path.Combine(projectDir, "tn-invite-csharp.zip");

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var minted = await tn.Inbox.MintInviteAsync(
            "did:key:zRecipient",
            invitePath,
            new MintInvitationOptions
            {
                Group = "default",
                FromEmail = "alice@example.test",
                ProjectId = "proj_123",
                ProjectName = "payments",
                Note = "hello",
                InvitationId = "invite-csharp",
                Provenance = "test",
            });

        Assert.Equal(Path.GetFullPath(invitePath), minted.Path);
        Assert.Equal("did:key:zRecipient", minted.RecipientDid);
        Assert.Equal("default.btn.mykit", minted.KitEntryName);
        Assert.True(minted.ZipLength > 0);
        Assert.True(File.Exists(invitePath));
        Assert.Equal("invite-csharp", minted.Manifest.InvitationId);
        Assert.Equal(tn.Did, minted.Manifest.FromAccountDid);
        Assert.Equal("alice@example.test", minted.Manifest.FromEmail);
        Assert.Equal("proj_123", minted.Manifest.ProjectId);
        Assert.Equal("payments", minted.Manifest.ProjectName);
        Assert.Equal("default", minted.Manifest.GroupName);
        Assert.Equal("hello", minted.Manifest.Note);
        Assert.Equal("test", minted.Manifest.Provenance);

        var info = await tn.Inbox.InspectAsync(invitePath);

        Assert.Equal("default.btn.mykit", info.KitEntryName);
        Assert.True(info.KitHashVerified);
        Assert.Equal(minted.Manifest.KitSha256, info.Manifest.KitSha256);
    }

    [Fact]
    public async Task MintInviteAsyncCanBeAcceptedByAnotherProject()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-consumer-" + Guid.NewGuid().ToString("N"));
        var invitePath = Path.Combine(producerDir, "tn-invite-peer.zip");

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var minted = await producer.Inbox.MintInviteAsync(
            consumer.Did,
            invitePath,
            new MintInvitationOptions
            {
                FromEmail = "producer@example.test",
                InvitationId = "roundtrip",
            });
        var accepted = await consumer.Inbox.AcceptAsync(invitePath);

        Assert.Equal(consumer.Did, minted.RecipientDid);
        Assert.Equal("roundtrip", accepted.Info.Manifest.InvitationId);
        Assert.Equal("producer@example.test", accepted.FromEmail);
        Assert.Equal(producer.Did, accepted.Info.Manifest.FromAccountDid);
        Assert.Equal(minted.Manifest.KitSha256, accepted.Info.Manifest.KitSha256);
        Assert.True(File.Exists(accepted.KitPath));
    }

    [Fact]
    public async Task MintInviteAsyncUsesFriendlyLabelPlaceholderDid()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var minted = await tn.Inbox.MintInviteAsync(
            "Frank",
            Path.Combine(projectDir, "tn-invite-label.zip"));
        var recipients = await tn.Admin.RecipientsAsync("default");

        Assert.Equal("did:key:zLabel-Frank", minted.RecipientDid);
        Assert.Contains(recipients, recipient => recipient.RecipientIdentity == "did:key:zLabel-Frank");
    }

    [Fact]
    public async Task MintInviteAsyncRejectsEmptyFieldsBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var emptyRecipient = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Inbox.MintInviteAsync("", Path.Combine(projectDir, "tn-invite-empty.zip")));
        var emptyPath = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Inbox.MintInviteAsync("did:key:zRecipient", ""));

        Assert.Equal("recipient", emptyRecipient.ParamName);
        Assert.Equal("outPath", emptyPath.ParamName);
    }

    private static async Task WriteInviteZipAsync(
        string path,
        string kitEntryName,
        byte[] kitBytes,
        object manifest)
    {
        await using var stream = File.Create(path);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create);

        var kitEntry = archive.CreateEntry(kitEntryName);
        await using (var kitStream = kitEntry.Open())
        {
            await kitStream.WriteAsync(kitBytes);
        }

        var manifestEntry = archive.CreateEntry("manifest.json");
        await using var manifestStream = manifestEntry.Open();
        await JsonSerializer.SerializeAsync(manifestStream, manifest);
    }

    private static string Sha256Hex(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
