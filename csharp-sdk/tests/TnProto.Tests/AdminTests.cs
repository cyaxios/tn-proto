namespace TnProto.Tests;

public sealed class AdminTests
{
    [Fact]
    public async Task EnsureGroupAsyncCreatesGroupAndRoutesFields()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var result = await tn.Admin.EnsureGroupAsync("payments", ["order_id", "amount"]);

        Assert.Equal("payments", result.Group);
        Assert.Equal(["order_id", "amount"], result.Fields);
        Assert.True(result.Created);
        Assert.True(result.Changed);

        var yaml = await File.ReadAllTextAsync(tn.YamlPath);
        Assert.Contains("payments", yaml, StringComparison.Ordinal);
        Assert.Contains("order_id", yaml, StringComparison.Ordinal);
        Assert.Contains("amount", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EnsureGroupAsyncKeepsRoutedFieldValuesPrivateInRawLog()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        string logPath;

        await using (var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
            await tn.InfoAsync(
                "payment.created",
                new
                {
                    order_id = "PAY-CSharp-100",
                    note = "public note",
                });

            var entries = await tn.ReadAsync();
            var entry = Assert.Single(entries.Where(e => e.EventType == "payment.created"));
            Assert.Equal("PAY-CSharp-100", entry.GetString("order_id"));
            Assert.Equal("public note", entry.GetString("note"));

            logPath = tn.LogPath;
        }

        var rawLog = await File.ReadAllTextAsync(logPath);
        Assert.DoesNotContain("PAY-CSharp-100", rawLog, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EnsureGroupAsyncIsIdempotentForExistingRoutes()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var first = await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        var second = await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);

        Assert.True(first.Created);
        Assert.True(first.Changed);
        Assert.False(second.Created);
        Assert.False(second.Changed);
    }

    [Fact]
    public async Task EnsureGroupAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.EnsureGroupAsync("", ["order_id"]));

        Assert.Equal("group", error.ParamName);
    }

    [Fact]
    public async Task EnsureGroupAsyncRejectsEmptyFieldBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.EnsureGroupAsync("payments", ["order_id", ""]));

        Assert.Equal("fields", error.ParamName);
    }

    [Fact]
    public async Task AddRecipientAsyncMintsReaderKit()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);

        var kitPath = Path.Combine(projectDir, "alice.btn.mykit");
        var result = await tn.Admin.AddRecipientAsync(
            "payments",
            kitPath,
            "did:key:zCSharpRecipientAlice");

        Assert.Equal("payments", result.Group);
        Assert.Equal("did:key:zCSharpRecipientAlice", result.RecipientDid);
        Assert.Equal<ulong>(1, result.LeafIndex);
        Assert.Equal(Path.GetFullPath(kitPath), result.KitPath);
        Assert.True(File.Exists(kitPath));
    }

    [Fact]
    public async Task AddRecipientAsyncAllocatesNextLeafIndex()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);

        var first = await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "alice.btn.mykit"),
            "did:key:zCSharpRecipientAlice");
        var second = await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "bob.btn.mykit"),
            "did:key:zCSharpRecipientBob");

        Assert.Equal<ulong>(1, first.LeafIndex);
        Assert.Equal<ulong>(2, second.LeafIndex);
    }

    [Fact]
    public async Task AddRecipientAsyncAllowsMissingRecipientDid()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);

        var result = await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "anonymous.btn.mykit"));

        Assert.Null(result.RecipientDid);
        Assert.True(File.Exists(result.KitPath));
    }

    [Fact]
    public async Task AddRecipientAsyncRejectsInvalidKitSuffixBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.AddRecipientAsync("payments", Path.Combine(projectDir, "alice.txt")));

        Assert.Equal("outKitPath", error.ParamName);
    }

    [Fact]
    public async Task RecipientsAsyncListsActiveRecipients()
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

        var recipients = await tn.Admin.RecipientsAsync("payments");

        Assert.Equal(2, recipients.Count);
        Assert.Equal<ulong>(1, recipients[0].LeafIndex);
        Assert.Equal("did:key:zCSharpRecipientAlice", recipients[0].RecipientIdentity);
        Assert.NotNull(recipients[0].MintedAt);
        Assert.StartsWith("sha256:", recipients[0].KitSha256, StringComparison.Ordinal);
        Assert.False(recipients[0].Revoked);
        Assert.Null(recipients[0].RevokedAt);
        Assert.Equal<ulong>(2, recipients[1].LeafIndex);
        Assert.Equal("did:key:zCSharpRecipientBob", recipients[1].RecipientIdentity);
    }

    [Fact]
    public async Task RecipientsAsyncIncludesAnonymousRecipients()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "anonymous.btn.mykit"));

        var recipient = Assert.Single(await tn.Admin.RecipientsAsync("payments"));

        Assert.Null(recipient.RecipientIdentity);
        Assert.Equal<ulong>(1, recipient.LeafIndex);
        Assert.False(recipient.Revoked);
    }

    [Fact]
    public async Task RevokedCountAsyncReturnsZeroBeforeRevocations()
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

        Assert.Equal<ulong>(0, await tn.Admin.RevokedCountAsync("payments"));
    }

    [Fact]
    public async Task RevokeRecipientAsyncUpdatesRosterAndRevokedCount()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        var alice = await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "alice.btn.mykit"),
            "did:key:zCSharpRecipientAlice");
        var bob = await tn.Admin.AddRecipientAsync(
            "payments",
            Path.Combine(projectDir, "bob.btn.mykit"),
            "did:key:zCSharpRecipientBob");

        var result = await tn.Admin.RevokeRecipientAsync("payments", alice.LeafIndex);

        Assert.Equal("payments", result.Group);
        Assert.Equal(alice.LeafIndex, result.LeafIndex);
        Assert.Equal<ulong>(1, await tn.Admin.RevokedCountAsync("payments"));

        var active = await tn.Admin.RecipientsAsync("payments");
        var remaining = Assert.Single(active);
        Assert.Equal(bob.LeafIndex, remaining.LeafIndex);
        Assert.False(remaining.Revoked);

        var all = await tn.Admin.RecipientsAsync("payments", includeRevoked: true);
        Assert.Equal(2, all.Count);
        var revoked = Assert.Single(all.Where(recipient => recipient.LeafIndex == alice.LeafIndex));
        Assert.True(revoked.Revoked);
        Assert.NotNull(revoked.RevokedAt);
        Assert.Equal("did:key:zCSharpRecipientAlice", revoked.RecipientIdentity);
    }

    [Fact]
    public async Task AdminReplayReturnsDeterministicRecipientStateAfterReopen()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        string yamlPath;
        IReadOnlyList<TnProto.Admin.AdminRecipient> activeBefore;
        IReadOnlyList<TnProto.Admin.AdminRecipient> allBefore;
        ulong revokedBefore;

        await using (var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            yamlPath = tn.YamlPath;

            await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
            var alice = await tn.Admin.AddRecipientAsync(
                "payments",
                Path.Combine(projectDir, "alice.btn.mykit"),
                "did:key:zCSharpRecipientAlice");
            await tn.Admin.AddRecipientAsync(
                "payments",
                Path.Combine(projectDir, "bob.btn.mykit"),
                "did:key:zCSharpRecipientBob");
            await tn.Admin.RevokeRecipientAsync("payments", alice.LeafIndex);

            activeBefore = await tn.Admin.RecipientsAsync("payments");
            allBefore = await tn.Admin.RecipientsAsync("payments", includeRevoked: true);
            revokedBefore = await tn.Admin.RevokedCountAsync("payments");
        }

        await using var reopened = await Tn.InitAsync(yamlPath);

        Assert.Equal(activeBefore, await reopened.Admin.RecipientsAsync("payments"));
        Assert.Equal(allBefore, await reopened.Admin.RecipientsAsync("payments", includeRevoked: true));
        Assert.Equal(revokedBefore, await reopened.Admin.RevokedCountAsync("payments"));
    }

    [Fact]
    public async Task RotateAsyncBumpsGenerationAndKeepsOldEntriesReadable()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        string yamlPath;

        await using (var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            yamlPath = tn.YamlPath;

            await tn.InfoAsync("payment.before_rotate", new { order_id = "OLD-1" });

            var result = await tn.Admin.RotateAsync("default");

            Assert.Equal("default", result.Group);
            Assert.True(result.Generation >= 1);
            Assert.StartsWith("sha256:", result.PreviousKitSha256, StringComparison.Ordinal);
            Assert.StartsWith("sha256:", result.NewKitSha256, StringComparison.Ordinal);
            Assert.NotEqual(result.PreviousKitSha256, result.NewKitSha256);
            Assert.False(string.IsNullOrWhiteSpace(result.RotatedAt));

            await tn.InfoAsync("payment.after_rotate", new { order_id = "NEW-1" });

            var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true });
            Assert.Contains(entries, entry =>
                entry.EventType == "payment.before_rotate" && entry.GetString("order_id") == "OLD-1");
            Assert.Contains(entries, entry =>
                entry.EventType == "payment.after_rotate" && entry.GetString("order_id") == "NEW-1");
        }

        var yaml = await File.ReadAllTextAsync(yamlPath);
        Assert.Contains("index_epoch: 1", yaml, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(projectDir, ".tn", "payments", "keys", "default.btn.mykit.retired.0")));
    }

    [Fact]
    public async Task RotateAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.RotateAsync(""));

        Assert.Equal("group", error.ParamName);
    }

    [Fact]
    public async Task RevokeRecipientAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.RevokeRecipientAsync("", 1));

        Assert.Equal("group", error.ParamName);
    }

    [Fact]
    public async Task RecipientsAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.RecipientsAsync(""));

        Assert.Equal("group", error.ParamName);
    }

    [Fact]
    public async Task RevokedCountAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.RevokedCountAsync(""));

        Assert.Equal("group", error.ParamName);
    }

    [Fact]
    public async Task GrantReaderAsyncRejectsEmptyArgumentsBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var groupError = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.GrantReaderAsync("", "did:key:zReader", "kit.tnpkg"));
        Assert.Equal("group", groupError.ParamName);

        var didError = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.GrantReaderAsync("payments", "", "kit.tnpkg"));
        Assert.Equal("readerDid", didError.ParamName);

        var pathError = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.GrantReaderAsync("payments", "did:key:zReader", ""));
        Assert.Equal("outPath", pathError.ParamName);
    }

    [Fact]
    public async Task GrantReaderAsyncIsHibeOnly()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        // Message parity with Python tn.admin.grant_reader's guard.
        var error = await Assert.ThrowsAsync<TnException>(() =>
            tn.Admin.GrantReaderAsync(
                "default",
                "did:key:zReader",
                Path.Combine(projectDir, "kit.tnpkg")));

        Assert.Contains(
            "grant_reader is hibe-only. Use add_recipient for btn/jwe groups.",
            error.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task RotateIdPathAsyncRejectsEmptyGroupBeforeNativeCall()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            tn.Admin.RotateIdPathAsync("", "team/policy-b"));

        Assert.Equal("group", error.ParamName);
    }

    [Fact]
    public async Task RotateIdPathAsyncIsHibeOnly()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var error = await Assert.ThrowsAsync<TnException>(() =>
            tn.Admin.RotateIdPathAsync("default", "team/policy-b"));

        Assert.Contains(
            "this rotation is hibe-only (btn groups rotate via tn rotate).",
            error.Message,
            StringComparison.Ordinal);
    }
}
