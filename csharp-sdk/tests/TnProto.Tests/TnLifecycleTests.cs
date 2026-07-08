namespace TnProto.Tests;

public sealed class TnLifecycleTests
{
    [Fact]
    public async Task InitProjectAsyncCreatesProjectAndTracksPaths()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        Assert.Equal("payments", tn.ProjectName);
        Assert.Equal(Path.GetFullPath(projectDir), tn.ProjectDirectory);
        Assert.Equal(Tn.ProjectYamlPath(projectDir, "payments"), tn.YamlPath);
        Assert.EndsWith(Path.Combine("logs", "default.ndjson"), tn.LogPath, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("did:key:", tn.Did, StringComparison.Ordinal);
        Assert.True(File.Exists(tn.YamlPath));
    }

    [Fact]
    public async Task InitProjectAsyncHonorsSelectedProfile()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using var tn = await Tn.InitProjectAsync(
            "telemetry",
            new TnProjectOptions
            {
                ProjectDirectory = projectDir,
                Profile = TnProfile.Telemetry,
            });

        var yaml = await File.ReadAllTextAsync(tn.YamlPath);

        Assert.Contains("profile: telemetry", yaml, StringComparison.Ordinal);
        Assert.Contains("sign: false", yaml, StringComparison.Ordinal);
        Assert.Contains("chain: false", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InitAsyncOpensExistingYaml()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        await using (await Tn.InitProjectAsync(
            "audit",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
        }

        await using var reopened = await Tn.InitAsync(Tn.ProjectYamlPath(projectDir, "audit"));

        Assert.Equal("audit", reopened.ProjectName);
        Assert.Equal(Path.GetFullPath(projectDir), reopened.ProjectDirectory);
        Assert.EndsWith(Path.Combine("logs", "default.ndjson"), reopened.LogPath, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("did:key:", reopened.Did, StringComparison.Ordinal);
        Assert.True(File.Exists(reopened.YamlPath));
    }

    [Fact]
    public async Task RuntimeMetadataIsStableAfterReopen()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        string did;
        string logPath;
        string yamlPath;
        await using (var tn = await Tn.InitProjectAsync(
            "metadata",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            did = tn.Did;
            logPath = tn.LogPath;
            yamlPath = tn.YamlPath;
        }

        await using var reopened = await Tn.InitAsync(yamlPath);

        Assert.Equal(did, reopened.Did);
        Assert.Equal(logPath, reopened.LogPath);
        Assert.Equal(yamlPath, reopened.YamlPath);
    }

    [Fact]
    public async Task EnvironmentSnapshotReturnsSafeRuntimeFields()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var snapshot = tn.EnvironmentSnapshot();

        Assert.Equal(tn.Did, snapshot.Did);
        Assert.Equal(tn.YamlPath, snapshot.YamlPath);
        Assert.Equal(tn.LogPath, snapshot.LogPath);
        Assert.Equal("payments", snapshot.ProjectName);
        Assert.Equal(Path.GetFullPath(projectDir), snapshot.ProjectDirectory);
    }

    [Fact]
    public async Task InitProjectAsyncRejectsEmptyProjectNameBeforeNativeCall()
    {
        var error = await Assert.ThrowsAsync<ArgumentException>(() => Tn.InitProjectAsync(""));

        Assert.Equal("project", error.ParamName);
    }

    [Fact]
    public async Task DisposeIsIdempotent()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });

        tn.Dispose();
        tn.Dispose();
        await tn.DisposeAsync();
    }
}
