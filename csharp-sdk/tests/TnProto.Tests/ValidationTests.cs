using TnProto.Validation;

namespace TnProto.Tests;

public sealed class ValidationTests
{
    [Fact]
    public async Task ValidateProjectAsyncReportsCleanProjectAsValid()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using (await Tn.InitProjectAsync("default", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
        }

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.True(result.Valid);
        Assert.Equal(["default"], result.CeremonyNames);
        Assert.Empty(result.Errors);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public async Task ValidateProjectAsyncTreatsMissingTnRootAsNothingToValidate()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.True(result.Valid);
        Assert.Empty(result.CeremonyNames);
        Assert.Empty(result.Issues);
    }

    [Fact]
    public async Task ValidateProjectAsyncWarnsWhenDefaultCeremonyIsMissing()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using (await Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
        }

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.True(result.Valid);
        Assert.Single(result.Warnings);
        Assert.Contains("default", result.Warnings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidateProjectAsyncReportsUnknownProfile()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using (var tn = await Tn.InitProjectAsync("default", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            var yaml = await File.ReadAllTextAsync(tn.YamlPath);
            await File.WriteAllTextAsync(tn.YamlPath, yaml.Replace("profile: transaction", "profile: nope", StringComparison.Ordinal));
        }

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, issue => issue.Message.Contains("unknown profile", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateProjectAsyncReportsMissingGroupKit()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using (var tn = await Tn.InitProjectAsync("default", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            File.Delete(Path.Combine(Path.GetDirectoryName(tn.YamlPath)!, "keys", "default.btn.mykit"));
        }

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, issue => issue.Message.Contains("kit missing", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateProjectAsyncReportsDidMismatch()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using (var tn = await Tn.InitProjectAsync("default", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            var yaml = await File.ReadAllTextAsync(tn.YamlPath);
            await File.WriteAllTextAsync(
                tn.YamlPath,
                yaml.Replace(tn.Did, "did:key:zDifferent", StringComparison.Ordinal));
        }

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, issue => issue.Message.Contains("does not match", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateProjectAsyncReportsMalformedYamlWithoutThrowing()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var yamlDir = Path.Combine(projectDir, ".tn", "default");
        Directory.CreateDirectory(yamlDir);
        await File.WriteAllTextAsync(Path.Combine(yamlDir, "tn.yaml"), "ceremony: [\n");

        var result = await TnValidator.ValidateProjectAsync(projectDir);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, issue => issue.Message.Contains("read/parse failed", StringComparison.Ordinal));
    }
}
