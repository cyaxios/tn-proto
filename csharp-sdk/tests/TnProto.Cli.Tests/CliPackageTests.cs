using System.Text.Json.Nodes;
using TnProto;

namespace TnProto.Cli.Tests;

public sealed class CliPackageTests
{
    [Fact]
    public async Task AbsorbAppliesPackageAndPrintsJson()
    {
        var (consumerYamlPath, packagePath) = await CreateAbsorbFixtureAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["absorb", packagePath, "--yaml", consumerYamlPath, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI absorb output was not an object.");
        Assert.Equal("kit_bundle", result["kind"]?.GetValue<string>());
        Assert.Equal("accepted", result["status"]?.GetValue<string>());
        Assert.Equal(1UL, result["accepted_count"]?.GetValue<ulong>());
        Assert.Equal(0UL, result["deduped_count"]?.GetValue<ulong>());
        Assert.False(result["noop"]?.GetValue<bool>());
        Assert.Equal(0UL, result["conflict_count"]?.GetValue<ulong>());
    }

    [Fact]
    public async Task AbsorbDuplicatePackageReportsNoOpJson()
    {
        var (consumerYamlPath, packagePath) = await CreateAbsorbFixtureAsync();
        await using (var tn = await Tn.InitAsync(consumerYamlPath))
        {
            await tn.Packages.AbsorbAsync(packagePath);
        }

        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["absorb", packagePath, "--yaml", consumerYamlPath, "--json"],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI absorb output was not an object.");
        Assert.Equal("noop", result["status"]?.GetValue<string>());
        Assert.True(result["noop"]?.GetValue<bool>());
        Assert.Equal(0UL, result["accepted_count"]?.GetValue<ulong>());
        Assert.Equal(1UL, result["deduped_count"]?.GetValue<ulong>());
    }

    [Fact]
    public async Task AbsorbPrintsTextOutput()
    {
        var (consumerYamlPath, packagePath) = await CreateAbsorbFixtureAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["absorb", packagePath, "--yaml", consumerYamlPath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Contains("absorbed kit_bundle: accepted", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("accepted=1", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task AbsorbRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(["absorb", "package.tnpkg"], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AbsorbRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["absorb", "package.tnpkg", "--yaml", "tn.yaml", "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown absorb option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task CompileCreatesPackageAndPrintsJson()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectWithGroupAsync();
        var packagePath = Path.Combine(projectDir, "compiled-enrolment.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "compile", "default",
                "--yaml", yamlPath,
                "--recipient-did", recipientDid,
                "--out", packagePath,
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.True(File.Exists(packagePath));

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI compile output was not an object.");
        Assert.Equal(Path.GetFullPath(packagePath), result["path"]?.GetValue<string>());
        Assert.Equal(recipientDid, result["recipient_did"]?.GetValue<string>());
        Assert.False(result["sealed_for_recipient"]?.GetValue<bool>());
        Assert.Equal(64, result["manifest_sha256"]?.GetValue<string>().Length);
        Assert.Equal(64, result["package_sha256"]?.GetValue<string>().Length);
    }

    [Fact]
    public async Task CompileCanSealForRecipient()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectWithGroupAsync();
        var packagePath = Path.Combine(projectDir, "compiled-enrolment-sealed.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "compile", "default",
                "--yaml", yamlPath,
                "--recipient-did", recipientDid,
                "--out", packagePath,
                "--seal",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI compile output was not an object.");
        Assert.True(result["sealed_for_recipient"]?.GetValue<bool>());

        await using var tn = await Tn.InitAsync(yamlPath);
        var info = await tn.Packages.InspectAsync(packagePath);
        Assert.True(info.Sealed);
        Assert.True(info.IsAddressedTo(recipientDid));
    }

    [Fact]
    public async Task CompilePrintsTextOutput()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectWithGroupAsync();
        var packagePath = Path.Combine(projectDir, "compiled-enrolment.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["compile", "default", "--yaml", yamlPath, "--recipient-did", recipientDid, "--out", packagePath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal($"compiled: {Path.GetFullPath(packagePath)}" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task CompileRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["compile", "default", "--recipient-did", "did:key:zAlice", "--out", "compiled.tnpkg"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task CompileRequiresRecipientDid()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["compile", "default", "--yaml", "tn.yaml", "--out", "compiled.tnpkg"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --recipient-did", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task CompileRequiresOutPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["compile", "default", "--yaml", "tn.yaml", "--recipient-did", "did:key:zAlice"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --out", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task CompileRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["compile", "default", "--yaml", "tn.yaml", "--recipient-did", "did:key:zAlice", "--out", "compiled.tnpkg", "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown compile option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task BundleCreatesPackageAndPrintsJson()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectWithGroupAsync();
        var bundlePath = Path.Combine(projectDir, "alice.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "bundle",
                "--yaml", yamlPath,
                "--recipient-did", recipientDid,
                "--out", bundlePath,
                "--group", "payments",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.True(File.Exists(bundlePath));

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI bundle output was not an object.");
        Assert.Equal(Path.GetFullPath(bundlePath), result["path"]?.GetValue<string>());
        Assert.Equal(recipientDid, result["recipient_did"]?.GetValue<string>());
        Assert.False(result["sealed_for_recipient"]?.GetValue<bool>());
        var groups = result["groups"] as JsonArray
            ?? throw new InvalidOperationException("CLI bundle output omitted groups.");
        Assert.Contains(groups, group => group?.GetValue<string>() == "payments");
    }

    [Fact]
    public async Task BundleCanSealForRecipient()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectWithGroupAsync();
        var bundlePath = Path.Combine(projectDir, "sealed-alice.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            [
                "bundle",
                "--yaml", yamlPath,
                "--recipient-did", recipientDid,
                "--out", bundlePath,
                "--group", "payments",
                "--seal",
                "--json",
            ],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());

        var result = JsonNode.Parse(output.ToString()) as JsonObject
            ?? throw new InvalidOperationException("CLI bundle output was not an object.");
        Assert.True(result["sealed_for_recipient"]?.GetValue<bool>());

        await using var tn = await Tn.InitAsync(yamlPath);
        var info = await tn.Packages.InspectAsync(bundlePath);
        Assert.True(info.Sealed);
        Assert.True(info.IsAddressedTo(recipientDid));
    }

    [Fact]
    public async Task BundlePrintsTextOutput()
    {
        var (yamlPath, projectDir, recipientDid) = await CreateProjectWithGroupAsync();
        var bundlePath = Path.Combine(projectDir, "alice.tnpkg");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["bundle", "--yaml", yamlPath, "--recipient-did", recipientDid, "--out", bundlePath],
            output,
            error);

        Assert.Equal(0, exitCode);
        Assert.Equal($"bundle: {Path.GetFullPath(bundlePath)}" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task BundleRequiresYamlPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["bundle", "--recipient-did", "did:key:zAlice", "--out", "alice.tnpkg"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --yaml", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task BundleRequiresRecipientDid()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["bundle", "--yaml", "tn.yaml", "--out", "alice.tnpkg"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --recipient-did", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task BundleRequiresOutPath()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["bundle", "--yaml", "tn.yaml", "--recipient-did", "did:key:zAlice"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("requires --out", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task BundleRejectsUnknownOption()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApp.RunAsync(
            ["bundle", "--yaml", "tn.yaml", "--recipient-did", "did:key:zAlice", "--out", "alice.tnpkg", "--surprise"],
            output,
            error);

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown bundle option", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    private static async Task<(string YamlPath, string ProjectDir, string RecipientDid)> CreateProjectWithGroupAsync()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-" + Guid.NewGuid().ToString("N"));
        await using var tn = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = projectDir });
        await tn.Admin.EnsureGroupAsync("payments", ["order_id"]);
        var recipient = TnIdentity.FromSeed(Enumerable.Repeat((byte)71, 32).ToArray());
        return (tn.YamlPath, projectDir, recipient.Did);
    }

    private static async Task<(string ConsumerYamlPath, string PackagePath)> CreateAbsorbFixtureAsync()
    {
        var producerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-producer-" + Guid.NewGuid().ToString("N"));
        var consumerDir = Path.Combine(Path.GetTempPath(), "tn-csharp-cli-consumer-" + Guid.NewGuid().ToString("N"));

        await using var producer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = producerDir });
        await using var consumer = await Tn.InitProjectAsync(
            "payments",
            new TnProjectOptions { ProjectDirectory = consumerDir });

        var packagePath = Path.Combine(producerDir, "compiled-enrolment.tnpkg");
        await producer.Packages.CompileEnrolmentAsync(new()
        {
            Group = "default",
            RecipientDid = consumer.Did,
            OutPath = packagePath,
        });

        return (consumer.YamlPath, packagePath);
    }
}
