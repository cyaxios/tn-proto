using TnProto.Discovery;

namespace TnProto.Tests;

public sealed class DiscoveryTests
{
    [Fact]
    public async Task ListStreamsAsyncReturnsCeremoniesInStableOrder()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        await using (await Tn.InitProjectAsync("payments", new TnProjectOptions { ProjectDirectory = projectDir }))
        {
        }

        await using (await Tn.InitProjectAsync(
            "audit",
            new TnProjectOptions
            {
                ProjectDirectory = projectDir,
                Profile = TnProfile.Audit,
            }))
        {
        }

        var streams = await TnProjectDiscovery.ListStreamsAsync(projectDir);

        Assert.Equal(["audit", "payments"], streams.Select(stream => stream.Name).ToArray());
        Assert.Equal("audit", streams[0].Profile);
        Assert.Equal("transaction", streams[1].Profile);
        Assert.All(streams, stream => Assert.True(File.Exists(stream.YamlPath)));
    }

    [Fact]
    public async Task ListStreamsAsyncReturnsEmptyWhenTnRootIsMissing()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        var streams = await TnProjectDiscovery.ListStreamsAsync(projectDir);

        Assert.Empty(streams);
    }

    [Fact]
    public async Task ListStreamsAsyncUsesUnspecifiedProfileWhenYamlCannotBeRead()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));
        var yamlDir = Path.Combine(projectDir, ".tn", "broken");
        Directory.CreateDirectory(yamlDir);
        await File.WriteAllTextAsync(Path.Combine(yamlDir, "tn.yaml"), "ceremony:\n  id: broken\n");

        var streams = await TnProjectDiscovery.ListStreamsAsync(projectDir);

        var stream = Assert.Single(streams);
        Assert.Equal("broken", stream.Name);
        Assert.Equal("(unspecified)", stream.Profile);
    }
}
