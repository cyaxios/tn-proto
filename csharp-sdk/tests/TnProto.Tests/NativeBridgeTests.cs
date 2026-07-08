using TnProto.Native;

namespace TnProto.Tests;

public sealed class NativeBridgeTests
{
    [Fact]
    public void VersionReturnsNativeBridgeVersion()
    {
        Assert.Equal("0.1.0", NativeBridge.Version());
    }

    [Fact]
    public void OpeningMissingYamlReportsNativeError()
    {
        var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "tn.yaml");

        var error = Assert.Throws<TnException>(() => NativeBridge.Open(missing));

        Assert.Contains("cannot find", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InitProjectCreatesProjectAndReturnsClosableHandle()
    {
        var projectDir = Path.Combine(Path.GetTempPath(), "tn-csharp-" + Guid.NewGuid().ToString("N"));

        using var handle = NativeBridge.InitProject("payments", projectDir);

        Assert.False(handle.IsInvalid);
        Assert.True(File.Exists(Path.Combine(projectDir, ".tn", "payments", "tn.yaml")));
    }
}
