using TnProto;

namespace TnProto.Tests;

public sealed class SdkMetadataTests
{
    [Fact]
    public void SdkMetadataUsesReservedPackageName()
    {
        Assert.Equal("TnProto", TnSdk.PackageName);
        Assert.Equal("preview", TnSdk.Status);
    }

    [Fact]
    public void ProfileCatalogMatchesDocumentedNames()
    {
        var names = Enum.GetNames<TnProfile>();

        Assert.Contains(nameof(TnProfile.Transaction), names);
        Assert.Contains(nameof(TnProfile.Audit), names);
        Assert.Contains(nameof(TnProfile.SecureLog), names);
        Assert.Contains(nameof(TnProfile.Telemetry), names);
        Assert.Contains(nameof(TnProfile.Stdout), names);
    }

    [Fact]
    public void PublicProfileCatalogListsMetadataInStableOrder()
    {
        Assert.Equal(TnProfile.Transaction, TnProfiles.DefaultProfile);
        Assert.Equal(
            ["transaction", "audit", "secure_log", "telemetry", "stdout"],
            TnProfiles.AllNames());

        var transaction = TnProfiles.Get("transaction");
        Assert.True(transaction.Default);
        Assert.True(transaction.Encrypts);
        Assert.True(transaction.Signs);
        Assert.True(transaction.Chains);
        Assert.Equal("fsync", transaction.Flush);
        Assert.Equal("file_rotating", transaction.DefaultSink);
        Assert.True(transaction.HasReplaySurface);

        var stdout = TnProfiles.Get("stdout");
        Assert.False(stdout.Signs);
        Assert.False(stdout.Chains);
        Assert.Equal("stdout", stdout.DefaultSink);
        Assert.False(stdout.HasReplaySurface);
    }

    [Fact]
    public void PublicProfileCatalogValidatesNames()
    {
        Assert.True(TnProfiles.IsKnown("transaction"));
        Assert.False(TnProfiles.IsKnown("missing"));
        var error = Assert.Throws<ArgumentException>(() => TnProfiles.Get("missing"));
        Assert.Contains("transaction", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(TnProfile.Transaction, "transaction")]
    [InlineData(TnProfile.Audit, "audit")]
    [InlineData(TnProfile.SecureLog, "secure_log")]
    [InlineData(TnProfile.Telemetry, "telemetry")]
    [InlineData(TnProfile.Stdout, "stdout")]
    public void ProfileNamesMatchSharedCatalog(TnProfile profile, string expected)
    {
        Assert.Equal(expected, profile.ToTnName());
    }

    [Theory]
    [InlineData(TnLogLevel.Debug, "debug")]
    [InlineData(TnLogLevel.Info, "info")]
    [InlineData(TnLogLevel.Warning, "warning")]
    [InlineData(TnLogLevel.Error, "error")]
    public void LogLevelNamesMatchSharedCatalog(TnLogLevel level, string expected)
    {
        Assert.Equal(expected, level.ToTnName());
    }
}
