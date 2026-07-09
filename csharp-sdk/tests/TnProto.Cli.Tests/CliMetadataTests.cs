using TnProto.Cli;

namespace TnProto.Cli.Tests;

public sealed class CliMetadataTests
{
    [Fact]
    public void CliUsesDevelopmentCommandName()
    {
        Assert.Equal("tn-dotnet", CliInfo.CommandName);
    }
}
