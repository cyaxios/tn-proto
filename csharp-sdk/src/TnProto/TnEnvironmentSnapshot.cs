namespace TnProto;

/// <summary>
/// Safe read-only snapshot of the active TN runtime environment.
/// </summary>
public sealed record TnEnvironmentSnapshot(
    string Did,
    string YamlPath,
    string LogPath,
    string? ProjectName,
    string? ProjectDirectory);
