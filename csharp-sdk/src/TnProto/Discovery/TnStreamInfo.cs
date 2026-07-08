namespace TnProto.Discovery;

/// <summary>
/// One TN ceremony/stream discovered under a project's <c>.tn</c> directory.
/// </summary>
public sealed record TnStreamInfo(
    string Name,
    string Profile,
    string YamlPath);
