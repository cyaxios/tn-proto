namespace TnProto;

/// <summary>
/// Standard TN event levels.
/// </summary>
public enum TnLogLevel
{
    /// <summary>Debug-level diagnostic event.</summary>
    Debug,

    /// <summary>Info-level event.</summary>
    Info,

    /// <summary>Warning-level event.</summary>
    Warning,

    /// <summary>Error-level event.</summary>
    Error,
}

/// <summary>
/// Helpers for TN event levels.
/// </summary>
public static class TnLogLevelExtensions
{
    /// <summary>
    /// Returns the canonical level string used by TN entries.
    /// </summary>
    public static string ToTnName(this TnLogLevel level)
    {
        return level switch
        {
            TnLogLevel.Debug => "debug",
            TnLogLevel.Info => "info",
            TnLogLevel.Warning => "warning",
            TnLogLevel.Error => "error",
            _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown TN log level."),
        };
    }
}
