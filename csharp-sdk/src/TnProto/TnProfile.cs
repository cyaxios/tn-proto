namespace TnProto;

/// <summary>
/// TN profile presets shared by Python, TypeScript, Rust, and C# SDKs.
/// </summary>
public enum TnProfile
{
    /// <summary>Signed, chained, fsync-backed entries for maximum evidence.</summary>
    Transaction,

    /// <summary>Signed and chained entries with buffered durability.</summary>
    Audit,

    /// <summary>Signed entries without hash chaining.</summary>
    SecureLog,

    /// <summary>Fast encrypted telemetry without signatures or chaining.</summary>
    Telemetry,

    /// <summary>Development profile that writes encrypted envelopes to stdout.</summary>
    Stdout,
}

/// <summary>
/// Public metadata for one curated TN profile.
/// </summary>
public sealed record TnProfileInfo(
    TnProfile Profile,
    string Name,
    bool Encrypts,
    bool Signs,
    bool Chains,
    string Flush,
    string DefaultSink,
    string IntendedUse,
    bool Default)
{
    /// <summary>
    /// True when this profile has a file-backed replay surface.
    /// </summary>
    public bool HasReplaySurface => string.Equals(DefaultSink, "file_rotating", StringComparison.Ordinal);
}

/// <summary>
/// Public access to the curated TN profile catalog.
/// </summary>
public static class TnProfiles
{
    /// <summary>
    /// Conservative default profile used when project creation does not specify one.
    /// </summary>
    public static TnProfile DefaultProfile => TnProfile.Transaction;

    /// <summary>
    /// Canonical profile catalog in documentation order.
    /// </summary>
    public static IReadOnlyList<TnProfileInfo> All { get; } =
    [
        new(
            TnProfile.Transaction,
            "transaction",
            Encrypts: true,
            Signs: true,
            Chains: true,
            Flush: "fsync",
            DefaultSink: "file_rotating",
            IntendedUse: "Grants, revokes, payments, agent actions, security events. Maximum evidence: signed, chained, durable. Use when reconstruction and non-repudiation matter.",
            Default: true),
        new(
            TnProfile.Audit,
            "audit",
            Encrypts: true,
            Signs: true,
            Chains: true,
            Flush: "buffered",
            DefaultSink: "file_rotating",
            IntendedUse: "Normal business events where reconstruction matters but you can afford a small flush window. Same evidence as transaction; weaker durability.",
            Default: false),
        new(
            TnProfile.SecureLog,
            "secure_log",
            Encrypts: true,
            Signs: true,
            Chains: false,
            Flush: "buffered",
            DefaultSink: "file_rotating",
            IntendedUse: "Sensitive application logs where signing matters more than sequence. No chain; each entry stands alone. Cheaper to scale than audit/transaction.",
            Default: false),
        new(
            TnProfile.Telemetry,
            "telemetry",
            Encrypts: true,
            Signs: false,
            Chains: false,
            Flush: "async",
            DefaultSink: "file_rotating",
            IntendedUse: "Fast-as-stdlib-logger profile. Encryption still applies; signing and chain linkage are dropped to approach zero overhead. Writes a file so read works and also stdout.",
            Default: false),
        new(
            TnProfile.Stdout,
            "stdout",
            Encrypts: true,
            Signs: false,
            Chains: false,
            Flush: "async",
            DefaultSink: "stdout",
            IntendedUse: "Dev-friendly profile for local logs, notebooks, scratchpads, demos, and any context where print-like behavior is wanted.",
            Default: false),
    ];

    /// <summary>
    /// Return all canonical profile names in catalog order.
    /// </summary>
    public static IReadOnlyList<string> AllNames()
    {
        return All.Select(profile => profile.Name).ToArray();
    }

    /// <summary>
    /// True when the provided name exists in the profile catalog.
    /// </summary>
    public static bool IsKnown(string name)
    {
        return All.Any(profile => string.Equals(profile.Name, name, StringComparison.Ordinal));
    }

    /// <summary>
    /// Look up one profile by canonical name.
    /// </summary>
    public static TnProfileInfo Get(string name)
    {
        return All.FirstOrDefault(profile => string.Equals(profile.Name, name, StringComparison.Ordinal))
            ?? throw new ArgumentException($"Unknown profile {name}; catalog: {string.Join(", ", AllNames())}", nameof(name));
    }
}

/// <summary>
/// Helpers for TN profile presets.
/// </summary>
public static class TnProfileExtensions
{
    /// <summary>
    /// Returns the canonical profile name used in <c>tn.yaml</c> and across
    /// Python, TypeScript, and Rust SDKs.
    /// </summary>
    public static string ToTnName(this TnProfile profile)
    {
        return profile switch
        {
            TnProfile.Transaction => "transaction",
            TnProfile.Audit => "audit",
            TnProfile.SecureLog => "secure_log",
            TnProfile.Telemetry => "telemetry",
            TnProfile.Stdout => "stdout",
            _ => throw new ArgumentOutOfRangeException(nameof(profile), profile, "Unknown TN profile."),
        };
    }
}
