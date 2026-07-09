namespace TnProto;

/// <summary>
/// Options for <see cref="Tn.SealAsync{TFields}"/>.
/// </summary>
public sealed class SealOptions
{
    /// <summary>
    /// Chain a <c>tn.object.sealed</c> receipt row through the normal
    /// runtime emit path (default <see langword="true"/>). The receipt
    /// records the object id (its row hash), object type, and group names
    /// on the ceremony's admin surface; receipt failures propagate.
    /// </summary>
    public bool Receipt { get; init; } = true;

    /// <summary>
    /// Per-seal AAD marker map, merged over each group's configured
    /// default marker (per-seal wins per key), bound as additional
    /// authenticated data into every sealed group body, and echoed under
    /// the public <c>tn_aad</c> envelope field when non-empty.
    /// </summary>
    public IReadOnlyDictionary<string, object?>? Aad { get; init; }
}
