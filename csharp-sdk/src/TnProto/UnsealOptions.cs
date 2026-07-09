namespace TnProto;

/// <summary>
/// Options for <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>.
/// </summary>
public sealed class UnsealOptions
{
    /// <summary>
    /// Verify the signature and row hash before decrypting (default
    /// <see langword="true"/>). A failed check throws
    /// <see cref="TnVerifyException"/>; with <see langword="false"/> both
    /// <see cref="UnsealValidity"/> flags report <see langword="false"/>
    /// and the decrypt walk proceeds.
    /// </summary>
    public bool Verify { get; init; } = true;

    /// <summary>
    /// Bring-your-own-kit override: a directory holding recipient key
    /// files (<c>&lt;group&gt;.btn.mykit</c> / <c>&lt;group&gt;.jwe.mykey</c> /
    /// <c>&lt;group&gt;.hibe.sk</c>). When set, only <see cref="Group"/> is
    /// decrypted and the runtime's own groups and keystore are not
    /// consulted.
    /// </summary>
    public string? AsRecipient { get; init; }

    /// <summary>
    /// The group the <see cref="AsRecipient"/> override opens (default
    /// <c>"default"</c>). Ignored on the default walk, which tries every
    /// block.
    /// </summary>
    public string Group { get; init; } = "default";

    /// <summary>
    /// Managed ciphers for the second-pass decrypt seam, keyed by group
    /// name. After the native walk, every block still sealed whose group
    /// has a registered cipher is decrypted managed-side and merged into
    /// the result exactly as a native open would be. A cipher throw for
    /// one block is swallowed — that block simply stays sealed.
    /// </summary>
    public IReadOnlyDictionary<string, ISealedGroupCipher>? GroupCiphers { get; init; }
}
