namespace TnProto;

/// <summary>
/// A managed group cipher for the sealed-object second-pass decrypt seam.
/// </summary>
/// <remarks>
/// The native call leaves a group block sealed when it holds no usable key or
/// a compile-time cipher feature is disabled. A host may also use this seam
/// with an external key store; see <see cref="SealedBlock.KeystoreCandidates"/>.
/// Registering an implementation under the group name in
/// <see cref="UnsealOptions.GroupCiphers"/> lets
/// <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>
/// open those blocks after the native call, without reimplementing the AAD
/// reconstruction: the exact bytes to authenticate arrive as
/// <see cref="SealedBlock.AadB64"/>.
/// </remarks>
public interface ISealedGroupCipher
{
    /// <summary>
    /// Cipher kind label (for example <c>"jwe"</c>), matched against
    /// <see cref="SealedBlock.KeystoreCandidates"/> by diagnostics only —
    /// the block-to-cipher routing key is the group name.
    /// </summary>
    string Kind { get; }

    /// <summary>
    /// Decrypt one group block body. <paramref name="aad"/> carries the
    /// exact additional-authenticated-data bytes the publisher bound
    /// (empty when the object bound no marker for this group). Throw on
    /// any failure — the caller swallows it and leaves the block sealed.
    /// </summary>
    byte[] Decrypt(byte[] ciphertext, byte[] aad);
}
