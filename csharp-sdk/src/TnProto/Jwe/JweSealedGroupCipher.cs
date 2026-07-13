using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace TnProto.Jwe;

/// <summary>
/// Managed RFC 7516 JWE cipher for <c>cipher: jwe</c> group blocks — the
/// decrypt plug for the <see cref="UnsealOptions.GroupCiphers"/>
/// second-pass seam. The native Rust runtime opens JWE when its keystore
/// contains the group's raw X25519 reader key. Registering this managed
/// cipher under the group name also lets
/// <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>
/// open them.
/// </summary>
/// <remarks>
/// <para>
/// Opens the wire shape the Rust (RustCrypto/Dalek), Python (joserfc), and
/// TypeScript (panva/jose) runtimes seal: a General JSON Serialization object
/// whose recipient blocks
/// each wrap one shared A256GCM content key with <c>ECDH-ES+A256KW</c>
/// over X25519 (RFC 8037 OKP), the sender's ephemeral public key riding
/// in each recipient's <c>epk</c> header. Blocks are anonymous (no
/// <c>kid</c>), so opening trial-decrypts every block with every held
/// reader key — the AES-KW integrity check and the AEAD tag reject a
/// wrong key with no false-plaintext risk.
/// </para>
/// <para>
/// The TN marker rides in the JWE's own <c>aad</c> member; it must
/// byte-match the aad bytes the seam reconstructs from the record's
/// public <c>tn_aad</c> echo, in both directions: an empty
/// marker requires the member to be absent, a bound marker requires it
/// present and equal. This managed class is decrypt-only; the public C#
/// <see cref="Tn"/> seal and emit paths use the native Rust runtime.
/// </para>
/// </remarks>
public sealed class JweSealedGroupCipher : ISealedGroupCipher
{
    private const string KeyManagementAlg = "ECDH-ES+A256KW";

    private const string ContentEncryption = "A256GCM";

    private readonly byte[][] _privateKeys;

    /// <summary>
    /// Creates a cipher over one or more raw 32-byte X25519 reader
    /// private keys, tried in the order given (the current key first,
    /// then rotation-archived priors — the order
    /// <see cref="JweKeystore.LoadGroupCiphers"/> produces).
    /// </summary>
    /// <exception cref="ArgumentException">
    /// No keys were given, or a key is not exactly 32 bytes.
    /// </exception>
    public JweSealedGroupCipher(params byte[][] privateKeys)
    {
        ArgumentNullException.ThrowIfNull(privateKeys);
        if (privateKeys.Length == 0)
        {
            throw new ArgumentException(
                "At least one X25519 private key is required.",
                nameof(privateKeys));
        }

        _privateKeys = new byte[privateKeys.Length][];
        for (var i = 0; i < privateKeys.Length; i++)
        {
            var key = privateKeys[i];
            if (key is null || key.Length != 32)
            {
                throw new ArgumentException(
                    $"Private key {i} must be 32 raw X25519 bytes, got {key?.Length.ToString() ?? "null"}.",
                    nameof(privateKeys));
            }

            _privateKeys[i] = (byte[])key.Clone();
        }
    }

    /// <inheritdoc />
    public string Kind => "jwe";

    /// <inheritdoc />
    public byte[] Decrypt(byte[] ciphertext, byte[] aad)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        var jwe = ParseGeneralJson(ciphertext);
        EnforceAadRule(jwe.Aad, aad ?? []);

        byte[] iv;
        byte[] body;
        byte[] tag;
        JsonObject protectedHeader;
        try
        {
            iv = JweBase64Url.Decode(jwe.Iv);
            body = JweBase64Url.Decode(jwe.Ciphertext);
            tag = JweBase64Url.Decode(jwe.Tag);
            protectedHeader = JsonNode.Parse(Encoding.UTF8.GetString(JweBase64Url.Decode(jwe.Protected))) as JsonObject
                ?? throw new FormatException("protected header is not a JSON object");
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            throw new TnException(
                $"jwe: envelope segments are not valid base64url JSON ({exception.Message})",
                exception);
        }

        // RFC 7516 §5.1 step 14: the AEAD authenticates the ASCII of the
        // protected member as it appears on the wire, extended with
        // '.' + the aad member when one is present.
        var aeadAad = Encoding.ASCII.GetBytes(
            jwe.Aad is null ? jwe.Protected : $"{jwe.Protected}.{jwe.Aad}");

        foreach (var privateKey in _privateKeys)
        {
            foreach (var recipient in jwe.Recipients)
            {
                try
                {
                    var plaintext = OpenRecipientBlock(
                        privateKey, recipient, protectedHeader, jwe.Unprotected, iv, body, tag, aeadAad);
                    if (plaintext is not null)
                    {
                        return plaintext;
                    }
                }
                catch
                {
                    // Anonymous blocks: a failing candidate (AES-KW or
                    // AEAD integrity under a wrong key, an undecodable
                    // header field) just means "not my block" — keep
                    // walking, exactly like the Python/TS readers.
                }
            }
        }

        throw new TnException(_privateKeys.Length == 1
            ? "jwe: no recipient block in this envelope opens under this key"
            : $"jwe: none of {_privateKeys.Length} recipient keys opens this envelope");
    }

    /// <summary>
    /// One recipient-block candidate: ECDH-ES over the block's ephemeral
    /// key, the RFC 7518 §4.6 Concat KDF, AES-KW unwrap of the content
    /// key, then the A256GCM body. Returns <see langword="null"/> when
    /// the block sits outside the TN JOSE profile; throws when the
    /// crypto rejects the candidate (the caller treats both as a miss).
    /// </summary>
    private static byte[]? OpenRecipientBlock(
        byte[] privateKey,
        JweRecipient recipient,
        JsonObject protectedHeader,
        JsonObject? unprotectedHeader,
        byte[] iv,
        byte[] body,
        byte[] tag,
        byte[] aeadAad)
    {
        // RFC 7516 §7.2.1: the JOSE header is the union of the protected,
        // shared-unprotected, and per-recipient headers (disjoint by
        // spec; recipient-most lookup wins, matching the TS reader).
        JsonNode? Merged(string name) =>
            recipient.Header?[name] ?? unprotectedHeader?[name] ?? protectedHeader[name];

        if (AsString(Merged("alg")) != KeyManagementAlg
            || AsString(Merged("enc")) != ContentEncryption)
        {
            return null;
        }

        if (Merged("epk") is not JsonObject epk
            || AsString(epk["kty"]) != "OKP"
            || AsString(epk["crv"]) != "X25519"
            || AsString(epk["x"]) is not { } epkX)
        {
            return null;
        }

        var ephemeralPublic = JweBase64Url.Decode(epkX);
        if (ephemeralPublic.Length != 32)
        {
            return null;
        }

        // Our sealers bind no party info, but RFC 7518 feeds apu/apv into
        // the KDF when present, so honor them for conformance.
        var apu = AsString(Merged("apu")) is { } apuText ? JweBase64Url.Decode(apuText) : [];
        var apv = AsString(Merged("apv")) is { } apvText ? JweBase64Url.Decode(apvText) : [];

        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(privateKey, 0));
        var sharedSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(new X25519PublicKeyParameters(ephemeralPublic, 0), sharedSecret, 0);

        var kek = DeriveA256KwKek(sharedSecret, apu, apv);

        var wrapped = JweBase64Url.Decode(recipient.EncryptedKey);
        var unwrap = new AesWrapEngine();
        unwrap.Init(forWrapping: false, new KeyParameter(kek));
        var contentKey = unwrap.Unwrap(wrapped, 0, wrapped.Length);
        if (contentKey.Length != 32)
        {
            return null;
        }

        var plaintext = new byte[body.Length];
        using var aes = new AesGcm(contentKey, tagSizeInBytes: 16);
        aes.Decrypt(iv, body, tag, plaintext, aeadAad);
        return plaintext;
    }

    /// <summary>
    /// The Concat KDF of RFC 7518 §4.6 (NIST SP 800-56A §5.8.1, SHA-256)
    /// deriving the 256-bit A256KW key-encryption key. The derived width
    /// equals the hash width, so exactly one rep:
    /// <c>SHA-256(round1 || Z || AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo)</c>,
    /// where AlgorithmID is the length-prefixed <c>alg</c> value (the
    /// +A256KW variants use the alg name, not the enc name) and
    /// SuppPubInfo is the big-endian KEK bit length.
    /// </summary>
    private static byte[] DeriveA256KwKek(byte[] sharedSecret, byte[] apu, byte[] apv)
    {
        var algorithm = Encoding.ASCII.GetBytes(KeyManagementAlg);
        using var input = new MemoryStream();
        WriteUInt32BigEndian(input, 1);
        input.Write(sharedSecret, 0, sharedSecret.Length);
        WriteUInt32BigEndian(input, (uint)algorithm.Length);
        input.Write(algorithm, 0, algorithm.Length);
        WriteUInt32BigEndian(input, (uint)apu.Length);
        input.Write(apu, 0, apu.Length);
        WriteUInt32BigEndian(input, (uint)apv.Length);
        input.Write(apv, 0, apv.Length);
        WriteUInt32BigEndian(input, 256);
        return SHA256.HashData(input.ToArray());
    }

    private static void WriteUInt32BigEndian(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    /// <summary>
    /// The marker rule, both directions: an empty caller marker requires
    /// the wire to carry NO <c>aad</c> member, a bound marker requires
    /// the member present and byte-equal — so a stripped or injected
    /// member can never open (the
    /// <c>python/tn/cipher.py::_jwe_open_key</c> posture).
    /// </summary>
    private static void EnforceAadRule(string? aadMember, byte[] expected)
    {
        if (aadMember is null)
        {
            if (expected.Length != 0)
            {
                throw new TnException("jwe: aad marker mismatch");
            }

            return;
        }

        if (expected.Length == 0)
        {
            throw new TnException("jwe: aad marker mismatch");
        }

        byte[] bound;
        try
        {
            bound = JweBase64Url.Decode(aadMember);
        }
        catch (FormatException exception)
        {
            throw new TnException("jwe: field 'aad' is not valid base64url", exception);
        }

        if (!CryptographicOperations.FixedTimeEquals(bound, expected))
        {
            throw new TnException("jwe: aad marker mismatch");
        }
    }

    /// <summary>
    /// Parse and shape-validate the General JSON Serialization, mirroring
    /// <c>python/tn/cipher.py::_validate_jwe_general_json_shape</c>: a
    /// malformed envelope throws a <see cref="TnException"/> (which the
    /// unseal seam swallows per block) rather than surfacing an
    /// incidental parser error.
    /// </summary>
    private static GeneralJwe ParseGeneralJson(byte[] ciphertext)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(Encoding.UTF8.GetString(ciphertext));
        }
        catch (JsonException exception)
        {
            throw new TnException(
                $"jwe: ciphertext is not a JWE JSON object ({exception.Message})",
                exception);
        }

        if (node is not JsonObject obj)
        {
            throw new TnException("jwe: ciphertext is not a JWE JSON object");
        }

        var segments = new Dictionary<string, string>(4, StringComparer.Ordinal);
        foreach (var fieldName in (string[])["protected", "iv", "ciphertext", "tag"])
        {
            segments[fieldName] = AsString(obj[fieldName])
                ?? throw new TnException($"jwe: field '{fieldName}' must be present as a string");
        }

        string? aadMember = null;
        if (obj.ContainsKey("aad"))
        {
            aadMember = AsString(obj["aad"])
                ?? throw new TnException("jwe: field 'aad' must be a string when present");
        }

        if (obj["recipients"] is not JsonArray recipientsNode)
        {
            throw new TnException("jwe: field 'recipients' must be a list");
        }

        var recipients = new List<JweRecipient>(recipientsNode.Count);
        for (var i = 0; i < recipientsNode.Count; i++)
        {
            if (recipientsNode[i] is not JsonObject recipientObj)
            {
                throw new TnException($"jwe: recipient {i} must be an object");
            }

            var encryptedKey = AsString(recipientObj["encrypted_key"])
                ?? throw new TnException($"jwe: recipient {i} must include string 'encrypted_key'");

            JsonObject? header = null;
            if (recipientObj.ContainsKey("header"))
            {
                header = recipientObj["header"] as JsonObject
                    ?? throw new TnException($"jwe: recipient {i} header must be an object");
            }

            recipients.Add(new JweRecipient(encryptedKey, header));
        }

        return new GeneralJwe(
            segments["protected"],
            segments["iv"],
            segments["ciphertext"],
            segments["tag"],
            aadMember,
            obj["unprotected"] as JsonObject,
            recipients);
    }

    private static string? AsString(JsonNode? node)
    {
        return node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
    }

    private sealed record JweRecipient(string EncryptedKey, JsonObject? Header);

    private sealed record GeneralJwe(
        string Protected,
        string Iv,
        string Ciphertext,
        string Tag,
        string? Aad,
        JsonObject? Unprotected,
        IReadOnlyList<JweRecipient> Recipients);
}
