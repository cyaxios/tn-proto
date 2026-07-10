namespace TnProto.Jwe;

/// <summary>
/// base64url decoding (RFC 7515 §2: the URL-safe alphabet, unpadded) for
/// JWE wire segments.
/// </summary>
internal static class JweBase64Url
{
    /// <summary>
    /// Decode one base64url segment. Throws <see cref="FormatException"/>
    /// when the input is not decodable base64.
    /// </summary>
    public static byte[] Decode(string value)
    {
        var standard = value.Replace('-', '+').Replace('_', '/');
        var padding = (4 - (standard.Length % 4)) % 4;
        return Convert.FromBase64String(standard.PadRight(standard.Length + padding, '='));
    }
}
