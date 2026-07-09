namespace TnProto;

/// <summary>
/// Identity material restored from BIP-39 mnemonic words.
/// </summary>
public sealed record MnemonicIdentityResult(
    DeviceIdentity Identity,
    string IdentitySeedBase64Url,
    string Mnemonic);
