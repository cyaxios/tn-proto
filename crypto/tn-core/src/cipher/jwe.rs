//! RFC 7516 General JSON JWE for native TN runtimes.
//!
//! The bytes returned by this cipher are the JWE JSON object itself. The TN
//! envelope performs the only outer encoding when it stores those bytes in a
//! group's `ciphertext` field.

#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
mod native {
    use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
    use aes_gcm::{Aes256Gcm, Nonce, Tag};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use rand_core::RngCore as _;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};
    use subtle::ConstantTimeEq as _;
    use zeroize::Zeroizing;

    use crate::{Error, Result};

    const ALG: &str = "ECDH-ES+A256KW";
    const ENC: &str = "A256GCM";
    const MAX_RECIPIENTS: usize = 1_024;
    const MAX_READER_KEYS: usize = 1_024;
    const MAX_JWE_BYTES: usize = 128 * 1024 * 1024;
    const MAX_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
    const MAX_AAD_BYTES: usize = 64 * 1024;

    /// A native TN JWE cipher using anonymous raw-X25519 recipient blocks.
    pub struct JweCipher {
        group: String,
        recipient_public_keys: Vec<[u8; 32]>,
        reader_private_keys: Vec<Zeroizing<[u8; 32]>>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GeneralJwe {
        protected: String,
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        unprotected: Option<JoseHeader>,
        recipients: Vec<Recipient>,
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        aad: Option<String>,
        iv: String,
        ciphertext: String,
        tag: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Recipient {
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        header: Option<JoseHeader>,
        encrypted_key: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JoseHeader {
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        alg: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        enc: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        epk: Option<EphemeralPublicKey>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EphemeralPublicKey {
        kty: String,
        crv: String,
        x: String,
    }

    struct ParsedJwe {
        protected: String,
        aad: Option<String>,
        iv: [u8; 12],
        ciphertext: Vec<u8>,
        tag: [u8; 16],
        recipients: Vec<ParsedRecipient>,
    }

    struct ParsedRecipient {
        ephemeral_public: [u8; 32],
        encrypted_key: [u8; 40],
    }

    fn deserialize_present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: Deserialize<'de>,
    {
        T::deserialize(deserializer).map(Some)
    }

    impl JweCipher {
        /// Bind a group to enrolled raw X25519 publisher and reader material.
        pub fn new(
            group: impl Into<String>,
            recipient_public_keys: &[[u8; 32]],
            reader_private_keys: &[[u8; 32]],
        ) -> Result<Self> {
            let reader_private_keys = reader_private_keys
                .iter()
                .map(|key| Zeroizing::new(*key))
                .collect();
            Self::new_with_owned_reader_keys(group, recipient_public_keys, reader_private_keys)
        }

        pub(crate) fn new_with_owned_reader_keys(
            group: impl Into<String>,
            recipient_public_keys: &[[u8; 32]],
            reader_private_keys: Vec<Zeroizing<[u8; 32]>>,
        ) -> Result<Self> {
            validate_key_counts(recipient_public_keys.len(), reader_private_keys.len())?;
            Ok(Self {
                group: group.into(),
                recipient_public_keys: recipient_public_keys.to_vec(),
                reader_private_keys,
            })
        }

        fn not_entitled(&self) -> Error {
            Error::NotEntitled {
                group: self.group.clone(),
            }
        }
    }

    impl super::super::GroupCipher for JweCipher {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            self.encrypt_with_aad(plaintext, &[])
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            self.decrypt_with_aad(ciphertext, &[])
        }

        fn kind(&self) -> &'static str {
            "jwe"
        }

        fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            validate_seal_sizes(plaintext, aad)?;
            if self.recipient_public_keys.is_empty() {
                return Err(Error::NotAPublisher {
                    group: self.group.clone(),
                    reason: "no enrolled JWE recipient public keys".to_owned(),
                });
            }
            let cek = random_secret();
            let recipients = self
                .recipient_public_keys
                .iter()
                .map(|public| wrap_for_recipient(public, &cek))
                .collect::<Result<Vec<_>>>()?;
            let protected = protected_segment()?;
            let aad_segment = (!aad.is_empty()).then(|| URL_SAFE_NO_PAD.encode(aad));
            let authentication_data = authentication_data(&protected, aad_segment.as_deref());
            let (iv, ciphertext, tag) = seal_content(plaintext, &cek, &authentication_data)?;
            serialize_jwe(&GeneralJwe {
                protected,
                unprotected: None,
                recipients,
                aad: aad_segment,
                iv: URL_SAFE_NO_PAD.encode(iv),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
                tag: URL_SAFE_NO_PAD.encode(tag),
            })
        }

        fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            let parsed = parse_jwe(ciphertext)?;
            if !aad_matches(parsed.aad.as_deref(), aad)? {
                return Err(Error::Cipher("JWE AAD does not match the envelope".into()));
            }
            let authentication_data = authentication_data(&parsed.protected, parsed.aad.as_deref());
            let mut unwrapped_cek = false;
            for private in &self.reader_private_keys {
                for recipient in &parsed.recipients {
                    let Some(cek) = unwrap_for_reader(private, recipient) else {
                        continue;
                    };
                    unwrapped_cek = true;
                    if let Some(plaintext) = open_content(&parsed, &cek, &authentication_data) {
                        return Ok(plaintext);
                    }
                }
            }
            if unwrapped_cek {
                Err(Error::Cipher("JWE content authentication failed".into()))
            } else {
                Err(self.not_entitled())
            }
        }
    }

    fn validate_key_counts(recipients: usize, readers: usize) -> Result<()> {
        if recipients > MAX_RECIPIENTS {
            return Err(Error::InvalidConfig(format!(
                "JWE has {recipients} recipients; maximum is {MAX_RECIPIENTS}"
            )));
        }
        if readers > MAX_READER_KEYS {
            return Err(Error::InvalidConfig(format!(
                "JWE has {readers} reader keys; maximum is {MAX_READER_KEYS}"
            )));
        }
        Ok(())
    }

    fn validate_seal_sizes(plaintext: &[u8], aad: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::Cipher(format!(
                "JWE plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes"
            )));
        }
        if aad.len() > MAX_AAD_BYTES {
            return Err(Error::Cipher(format!(
                "JWE AAD exceeds {MAX_AAD_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn random_secret() -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        rand_core::OsRng.fill_bytes(&mut bytes[..]);
        bytes
    }

    fn wrap_for_recipient(public: &[u8; 32], cek: &[u8; 32]) -> Result<Recipient> {
        let ephemeral_private = random_secret();
        let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral_private);
        let shared = shared_secret(&MontgomeryPoint(*public), &ephemeral_private)
            .ok_or_else(|| Error::Cipher("JWE X25519 produced an all-zero shared secret".into()))?;
        let kek = derive_kek(&shared);
        let mut encrypted_key = [0_u8; 40];
        aes_kw::KekAes256::try_from(&kek[..])
            .and_then(|wrapper| wrapper.wrap(cek, &mut encrypted_key))
            .map_err(|error| Error::Cipher(format!("JWE AES-KW wrap failed: {error}")))?;
        Ok(Recipient {
            header: Some(JoseHeader {
                alg: Some(ALG.to_owned()),
                enc: None,
                epk: Some(EphemeralPublicKey {
                    kty: "OKP".to_owned(),
                    crv: "X25519".to_owned(),
                    x: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
                }),
            }),
            encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
        })
    }

    fn unwrap_for_reader(
        private: &[u8; 32],
        recipient: &ParsedRecipient,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let shared = shared_secret(&MontgomeryPoint(recipient.ephemeral_public), private)?;
        let kek = derive_kek(&shared);
        let mut cek = Zeroizing::new([0_u8; 32]);
        let wrapper = aes_kw::KekAes256::try_from(&kek[..]).ok()?;
        wrapper
            .unwrap(&recipient.encrypted_key, &mut cek[..])
            .ok()?;
        Some(cek)
    }

    fn shared_secret(public: &MontgomeryPoint, private: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        let shared = Zeroizing::new(public.mul_clamped(*private).to_bytes());
        if bool::from(shared.ct_eq(&[0_u8; 32])) {
            None
        } else {
            Some(shared)
        }
    }

    fn derive_kek(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(1_u32.to_be_bytes());
        digest.update(shared);
        update_length_prefixed(&mut digest, ALG.as_bytes());
        update_length_prefixed(&mut digest, &[]);
        update_length_prefixed(&mut digest, &[]);
        digest.update(256_u32.to_be_bytes());
        Zeroizing::new(digest.finalize().into())
    }

    fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
        let length = u32::try_from(value.len()).expect("fixed JOSE KDF fields fit in u32");
        digest.update(length.to_be_bytes());
        digest.update(value);
    }

    fn protected_segment() -> Result<String> {
        let bytes = serde_json::to_vec(&serde_json::json!({ "enc": ENC })).map_err(|error| {
            Error::Internal(format!("JWE header serialization failed: {error}"))
        })?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn authentication_data(protected: &str, aad: Option<&str>) -> Vec<u8> {
        let extra = aad.map_or(0, |value| value.len() + 1);
        let mut out = Vec::with_capacity(protected.len() + extra);
        out.extend_from_slice(protected.as_bytes());
        if let Some(value) = aad {
            out.push(b'.');
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    fn seal_content(
        plaintext: &[u8],
        cek: &[u8; 32],
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>, [u8; 16])> {
        let mut iv = [0_u8; 12];
        rand_core::OsRng.fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new_from_slice(cek)
            .map_err(|error| Error::Cipher(format!("JWE CEK setup failed: {error}")))?;
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), aad, &mut ciphertext)
            .map_err(|error| Error::Cipher(format!("JWE A256GCM seal failed: {error}")))?;
        Ok((iv, ciphertext, tag.into()))
    }

    fn open_content(parsed: &ParsedJwe, cek: &[u8; 32], aad: &[u8]) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(cek).ok()?;
        let mut plaintext = parsed.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&parsed.iv),
                aad,
                &mut plaintext,
                Tag::from_slice(&parsed.tag),
            )
            .ok()?;
        Some(plaintext)
    }

    fn serialize_jwe(jwe: &GeneralJwe) -> Result<Vec<u8>> {
        serde_json::to_vec(&jwe)
            .map_err(|error| Error::Internal(format!("JWE serialization failed: {error}")))
    }

    fn parse_jwe(ciphertext: &[u8]) -> Result<ParsedJwe> {
        if ciphertext.len() > MAX_JWE_BYTES {
            return Err(malformed(format!(
                "ciphertext exceeds {MAX_JWE_BYTES} bytes"
            )));
        }
        let wire: GeneralJwe = serde_json::from_slice(ciphertext)
            .map_err(|error| malformed(format!("ciphertext is not valid profile JSON: {error}")))?;
        validate_recipient_count(wire.recipients.len())?;
        let protected_header = parse_protected(&wire.protected)?;
        validate_protected_enc(&protected_header)?;
        let multiple = wire.recipients.len() > 1;
        let shared = wire.unprotected.as_ref();
        let recipients = wire
            .recipients
            .into_iter()
            .map(|recipient| parse_recipient(recipient, &protected_header, shared, multiple))
            .collect::<Result<Vec<_>>>()?;
        Ok(ParsedJwe {
            protected: wire.protected,
            aad: validate_aad_segment(wire.aad)?,
            iv: decode_array("iv", &wire.iv)?,
            ciphertext: decode_b64("ciphertext", &wire.ciphertext, MAX_JWE_BYTES)?,
            tag: decode_array("tag", &wire.tag)?,
            recipients,
        })
    }

    fn validate_recipient_count(count: usize) -> Result<()> {
        if count == 0 || count > MAX_RECIPIENTS {
            return Err(malformed(format!(
                "recipients must contain between 1 and {MAX_RECIPIENTS} entries"
            )));
        }
        Ok(())
    }

    fn parse_protected(segment: &str) -> Result<JoseHeader> {
        let bytes = decode_b64("protected", segment, 256)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| malformed(format!("protected header is invalid: {error}")))
    }

    fn validate_protected_enc(header: &JoseHeader) -> Result<()> {
        if header.enc.as_deref() != Some(ENC) {
            return Err(malformed("protected enc must be A256GCM"));
        }
        Ok(())
    }

    fn parse_recipient(
        recipient: Recipient,
        protected: &JoseHeader,
        shared: Option<&JoseHeader>,
        multiple: bool,
    ) -> Result<ParsedRecipient> {
        let local = recipient.header.as_ref();
        validate_header_union(protected, shared, local)?;
        let alg = protected
            .alg
            .as_deref()
            .or_else(|| shared.and_then(|header| header.alg.as_deref()))
            .or_else(|| local.and_then(|header| header.alg.as_deref()));
        if alg != Some(ALG) {
            return Err(malformed("merged alg must be ECDH-ES+A256KW"));
        }
        let epk = resolve_epk(protected, shared, local, multiple)?;
        if epk.kty != "OKP" || epk.crv != "X25519" {
            return Err(malformed("recipient epk must be an X25519 OKP JWK"));
        }
        Ok(ParsedRecipient {
            ephemeral_public: decode_array("recipient epk.x", &epk.x)?,
            encrypted_key: decode_array("recipient encrypted_key", &recipient.encrypted_key)?,
        })
    }

    fn validate_header_union(
        protected: &JoseHeader,
        shared: Option<&JoseHeader>,
        recipient: Option<&JoseHeader>,
    ) -> Result<()> {
        let shared = shared.unwrap_or(&EMPTY_HEADER);
        let recipient = recipient.unwrap_or(&EMPTY_HEADER);
        let counts = [
            (
                "alg",
                present(&protected.alg) + present(&shared.alg) + present(&recipient.alg),
            ),
            (
                "enc",
                present(&protected.enc) + present(&shared.enc) + present(&recipient.enc),
            ),
            (
                "epk",
                present(&protected.epk) + present(&shared.epk) + present(&recipient.epk),
            ),
        ];
        for (name, count) in counts {
            if count > 1 {
                return Err(malformed(format!("header member {name} is duplicated")));
            }
        }
        Ok(())
    }

    fn resolve_epk<'a>(
        protected: &'a JoseHeader,
        shared: Option<&'a JoseHeader>,
        recipient: Option<&'a JoseHeader>,
        multiple: bool,
    ) -> Result<&'a EphemeralPublicKey> {
        if multiple && (protected.epk.is_some() || shared.is_some_and(|h| h.epk.is_some())) {
            return Err(malformed("multi-recipient epk must be per-recipient"));
        }
        if shared.is_some_and(|header| header.epk.is_some()) {
            return Err(malformed("shared unprotected epk is not permitted"));
        }
        if multiple {
            return recipient
                .and_then(|header| header.epk.as_ref())
                .ok_or_else(|| malformed("each recipient must contain epk"));
        }
        protected
            .epk
            .as_ref()
            .or_else(|| recipient.and_then(|header| header.epk.as_ref()))
            .ok_or_else(|| malformed("merged header must contain epk"))
    }

    fn present<T>(value: &Option<T>) -> usize {
        usize::from(value.is_some())
    }

    static EMPTY_HEADER: JoseHeader = JoseHeader {
        alg: None,
        enc: None,
        epk: None,
    };

    fn validate_aad_segment(aad: Option<String>) -> Result<Option<String>> {
        if let Some(segment) = aad.as_deref() {
            let decoded = decode_b64("aad", segment, MAX_AAD_BYTES)?;
            if decoded.is_empty() {
                return Err(malformed("aad must be omitted when empty"));
            }
        }
        Ok(aad)
    }

    fn aad_matches(segment: Option<&str>, expected: &[u8]) -> Result<bool> {
        if expected.len() > MAX_AAD_BYTES {
            return Ok(false);
        }
        match segment {
            Some(value) if !expected.is_empty() => {
                let actual = decode_b64("aad", value, MAX_AAD_BYTES)?;
                Ok(bool::from(actual.as_slice().ct_eq(expected)))
            }
            None if expected.is_empty() => Ok(true),
            _ => Ok(false),
        }
    }

    fn decode_array<const N: usize>(name: &str, value: &str) -> Result<[u8; N]> {
        let decoded = decode_b64(name, value, N)?;
        decoded.try_into().map_err(|bytes: Vec<u8>| {
            malformed(format!(
                "{name} decoded to {} bytes; expected {N}",
                bytes.len()
            ))
        })
    }

    fn decode_b64(name: &str, value: &str, max_decoded: usize) -> Result<Vec<u8>> {
        let max_encoded = max_decoded.saturating_mul(4).saturating_add(2) / 3;
        if value.len() > max_encoded {
            return Err(malformed(format!("{name} exceeds its size limit")));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|error| malformed(format!("{name} is not base64url: {error}")))?;
        if decoded.len() > max_decoded || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(malformed(format!("{name} is not canonical base64url")));
        }
        Ok(decoded)
    }

    fn malformed(reason: impl Into<String>) -> Error {
        Error::Malformed {
            kind: "JWE General JSON",
            reason: reason.into(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::cipher::GroupCipher as _;
        use serde_json::{json, Value};

        fn key_pair(fill: u8) -> ([u8; 32], [u8; 32]) {
            let private = [fill; 32];
            let public = *MontgomeryPoint::mul_base_clamped(private).as_bytes();
            (private, public)
        }

        #[test]
        fn named_recipient_round_trips_and_stranger_is_not_entitled() {
            let (reader_private, reader_public) = key_pair(2);
            let (stranger_private, _) = key_pair(3);
            let sealer = JweCipher::new("partners", &[reader_public], &[]).unwrap();
            let opener = JweCipher::new("partners", &[], &[reader_private]).unwrap();
            let denied = JweCipher::new("partners", &[], &[stranger_private]).unwrap();
            let ciphertext = sealer.encrypt_with_aad(b"secret", b"marker").unwrap();

            assert_eq!(
                opener.decrypt_with_aad(&ciphertext, b"marker").unwrap(),
                b"secret"
            );
            assert!(matches!(
                denied.decrypt_with_aad(&ciphertext, b"marker"),
                Err(Error::NotEntitled { .. })
            ));
            assert!(matches!(
                opener.decrypt_with_aad(&ciphertext, b"wrong"),
                Err(Error::Cipher(message)) if message.contains("AAD")
            ));
        }

        #[test]
        fn ciphertext_is_rfc7516_general_json() {
            let (_, reader_public) = key_pair(5);
            let cipher = JweCipher::new("partners", &[reader_public], &[]).unwrap();
            let ciphertext = cipher.encrypt_with_aad(b"secret", b"marker").unwrap();
            let jwe: Value = serde_json::from_slice(&ciphertext).unwrap();
            let recipients = jwe["recipients"].as_array().unwrap();
            let recipient = &recipients[0];
            let protected_bytes = URL_SAFE_NO_PAD
                .decode(jwe["protected"].as_str().unwrap())
                .unwrap();
            let protected: Value = serde_json::from_slice(&protected_bytes).unwrap();

            assert_eq!(protected, json!({ "enc": "A256GCM" }));
            assert_eq!(recipient["header"]["alg"], "ECDH-ES+A256KW");
            assert_eq!(recipient["header"]["epk"]["kty"], "OKP");
            assert_eq!(recipient["header"]["epk"]["crv"], "X25519");
            assert!(recipient["encrypted_key"].is_string());
            assert_eq!(jwe["aad"], URL_SAFE_NO_PAD.encode(b"marker"));
            assert!(jwe.get("frame").is_none());
            assert!(jwe.get("body").is_none());
            assert!(jwe.get("recipient_wraps").is_none());
            assert!(recipient["header"].get("kid").is_none());
        }

        #[test]
        fn empty_aad_is_omitted() {
            let (private, public) = key_pair(6);
            let sealer = JweCipher::new("partners", &[public], &[]).unwrap();
            let reader = JweCipher::new("partners", &[], &[private]).unwrap();
            let ciphertext = sealer.encrypt(b"secret").unwrap();
            let jwe: Value = serde_json::from_slice(&ciphertext).unwrap();

            assert!(jwe.get("aad").is_none());
            assert_eq!(reader.decrypt(&ciphertext).unwrap(), b"secret");
        }

        #[test]
        fn null_aad_is_rejected_instead_of_treated_as_omitted() {
            let (private, public) = key_pair(7);
            let sealer = JweCipher::new("partners", &[public], &[]).unwrap();
            let reader = JweCipher::new("partners", &[], &[private]).unwrap();
            let ciphertext = sealer.encrypt(b"secret").unwrap();
            let mut jwe: Value = serde_json::from_slice(&ciphertext).unwrap();
            jwe["aad"] = Value::Null;

            assert!(matches!(
                reader.decrypt(&serde_json::to_vec(&jwe).unwrap()),
                Err(Error::Malformed { .. })
            ));
        }

        #[test]
        fn tampered_content_tag_is_an_authentication_failure() {
            let (private, public) = key_pair(8);
            let sealer = JweCipher::new("partners", &[public], &[]).unwrap();
            let reader = JweCipher::new("partners", &[], &[private]).unwrap();
            let ciphertext = sealer.encrypt(b"secret").unwrap();
            let mut jwe: Value = serde_json::from_slice(&ciphertext).unwrap();
            let mut tag = URL_SAFE_NO_PAD
                .decode(jwe["tag"].as_str().unwrap())
                .unwrap();
            tag[0] ^= 1;
            jwe["tag"] = Value::String(URL_SAFE_NO_PAD.encode(tag));

            assert!(matches!(
                reader.decrypt(&serde_json::to_vec(&jwe).unwrap()),
                Err(Error::Cipher(message)) if message.contains("authentication")
            ));
        }

        #[test]
        fn single_recipient_accepts_protected_epk() {
            let mut jwe = sealed_jwe(1);
            let epk = take_recipient_member(&mut jwe, 0, "epk");
            set_protected_header(&mut jwe, json!({"enc": ENC, "epk": epk}));

            assert!(parse_value(&jwe).is_ok());
        }

        #[test]
        fn parser_preserves_the_transmitted_protected_segment() {
            let mut jwe = sealed_jwe(1);
            let epk = take_recipient_member(&mut jwe, 0, "epk");
            set_protected_header(&mut jwe, json!({"epk": epk, "enc": ENC}));
            let segment = jwe["protected"].as_str().unwrap().to_owned();

            assert_eq!(parse_value(&jwe).unwrap().protected, segment);
        }

        #[test]
        fn shared_unprotected_alg_is_accepted() {
            let mut jwe = sealed_jwe(1);
            let alg = take_recipient_member(&mut jwe, 0, "alg");
            jwe["unprotected"] = json!({"alg": alg});

            assert!(parse_value(&jwe).is_ok());
        }

        #[test]
        fn duplicate_header_names_across_components_are_rejected() {
            let base = sealed_jwe(1);
            let mut alg = base.clone();
            set_protected_header(&mut alg, json!({"enc": ENC, "alg": ALG}));
            let mut enc = base.clone();
            enc["unprotected"] = json!({"enc": ENC});
            let mut epk = base;
            let recipient_epk = epk["recipients"][0]["header"]["epk"].clone();
            set_protected_header(&mut epk, json!({"enc": ENC, "epk": recipient_epk}));

            for invalid in [alg, enc, epk] {
                assert_parse_malformed(&invalid);
            }
        }

        #[test]
        fn missing_alg_or_epk_is_rejected() {
            for member in ["alg", "epk"] {
                let mut jwe = sealed_jwe(1);
                take_recipient_member(&mut jwe, 0, member);
                assert_parse_malformed(&jwe);
            }
        }

        #[test]
        fn enc_outside_or_duplicated_beyond_protected_is_rejected() {
            let mut outside = sealed_jwe(1);
            set_protected_header(&mut outside, json!({}));
            outside["unprotected"] = json!({"enc": ENC});
            let mut duplicate = sealed_jwe(1);
            duplicate["recipients"][0]["header"]["enc"] = json!(ENC);

            assert_parse_malformed(&outside);
            assert_parse_malformed(&duplicate);
        }

        #[test]
        fn explicit_null_header_objects_and_members_are_rejected() {
            let mut shared = sealed_jwe(1);
            shared["unprotected"] = Value::Null;
            let mut recipient = sealed_jwe(1);
            recipient["recipients"][0]["header"] = Value::Null;
            let mut member = sealed_jwe(1);
            member["unprotected"] = json!({"alg": null});

            for invalid in [shared, recipient, member] {
                assert_parse_malformed(&invalid);
            }
        }

        #[test]
        fn unsupported_header_members_are_rejected() {
            let mut protected = sealed_jwe(1);
            set_protected_header(&mut protected, json!({"enc": ENC, "zip": "DEF"}));
            let mut shared = sealed_jwe(1);
            shared["unprotected"] = json!({"kid": "reader"});
            let mut recipient = sealed_jwe(1);
            recipient["recipients"][0]["header"]["kid"] = json!("reader");

            for invalid in [protected, shared, recipient] {
                assert_parse_malformed(&invalid);
            }
        }

        #[test]
        fn multi_recipient_rejects_protected_or_shared_epk() {
            for location in ["protected", "unprotected"] {
                let mut jwe = sealed_jwe(2);
                let epk = take_recipient_member(&mut jwe, 0, "epk");
                take_recipient_member(&mut jwe, 1, "epk");
                if location == "protected" {
                    set_protected_header(&mut jwe, json!({"enc": ENC, "epk": epk}));
                } else {
                    jwe["unprotected"] = json!({"epk": epk});
                }
                assert_parse_malformed(&jwe);
            }
        }

        #[test]
        fn strict_profile_rejects_duplicate_unsupported_and_excess_input() {
            let (_, public) = key_pair(9);
            let cipher = JweCipher::new("partners", &[public], &[]).unwrap();
            let ciphertext = cipher.encrypt(b"secret").unwrap();
            let mut jwe: Value = serde_json::from_slice(&ciphertext).unwrap();

            let iv_member = format!("\"iv\":\"{}\"", jwe["iv"].as_str().unwrap());
            let duplicate_iv = String::from_utf8(ciphertext.clone()).unwrap().replacen(
                &iv_member,
                &format!("{iv_member},{iv_member}"),
                1,
            );
            assert!(matches!(
                cipher.decrypt(duplicate_iv.as_bytes()),
                Err(Error::Malformed { .. })
            ));

            jwe["protected"] = Value::String(
                URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&json!({"enc": ENC, "zip": "DEF"})).unwrap()),
            );
            assert_malformed(&cipher, &jwe);

            let recipient = jwe["recipients"][0].clone();
            jwe["recipients"] = Value::Array(vec![recipient; MAX_RECIPIENTS + 1]);
            assert_malformed(&cipher, &jwe);
        }

        fn assert_malformed(cipher: &JweCipher, jwe: &Value) {
            assert!(matches!(
                cipher.decrypt(&serde_json::to_vec(jwe).unwrap()),
                Err(Error::Malformed { .. })
            ));
        }

        fn sealed_jwe(recipient_count: usize) -> Value {
            let public_keys = (0..recipient_count)
                .map(|index| key_pair(20 + index as u8).1)
                .collect::<Vec<_>>();
            let cipher = JweCipher::new("partners", &public_keys, &[]).unwrap();
            serde_json::from_slice(&cipher.encrypt(b"secret").unwrap()).unwrap()
        }

        fn set_protected_header(jwe: &mut Value, header: Value) {
            let bytes = serde_json::to_vec(&header).unwrap();
            jwe["protected"] = Value::String(URL_SAFE_NO_PAD.encode(bytes));
        }

        fn take_recipient_member(jwe: &mut Value, index: usize, name: &str) -> Value {
            jwe["recipients"][index]["header"]
                .as_object_mut()
                .unwrap()
                .remove(name)
                .unwrap()
        }

        fn parse_value(jwe: &Value) -> Result<ParsedJwe> {
            parse_jwe(&serde_json::to_vec(jwe).unwrap())
        }

        fn assert_parse_malformed(jwe: &Value) {
            assert!(matches!(parse_value(jwe), Err(Error::Malformed { .. })));
        }
    }
}

#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
pub use native::JweCipher;

#[cfg(all(
    feature = "fs",
    any(not(feature = "native-jwe"), target_arch = "wasm32")
))]
mod unavailable {
    use crate::cipher::GroupCipher;
    use crate::{Error, Result};

    /// Placeholder used where native JWE support is absent.
    pub struct JweCipher;

    impl JweCipher {
        /// Return the native-JWE unavailable error for this build.
        pub fn new(
            _group: impl Into<String>,
            _recipient_public_keys: &[[u8; 32]],
            _reader_private_keys: &[[u8; 32]],
        ) -> Result<Self> {
            Err(unavailable())
        }

        pub(crate) fn new_with_owned_reader_keys(
            _group: impl Into<String>,
            _recipient_public_keys: &[[u8; 32]],
            _reader_private_keys: Vec<zeroize::Zeroizing<[u8; 32]>>,
        ) -> Result<Self> {
            Err(unavailable())
        }
    }

    impl GroupCipher for JweCipher {
        fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
            Err(unavailable())
        }

        fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
            Err(unavailable())
        }

        fn kind(&self) -> &'static str {
            "jwe"
        }
    }

    fn unavailable() -> Error {
        Error::NotImplemented("native JWE is unavailable in this build")
    }
}

#[cfg(all(
    feature = "fs",
    any(not(feature = "native-jwe"), target_arch = "wasm32")
))]
pub use unavailable::JweCipher;
