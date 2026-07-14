//! Byte-oriented JWE primitive facade tests.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use tn_proto::jwe;
use tn_proto::Error;

#[test]
fn keygen_derives_public_x25519_material() -> tn_proto::Result<()> {
    let keys = jwe::keygen()?;

    assert_eq!(
        keys.public_key,
        tn_core::trusted_enrollment::x25519_public_key(&keys.private_key)
    );
    Ok(())
}

#[test]
fn one_recipient_roundtrip_emits_general_json_jwe() -> tn_proto::Result<()> {
    let keys = jwe::keygen()?;
    let ciphertext = jwe::encrypt(b"one recipient", [&keys.public_key])?;
    let frame: Value = serde_json::from_slice(&ciphertext)?;

    assert_eq!(frame["recipients"].as_array().map(Vec::len), Some(1));
    assert_standard_profile(&frame);
    assert_eq!(
        jwe::subscribe([keys.private_key])?.decrypt(&ciphertext)?,
        b"one recipient"
    );
    Ok(())
}

#[test]
fn each_recipient_can_open_multi_recipient_ciphertext() -> tn_proto::Result<()> {
    let first = jwe::keygen()?;
    let second = jwe::keygen()?;
    let ciphertext = jwe::encrypt(
        b"shared content key",
        [&first.public_key, &second.public_key],
    )?;

    assert_eq!(
        jwe::subscribe([first.private_key])?.decrypt(&ciphertext)?,
        b"shared content key"
    );
    assert_eq!(
        jwe::subscribe([second.private_key])?.decrypt(&ciphertext)?,
        b"shared content key"
    );
    Ok(())
}

#[test]
fn aad_must_match_exactly() -> tn_proto::Result<()> {
    let keys = jwe::keygen()?;
    let ciphertext =
        jwe::encrypt_with_aad(b"bound plaintext", [&keys.public_key], b"expected aad")?;
    let reader = jwe::subscribe([keys.private_key])?;

    assert_eq!(
        reader.decrypt_with_aad(&ciphertext, b"expected aad")?,
        b"bound plaintext"
    );
    assert!(matches!(
        reader
            .decrypt_with_aad(&ciphertext, b"changed aad")
            .expect_err("changed AAD must fail authentication"),
        Error::AuthenticationFailed(_)
    ));
    assert!(matches!(
        reader
            .decrypt(&ciphertext)
            .expect_err("missing AAD must fail authentication"),
        Error::AuthenticationFailed(_)
    ));
    Ok(())
}

#[test]
fn subscriber_tries_later_keys_and_reports_not_entitled() -> tn_proto::Result<()> {
    let recipient = jwe::keygen()?;
    let stranger = jwe::keygen()?;
    let ciphertext = jwe::encrypt(b"recipient only", [&recipient.public_key])?;

    assert_eq!(
        jwe::subscribe([stranger.private_key, recipient.private_key])?.decrypt(&ciphertext)?,
        b"recipient only"
    );
    assert!(matches!(
        jwe::subscribe([stranger.private_key])?
            .decrypt(&ciphertext)
            .expect_err("a wrong key must not open the JWE"),
        Error::NotEntitled(_)
    ));
    Ok(())
}

#[test]
fn malformed_or_unsupported_recipient_fails_closed() -> tn_proto::Result<()> {
    let first = jwe::keygen()?;
    let second = jwe::keygen()?;
    let ciphertext = jwe::encrypt(
        b"parse every recipient",
        [&first.public_key, &second.public_key],
    )?;
    let frame: Value = serde_json::from_slice(&ciphertext)?;
    let mut malformed = frame.clone();
    malformed["recipients"][0]
        .as_object_mut()
        .expect("recipient object")
        .remove("encrypted_key");
    let mut unsupported = frame;
    unsupported["recipients"][0]["header"]["kid"] = json!("must-not-be-skipped");
    let reader = jwe::subscribe([second.private_key])?;

    for invalid in [malformed, unsupported] {
        assert!(matches!(
            reader
                .decrypt(&serde_json::to_vec(&invalid)?)
                .expect_err("every malformed recipient must fail the whole JWE"),
            Error::Malformed(_)
        ));
    }
    Ok(())
}

#[test]
fn facade_maps_malformed_authentication_and_limit_errors() -> tn_proto::Result<()> {
    let keys = jwe::keygen()?;
    let reader = jwe::subscribe([keys.private_key])?;
    assert!(matches!(
        reader
            .decrypt(b"not JSON")
            .expect_err("invalid JSON must be malformed"),
        Error::Malformed(_)
    ));
    assert!(matches!(
        jwe::encrypt(b"invalid key", [[0_u8; 32]])
            .expect_err("an all-zero X25519 public key must be malformed"),
        Error::Malformed(_)
    ));

    let ciphertext = jwe::encrypt(b"authenticate me", [&keys.public_key])?;
    let mut frame: Value = serde_json::from_slice(&ciphertext)?;
    let tag = frame["tag"].as_str().expect("tag string");
    let replacement = if tag.starts_with('A') { "B" } else { "A" };
    frame["tag"] = json!(format!("{replacement}{}", &tag[1..]));
    assert!(matches!(
        reader
            .decrypt(&serde_json::to_vec(&frame)?)
            .expect_err("a changed tag must fail authentication"),
        Error::AuthenticationFailed(_)
    ));

    let too_many = vec![keys.public_key; 1_025];
    assert!(matches!(
        jwe::encrypt(b"too many", too_many).expect_err("recipient limit must be stable"),
        Error::LimitExceeded(_)
    ));
    let too_many = vec![keys.private_key; 1_025];
    let error = match jwe::subscribe(too_many) {
        Ok(_) => panic!("reader-key limit must be stable"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::LimitExceeded(_)));

    let too_much_aad = vec![0_u8; 64 * 1_024 + 1];
    assert!(matches!(
        jwe::encrypt_with_aad(b"limit", [&keys.public_key], &too_much_aad)
            .expect_err("AAD limit must be stable"),
        Error::LimitExceeded(_)
    ));
    assert!(matches!(
        reader
            .decrypt_with_aad(&ciphertext, &too_much_aad)
            .expect_err("decrypt AAD limit must be stable"),
        Error::LimitExceeded(_)
    ));

    let too_much_plaintext = vec![0_u8; 64 * 1_024 * 1_024 + 1];
    assert!(matches!(
        jwe::encrypt(&too_much_plaintext, [&keys.public_key])
            .expect_err("plaintext limit must be stable"),
        Error::LimitExceeded(_)
    ));
    Ok(())
}

#[test]
fn zero_recipients_are_rejected() {
    let error = jwe::encrypt(b"nobody", std::iter::empty::<[u8; 32]>())
        .expect_err("JWE encryption requires a recipient");

    assert!(matches!(error, Error::InvalidArgument(_)));
}

#[test]
fn zero_private_keys_are_rejected() {
    let error = match jwe::subscribe(std::iter::empty::<[u8; 32]>()) {
        Ok(_) => panic!("JWE subscription requires a private key"),
        Err(error) => error,
    };

    assert!(matches!(error, Error::InvalidArgument(_)));
}

#[test]
fn key_iterators_are_bounded() {
    let error = jwe::encrypt(b"bounded", std::iter::repeat([7_u8; 32]))
        .expect_err("an unbounded recipient iterator must stop at the key limit");
    assert!(matches!(error, Error::LimitExceeded(_)));

    let error = match jwe::subscribe(std::iter::repeat([9_u8; 32])) {
        Ok(_) => panic!("an unbounded private-key iterator must stop at the key limit"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::LimitExceeded(_)));
}

fn assert_standard_profile(frame: &Value) {
    let protected = frame["protected"]
        .as_str()
        .expect("JWE protected header is a base64url string");
    let protected: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(protected)
            .expect("protected header is base64url"),
    )
    .expect("protected header is JSON");
    let recipient = &frame["recipients"][0];

    assert_eq!(protected, json!({ "enc": "A256GCM" }));
    assert_eq!(recipient["header"]["alg"], "ECDH-ES+A256KW");
    assert_eq!(recipient["header"]["epk"]["kty"], "OKP");
    assert_eq!(recipient["header"]["epk"]["crv"], "X25519");
}
