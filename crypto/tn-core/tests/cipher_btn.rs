//! Integration tests for the btn cipher adapter (BtnPublisherCipher + BtnReaderCipher).

use tn_core::cipher::{
    btn::{BtnPublisherCipher, BtnReaderCipher},
    GroupCipher,
};

// ---------------------------------------------------------------------------
// Rust-only round-trip
// ---------------------------------------------------------------------------

#[test]
fn btn_roundtrip_rust_only() {
    // Mint a publisher, attach its own reader kit so both halves are exercised.
    let mut state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [1u8; 32]).unwrap();
    let kit = state.mint().unwrap();
    let kit_bytes = kit.to_bytes();

    let pub_c = BtnPublisherCipher::from_state(state)
        .with_reader_kit(&kit_bytes)
        .unwrap();
    let reader = BtnReaderCipher::from_kit_bytes(&kit_bytes).unwrap();

    let pt = b"hello btn";

    // Publisher encrypts; reader decrypts.
    let ct = pub_c.encrypt(pt).unwrap();
    assert_eq!(reader.decrypt(&ct).unwrap(), pt);

    // Publisher with attached reader also decrypts.
    assert_eq!(pub_c.decrypt(&ct).unwrap(), pt);
}

#[test]
fn btn_publisher_without_reader_kit_cannot_decrypt() {
    let state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [2u8; 32]).unwrap();
    let pub_c = BtnPublisherCipher::from_state(state);
    // Encrypt something just to have a valid ciphertext.
    let ct = pub_c.encrypt(b"x").unwrap();
    let err = pub_c.decrypt(&ct).unwrap_err();
    // Should return NotEntitled since no reader kit is attached.
    assert!(
        format!("{err}").to_lowercase().contains("entitled")
            || format!("{err}").to_lowercase().contains("not entitled"),
        "unexpected error: {err}"
    );
}

#[test]
fn btn_reader_cannot_encrypt() {
    let mut state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [3u8; 32]).unwrap();
    let kit = state.mint().unwrap();
    let reader = BtnReaderCipher::from_kit_bytes(&kit.to_bytes()).unwrap();
    let err = reader.encrypt(b"nope").unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("publisher"),
        "unexpected error: {err}"
    );
}

#[test]
fn btn_state_round_trip_via_bytes() {
    // Serialize publisher state → deserialize → still encrypts → reader decrypts.
    let mut state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [4u8; 32]).unwrap();
    let kit = state.mint().unwrap();
    let kit_bytes = kit.to_bytes();

    let state_bytes = state.to_bytes();
    let pub_c = BtnPublisherCipher::from_state_bytes(&state_bytes)
        .unwrap()
        .with_reader_kit(&kit_bytes)
        .unwrap();

    let ct = pub_c.encrypt(b"after reload").unwrap();
    let reader = BtnReaderCipher::from_kit_bytes(&kit_bytes).unwrap();
    assert_eq!(reader.decrypt(&ct).unwrap(), b"after reload");
}

#[test]
fn btn_kind_is_btn() {
    let state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [5u8; 32]).unwrap();
    let pub_c = BtnPublisherCipher::from_state(state);
    assert_eq!(pub_c.kind(), "btn");
}

// ---------------------------------------------------------------------------
// Golden fixture: decrypt Python-produced ciphertext with Python-produced kit
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct BtnFixture {
    publisher_state_bytes_hex: String,
    reader_kit_bytes_hex: String,
    plaintext_hex: String,
    ciphertext_hex: String,
}

#[test]
fn btn_decrypts_python_golden() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/btn_vectors.json"
    );
    let f: BtnFixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();

    let kit_bytes = hex::decode(&f.reader_kit_bytes_hex).unwrap();
    let ct_bytes = hex::decode(&f.ciphertext_hex).unwrap();
    let expected_pt = hex::decode(&f.plaintext_hex).unwrap();

    // Verify reader-side decrypt.
    let reader = BtnReaderCipher::from_kit_bytes(&kit_bytes).unwrap();
    let got = reader.decrypt(&ct_bytes).unwrap();
    assert_eq!(
        got, expected_pt,
        "Rust BtnReaderCipher failed to decrypt Python-produced btn ciphertext"
    );

    // Also verify via publisher-with-reader-kit path.
    let state_bytes = hex::decode(&f.publisher_state_bytes_hex).unwrap();
    let pub_c = BtnPublisherCipher::from_state_bytes(&state_bytes)
        .unwrap()
        .with_reader_kit(&kit_bytes)
        .unwrap();
    let got2 = pub_c.decrypt(&ct_bytes).unwrap();
    assert_eq!(
        got2, expected_pt,
        "Rust BtnPublisherCipher (with reader kit) failed to decrypt Python-produced ciphertext"
    );
}
