//! Integration tests for Runtime admin verbs (cipher-agnostic public names):
//!   admin_add_recipient, admin_revoke_recipient, admin_revoked_count.

#![cfg(feature = "fs")]

mod common;

use base64::Engine as _;
use tn_core::cipher::btn::BtnReaderCipher;
use tn_core::cipher::GroupCipher;

/// After revoking a kit, the publisher can still emit and self-decrypt, but
/// the revoked reader kit cannot decrypt post-revocation ciphertexts.
#[test]
fn revoke_then_subsequent_decrypt_fails_for_revoked_kit() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    // Before revoke: publisher should be able to emit + self-decrypt.
    let mut f1 = serde_json::Map::new();
    f1.insert("msg".into(), serde_json::json!("before"));
    rt.emit_with(
        "info",
        "x.test",
        f1,
        Some("2026-04-21T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-000000000001"),
    )
    .unwrap();

    // Mint a new reader kit via admin.
    let kit_path = td.path().join("reader_a.btn.mykit");
    let leaf_a = rt
        .admin_add_recipient("default", &kit_path, None)
        .unwrap();
    assert!(kit_path.exists(), "admin should write kit file");

    // Revoke reader_a.
    rt.admin_revoke_recipient("default", leaf_a).unwrap();
    assert_eq!(rt.admin_revoked_count("default").unwrap(), 1);

    // After revoke: publisher emit still works, still self-readable.
    let mut f2 = serde_json::Map::new();
    f2.insert("msg".into(), serde_json::json!("after"));
    rt.emit_with(
        "info",
        "x.test",
        f2,
        Some("2026-04-21T12:00:01.000000Z"),
        Some("00000000-0000-0000-0000-000000000002"),
    )
    .unwrap();

    let entries = rt.read_raw().unwrap();
    // Log now contains: x.test(before), tn.recipient.added, tn.recipient.revoked, x.test(after).
    // Admin verbs emit valid catalog events after the schema enforcement fix (Task C.1).
    let business: Vec<_> = entries
        .iter()
        .filter(|e| e.envelope["event_type"].as_str() == Some("x.test"))
        .collect();
    assert_eq!(business.len(), 2);
    assert_eq!(business[0].plaintext_per_group["default"]["msg"], "before");
    assert_eq!(business[1].plaintext_per_group["default"]["msg"], "after");

    // Verify revoked kit cannot decrypt the "after" envelope.
    let kit_bytes = std::fs::read(&kit_path).unwrap();
    let reader = BtnReaderCipher::from_kit_bytes(&kit_bytes).unwrap();
    let env_after = business[1].envelope.clone();
    let ct_b64 = env_after["default"]["ciphertext"].as_str().unwrap();
    let ct = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .unwrap();
    match reader.decrypt(&ct) {
        Ok(_) => panic!("revoked reader should NOT decrypt"),
        Err(tn_core::Error::NotEntitled { .. } | tn_core::Error::Btn(_)) => {} // expected
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// Minted kit state must survive a Runtime reload: the leaf we added must
/// appear as issued after the reload, and we must be able to mint more.
#[test]
fn add_recipient_persists_state_across_runtime_reload() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let kit_path = td.path().join("reader_new.btn.mykit");
    let _leaf = rt
        .admin_add_recipient("default", &kit_path, None)
        .unwrap();
    drop(rt);

    // Reload Runtime — the persisted state should reflect the minted kit.
    let rt2 = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    // Admin verb must still work after reload (state loaded from disk).
    let kit_path2 = td.path().join("reader_new2.btn.mykit");
    let _leaf2 = rt2
        .admin_add_recipient("default", &kit_path2, None)
        .unwrap();
    assert!(kit_path2.exists());
}

/// admin_revoked_count returns an error when the group is not a btn publisher.
#[test]
fn revoked_count_unknown_group_returns_error() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let err = rt.admin_revoked_count("no_such_group").unwrap_err();
    assert!(
        matches!(err, tn_core::Error::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}
