#![cfg(feature = "fs")]

mod common;

use common::setup_minimal_btn_ceremony;

#[test]
fn roundtrip_emit_then_read() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    let mut f1 = serde_json::Map::new();
    f1.insert("amount".into(), serde_json::json!(100));
    f1.insert("note".into(), serde_json::json!("first"));
    rt.emit_with(
        "info",
        "order.created",
        f1,
        Some("2026-04-21T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-00000000000a"),
    )
    .unwrap();

    let mut f2 = serde_json::Map::new();
    f2.insert("amount".into(), serde_json::json!(200));
    f2.insert("currency".into(), serde_json::json!("USD"));
    rt.emit_with(
        "info",
        "order.created",
        f2,
        Some("2026-04-21T12:00:01.000000Z"),
        Some("00000000-0000-0000-0000-00000000000b"),
    )
    .unwrap();

    let entries = rt.read_raw().unwrap();
    // entry 0 = tn.ceremony.init (emitted on fresh creation), entries 1-2 = business events.
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].envelope["event_type"], "tn.ceremony.init");

    let pt1 = &entries[1].plaintext_per_group["default"];
    assert_eq!(pt1["amount"], 100);
    assert_eq!(pt1["note"], "first");

    let pt2 = &entries[2].plaintext_per_group["default"];
    assert_eq!(pt2["amount"], 200);
    assert_eq!(pt2["currency"], "USD");
}

#[test]
fn read_from_missing_file_returns_empty() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let bogus = td.path().join("does_not_exist.ndjson");
    let entries = rt.read_from(&bogus).unwrap();
    assert!(entries.is_empty());
}

fn write_minimal_foreign_log(path: &std::path::Path, did: &str) {
    let row = serde_json::json!({
        "device_identity": did,
        "event_type": "x.foreign",
        "default": {
            "ciphertext": "not-valid-base64",
            "field_hashes": {}
        }
    });
    std::fs::write(path, format!("{row}\n")).unwrap();
}

#[test]
fn read_from_foreign_log_with_jwe_material_fails_explicitly() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    std::fs::write(cer.keystore.join("default.jwe.mykey"), [0x44u8; 32]).unwrap();
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let foreign_log = td.path().join("foreign-jwe.ndjson");
    write_minimal_foreign_log(&foreign_log, "did:key:zForeignJwe");

    let err = match rt.read_from(&foreign_log) {
        Ok(_) => panic!("read_from should reject foreign JWE material explicitly"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("read_from"), "{msg}");
    assert!(msg.contains("cipher=jwe"), "{msg}");
}

#[test]
fn read_from_with_validity_foreign_log_with_hibe_material_fails_explicitly() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    std::fs::write(cer.keystore.join("default.hibe.sk"), b"sk-bytes").unwrap();
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let foreign_log = td.path().join("foreign-hibe.ndjson");
    write_minimal_foreign_log(&foreign_log, "did:key:zForeignHibe");

    let err = match rt.read_from_with_validity(&foreign_log) {
        Ok(_) => panic!("read_from_with_validity should reject foreign HIBE material explicitly"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("read_from_with_validity"), "{msg}");
    assert!(msg.contains("cipher=hibe"), "{msg}");
}
