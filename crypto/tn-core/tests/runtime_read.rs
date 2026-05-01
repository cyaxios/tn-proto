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
