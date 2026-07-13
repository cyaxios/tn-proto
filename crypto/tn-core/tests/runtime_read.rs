#![cfg(feature = "fs")]

mod common;

use common::setup_minimal_btn_ceremony;

#[cfg(feature = "hibe")]
use rand_core::OsRng;
#[cfg(feature = "hibe")]
use serde_json::{json, Map, Value};
#[cfg(feature = "hibe")]
use std::path::Path;

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
            "ciphertext": "bm90LXZhbGlkLXdpcmU=",
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
fn foreign_writer_detection_skips_a_malformed_prefix() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    std::fs::write(cer.keystore.join("default.jwe.mykey"), [0x44u8; 32]).unwrap();
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let foreign_log = td.path().join("foreign-jwe-prefixed.ndjson");
    write_minimal_foreign_log(&foreign_log, "did:key:zForeignJwe");
    let valid = std::fs::read_to_string(&foreign_log).unwrap();
    std::fs::write(&foreign_log, format!("not-json\n{valid}")).unwrap();

    let error = match rt.read_from(&foreign_log) {
        Ok(_) => panic!("the parseable foreign row must still select JWE material"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("cipher=jwe"), "{error}");
}

#[test]
fn unrelated_jwe_material_does_not_block_a_btn_foreign_read() {
    let writer_dir = tempfile::tempdir().unwrap();
    let writer_ceremony = setup_minimal_btn_ceremony(writer_dir.path());
    let writer = tn_core::Runtime::init(&writer_ceremony.yaml_path).unwrap();
    writer
        .info(
            "foreign.btn",
            serde_json::Map::from_iter([("secret".into(), serde_json::json!("s3"))]),
        )
        .unwrap();

    let reader_dir = tempfile::tempdir().unwrap();
    let reader_ceremony = setup_minimal_btn_ceremony(reader_dir.path());
    std::fs::copy(
        writer_ceremony.keystore.join("default.btn.mykit"),
        reader_ceremony.keystore.join("default.btn.mykit"),
    )
    .unwrap();
    std::fs::write(
        reader_ceremony.keystore.join("unrelated.jwe.mykey"),
        [0x44u8; 32],
    )
    .unwrap();
    let reader = tn_core::Runtime::init(&reader_ceremony.yaml_path).unwrap();

    let entries = reader.read_from(writer.log_path()).unwrap();
    let row = entries
        .iter()
        .find(|entry| entry.envelope["event_type"] == "foreign.btn")
        .expect("foreign BTN row");
    assert_eq!(row.plaintext_per_group["default"]["secret"], "s3");
}

#[test]
fn unrelated_broken_hibe_material_does_not_block_a_btn_foreign_read() {
    let writer_dir = tempfile::tempdir().unwrap();
    let writer_ceremony = setup_minimal_btn_ceremony(writer_dir.path());
    let writer = tn_core::Runtime::init(&writer_ceremony.yaml_path).unwrap();
    writer
        .info(
            "foreign.btn",
            serde_json::Map::from_iter([("secret".into(), serde_json::json!("s3"))]),
        )
        .unwrap();

    let reader_dir = tempfile::tempdir().unwrap();
    let reader_ceremony = setup_minimal_btn_ceremony(reader_dir.path());
    std::fs::copy(
        writer_ceremony.keystore.join("default.btn.mykit"),
        reader_ceremony.keystore.join("default.btn.mykit"),
    )
    .unwrap();
    std::fs::write(
        reader_ceremony.keystore.join("unrelated.hibe.sk"),
        b"broken unrelated material",
    )
    .unwrap();
    let reader = tn_core::Runtime::init(&reader_ceremony.yaml_path).unwrap();

    let entries = reader.read_from(writer.log_path()).unwrap();
    let row = entries
        .iter()
        .find(|entry| entry.envelope["event_type"] == "foreign.btn")
        .expect("foreign BTN row");
    assert_eq!(row.plaintext_per_group["default"]["secret"], "s3");
}

#[test]
fn read_from_rejects_incomplete_hibe_material() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    std::fs::write(cer.keystore.join("default.hibe.sk"), b"sk-bytes").unwrap();
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let foreign_log = td.path().join("foreign-hibe.ndjson");
    write_minimal_foreign_log(&foreign_log, "did:key:zForeignHibe");

    let err = match rt.read_from(&foreign_log) {
        Ok(_) => panic!("incomplete HIBE material must fail before reading"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("hibe group default"), "{msg}");
    assert!(msg.contains("default.hibe.mpk"), "{msg}");
}

#[cfg(feature = "hibe")]
#[test]
fn btn_runtime_reads_aad_bound_foreign_hibe_log() {
    let writer_dir = tempfile::tempdir().unwrap();
    let (writer, public, master, id_path) = setup_hibe_writer(writer_dir.path());
    emit_hibe_row_with_aad(&writer);

    let reader_dir = tempfile::tempdir().unwrap();
    let reader_ceremony = setup_minimal_btn_ceremony(reader_dir.path());
    install_hibe_reader(&reader_ceremony.keystore, &public, &master, id_path);
    let reader = tn_core::Runtime::init(&reader_ceremony.yaml_path).unwrap();

    let entries = reader.read_from(writer.log_path()).unwrap();
    let row = entries
        .iter()
        .find(|entry| entry.envelope["event_type"] == "foreign.hibe")
        .expect("foreign HIBE row");
    assert_eq!(row.plaintext_per_group["default"]["secret"], "s3");
}

#[cfg(feature = "hibe")]
#[test]
fn direct_recipient_read_uses_the_shared_hibe_candidate_path() {
    let writer_dir = tempfile::tempdir().unwrap();
    let (writer, public, master, id_path) = setup_hibe_writer(writer_dir.path());
    emit_hibe_row_with_aad(&writer);

    let reader_dir = tempfile::tempdir().unwrap();
    let reader_ceremony = setup_minimal_btn_ceremony(reader_dir.path());
    install_hibe_reader(&reader_ceremony.keystore, &public, &master, id_path);

    let entries = tn_core::read_as_recipient::read_as_recipient(
        writer.log_path(),
        &reader_ceremony.keystore,
        tn_core::read_as_recipient::ReadAsRecipientOptions {
            group: "default".into(),
            verify_signatures: true,
        },
    )
    .unwrap();
    let row = entries
        .iter()
        .find(|entry| entry.envelope["event_type"] == "foreign.hibe")
        .expect("foreign HIBE row");
    assert_eq!(row.plaintext["default"]["secret"], "s3");
    assert!(row.valid.signature);
}

#[cfg(feature = "hibe")]
fn setup_hibe_writer(
    root: &Path,
) -> (
    tn_core::Runtime,
    tn_hibe::PublicParams,
    tn_hibe::MasterKey,
    &'static str,
) {
    let keystore = root.join(".tn/keys");
    std::fs::create_dir_all(&keystore).unwrap();
    let device = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), device.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();
    let (public, master) = tn_hibe::setup(4, OsRng).unwrap();
    let id_path = "acme/logs";
    std::fs::write(keystore.join("default.hibe.mpk"), public.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.hibe.idpath"), id_path).unwrap();
    std::fs::write(keystore.join("default.hibe.msk"), master.to_bytes()).unwrap();
    let yaml_path = root.join("tn.yaml");
    write_hibe_yaml(&yaml_path, device.did());
    let runtime = tn_core::Runtime::init(&yaml_path).unwrap();
    (runtime, public, master, id_path)
}

#[cfg(feature = "hibe")]
fn write_hibe_yaml(path: &Path, did: &str) {
    let yaml = format!(
        "ceremony: {{id: cer_hibe_read, mode: local, cipher: hibe, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default: {{policy: private, cipher: hibe, index_epoch: 0}}\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n"
    );
    std::fs::write(path, yaml).unwrap();
}

#[cfg(feature = "hibe")]
fn emit_hibe_row_with_aad(writer: &tn_core::Runtime) {
    let mut fields = Map::new();
    fields.insert("secret".into(), Value::String("s3".into()));
    let mut aad = Map::new();
    aad.insert("case".into(), json!("A-17"));
    writer
        .emit_with_aad_returning_line("info", "foreign.hibe", fields, None, None, None, &aad)
        .unwrap();
}

#[cfg(feature = "hibe")]
fn install_hibe_reader(
    keystore: &Path,
    public: &tn_hibe::PublicParams,
    master: &tn_hibe::MasterKey,
    id_path: &str,
) {
    let identity = tn_hibe::Identity::from_str_path(id_path);
    let secret = tn_hibe::keygen(public, master, &identity, OsRng).unwrap();
    std::fs::write(keystore.join("default.hibe.mpk"), public.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.hibe.idpath"), id_path).unwrap();
    std::fs::write(keystore.join("default.hibe.sk"), secret.to_bytes()).unwrap();
}
