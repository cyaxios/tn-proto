//! Configured-runtime coverage for the native TN-wrapped JWE cipher.

#![cfg(feature = "fs")]

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use tn_core::read_as_recipient::{read_as_recipient, ReadAsRecipientOptions};
use tn_core::runtime::unseal_as_recipient;
use tn_core::{DeviceKey, Runtime, SealOptions, UnsealOptions};

struct JweCeremony {
    yaml_path: PathBuf,
    keystore: PathBuf,
}

fn setup_jwe_ceremony(root: &Path, device: &DeviceKey, recipient_dids: &[String]) -> JweCeremony {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();
    std::fs::write(keystore.join("local.private"), device.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11_u8; 32]).unwrap();
    let did = device.did();
    let recipient_rows = recipient_dids
        .iter()
        .map(|recipient| format!("     - {{recipient_identity: \"{recipient}\"}}\n"))
        .collect::<String>();
    let yaml = format!(
        "ceremony: {{id: cer_jwe, mode: local, cipher: jwe, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   recipients:\n\
         {recipient_rows}\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n"
    );
    let yaml_path = root.join("tn.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    JweCeremony {
        yaml_path,
        keystore,
    }
}

fn private_fields() -> Map<String, Value> {
    Map::from_iter([
        ("amount".to_string(), json!(42)),
        ("note".to_string(), json!("wrapped once per reader")),
    ])
}

#[test]
fn configured_jwe_runtime_writes_and_reads() {
    let temp = tempfile::tempdir().unwrap();
    let device = DeviceKey::generate();
    let ceremony = setup_jwe_ceremony(temp.path(), &device, &[device.did().to_string()]);
    let runtime = Runtime::init(&ceremony.yaml_path).unwrap();

    runtime.info("invoice.created", private_fields()).unwrap();
    let entries = runtime.read().unwrap();
    let invoice = entries
        .iter()
        .find(|entry| entry["event_type"] == "invoice.created")
        .unwrap();

    assert_eq!(invoice["amount"], 42);
    assert_eq!(invoice["note"], "wrapped once per reader");
    assert!(!ceremony.keystore.join("default.jwe.mykey").exists());
}

#[test]
fn configured_jwe_runtime_seals_and_unseals() {
    let temp = tempfile::tempdir().unwrap();
    let device = DeviceKey::generate();
    let ceremony = setup_jwe_ceremony(temp.path(), &device, &[device.did().to_string()]);
    let runtime = Runtime::init(&ceremony.yaml_path).unwrap();
    let options = SealOptions {
        receipt: false,
        aad: Map::from_iter([("purpose".to_string(), json!("portable"))]),
    };

    let sealed = runtime
        .seal("obj.invoice.v1", private_fields(), &options)
        .unwrap();
    let opened = runtime
        .unseal(&sealed.wire, &UnsealOptions::default())
        .unwrap();

    assert_eq!(opened.plaintext["default"], Value::Object(private_fields()));
    assert_eq!(opened.fields["amount"], 42);
    assert_eq!(opened.fields["note"], "wrapped once per reader");
    assert!(opened.fields.contains_key("tn_aad"));
    assert!(opened.hidden_groups.is_empty());
    assert!(!ceremony.keystore.join("default.jwe.mykey").exists());
}

#[test]
fn named_jwe_reader_unseals_writer_object() {
    let writer_temp = tempfile::tempdir().unwrap();
    let reader_temp = tempfile::tempdir().unwrap();
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipient = vec![reader_device.did().to_string()];
    let writer_ceremony = setup_jwe_ceremony(writer_temp.path(), &writer_device, &recipient);
    let reader_ceremony = setup_jwe_ceremony(reader_temp.path(), &reader_device, &recipient);
    let writer = Runtime::init(&writer_ceremony.yaml_path).unwrap();
    let reader = Runtime::init(&reader_ceremony.yaml_path).unwrap();

    let sealed = writer
        .seal(
            "obj.invoice.v1",
            private_fields(),
            &SealOptions {
                receipt: false,
                aad: Map::new(),
            },
        )
        .unwrap();
    let opened = reader
        .unseal(&sealed.wire, &UnsealOptions::default())
        .unwrap();

    assert_eq!(opened.plaintext["default"], Value::Object(private_fields()));
    assert!(opened.hidden_groups.is_empty());
    assert!(!reader_ceremony.keystore.join("default.jwe.mykey").exists());
}

#[test]
fn standalone_jwe_reader_uses_its_device_key() {
    let writer_temp = tempfile::tempdir().unwrap();
    let reader_temp = tempfile::tempdir().unwrap();
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipient = vec![reader_device.did().to_string()];
    let writer_ceremony = setup_jwe_ceremony(writer_temp.path(), &writer_device, &recipient);
    let reader_ceremony = setup_jwe_ceremony(reader_temp.path(), &reader_device, &recipient);
    let writer = Runtime::init(&writer_ceremony.yaml_path).unwrap();
    let sealed = writer
        .seal(
            "obj.invoice.v1",
            private_fields(),
            &SealOptions {
                receipt: false,
                aad: Map::new(),
            },
        )
        .unwrap();

    let opened =
        unseal_as_recipient(&sealed.wire, &reader_ceremony.keystore, "default", true).unwrap();

    assert_eq!(opened.plaintext["default"], Value::Object(private_fields()));
    assert!(opened.hidden_groups.is_empty());
}

#[test]
fn direct_jwe_reader_opens_a_foreign_log() {
    let writer_temp = tempfile::tempdir().unwrap();
    let reader_temp = tempfile::tempdir().unwrap();
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipient = vec![reader_device.did().to_string()];
    let writer_ceremony = setup_jwe_ceremony(writer_temp.path(), &writer_device, &recipient);
    let reader_ceremony = setup_jwe_ceremony(reader_temp.path(), &reader_device, &recipient);
    let writer = Runtime::init(&writer_ceremony.yaml_path).unwrap();
    writer.info("invoice.created", private_fields()).unwrap();

    let entries = read_as_recipient(
        writer.log_path(),
        &reader_ceremony.keystore,
        ReadAsRecipientOptions::default(),
    )
    .unwrap();
    let invoice = entries
        .iter()
        .find(|entry| entry.envelope["event_type"] == "invoice.created")
        .unwrap();

    assert_eq!(invoice.plaintext["default"]["amount"], 42);
    assert_eq!(
        invoice.plaintext["default"]["note"],
        "wrapped once per reader"
    );
}
