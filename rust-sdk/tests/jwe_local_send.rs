//! Public Rust SDK proof for local JWE logging and sealed-object transport.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tn_core::DeviceKey;
use tn_proto::{ReadOptions, SealOptions, Tn, UnsealOptions};

struct JweCeremony {
    yaml_path: PathBuf,
    keystore: PathBuf,
}

fn setup_jwe_ceremony(
    root: &Path,
    ceremony_id: &str,
    device: &DeviceKey,
    recipients: &[String],
    public_fields: &[&str],
) -> JweCeremony {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();
    std::fs::write(keystore.join("local.private"), device.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x31_u8; 32]).unwrap();
    let recipient_rows = recipients
        .iter()
        .map(|did| format!("     - {{recipient_identity: \"{did}\"}}\n"))
        .collect::<String>();
    let public_fields = public_fields.join(", ");
    let did = device.did();
    let yaml = format!(
        "ceremony: {{id: {ceremony_id}, mode: local, cipher: jwe, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: [{public_fields}]\n\
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

fn jwe_frame(envelope: &Value) -> Value {
    let ciphertext = envelope["default"]["ciphertext"]
        .as_str()
        .expect("default group ciphertext");
    let bytes = STANDARD
        .decode(ciphertext)
        .expect("group ciphertext base64");
    serde_json::from_slice(&bytes).expect("tn-jwe-v1 frame")
}

fn assert_key_wrap(wrap: &Value) {
    assert_eq!(wrap["frame"], "tn-sealed-box-v1");
    assert_eq!(
        STANDARD
            .decode(wrap["ephemeral_x25519_pub_b64"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        STANDARD
            .decode(wrap["wrap_nonce_b64"].as_str().unwrap())
            .unwrap()
            .len(),
        12
    );
    assert_eq!(
        STANDARD
            .decode(wrap["wrapped_bek_b64"].as_str().unwrap())
            .unwrap()
            .len(),
        48
    );
}

#[test]
fn local_jwe_log_wraps_one_content_key_per_recipient() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipients = vec![
        writer_device.did().to_owned(),
        reader_device.did().to_owned(),
    ];
    let ceremony = setup_jwe_ceremony(
        temp.path(),
        "cer_local_jwe",
        &writer_device,
        &recipients,
        &[],
    );
    let tn = Tn::init(&ceremony.yaml_path)?;
    let secret = "local-log-secret-that-must-not-appear-on-disk";

    let receipt = tn.info("message.logged", json!({ "message": secret }))?;
    let envelope = receipt.envelope.expect("emitted envelope");
    let frame = jwe_frame(&envelope);
    let wraps = frame["recipient_wraps"].as_array().unwrap();

    assert_eq!(frame["frame"], "tn-jwe-v1");
    assert_eq!(frame["body"].as_str().unwrap().split('.').count(), 5);
    assert_eq!(wraps.len(), 2);
    wraps.iter().for_each(assert_key_wrap);
    let addressees = wraps
        .iter()
        .map(|wrap| wrap["recipient_identity"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        addressees,
        BTreeSet::from([writer_device.did(), reader_device.did()])
    );
    assert_ne!(wraps[0]["wrapped_bek_b64"], wraps[1]["wrapped_bek_b64"]);
    assert_ne!(
        wraps[0]["ephemeral_x25519_pub_b64"],
        wraps[1]["ephemeral_x25519_pub_b64"]
    );

    let raw_log = std::fs::read_to_string(tn.log_path())?;
    assert!(!raw_log.contains(secret));
    assert!(!ceremony.keystore.join("default.jwe.mykey").exists());
    tn.close()?;
    Ok(())
}

#[test]
fn local_jwe_read_unwraps_and_recovers_the_logged_string() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let device = DeviceKey::generate();
    let ceremony = setup_jwe_ceremony(
        temp.path(),
        "cer_local_read",
        &device,
        &[device.did().to_owned()],
        &[],
    );
    let tn = Tn::init(&ceremony.yaml_path)?;
    let secret = "read-me-through-the-wrapped-content-key";

    tn.info("message.logged", json!({ "message": secret }))?;
    let entries = tn.read(ReadOptions::default())?;
    let entry = common::find_event(&entries, "message.logged");

    assert_eq!(entry.get("message").and_then(Value::as_str), Some(secret));
    tn.close()?;
    Ok(())
}

#[test]
fn sealed_string_survives_transport_and_only_the_named_reader_opens_it() -> tn_proto::Result<()> {
    let writer_temp = tempfile::tempdir()?;
    let reader_temp = tempfile::tempdir()?;
    let stranger_temp = tempfile::tempdir()?;
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let stranger_device = DeviceKey::generate();
    let recipient = vec![reader_device.did().to_owned()];
    let writer_ceremony = setup_jwe_ceremony(
        writer_temp.path(),
        "cer_sender",
        &writer_device,
        &recipient,
        &["run_id"],
    );
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        "cer_reader",
        &reader_device,
        &recipient,
        &[],
    );
    let stranger_ceremony = setup_jwe_ceremony(
        stranger_temp.path(),
        "cer_stranger",
        &stranger_device,
        &[stranger_device.did().to_owned()],
        &[],
    );
    let writer = Tn::init(&writer_ceremony.yaml_path)?;
    let reader = Tn::init(&reader_ceremony.yaml_path)?;
    let stranger = Tn::init(&stranger_ceremony.yaml_path)?;
    let secret = "sealed string sent between two separate local projects";
    let run_id = "public-transport-id";

    let sealed = writer.seal(
        "obj.message.v1",
        json!({ "message": secret, "run_id": run_id }),
        SealOptions {
            receipt: false,
            ..SealOptions::default()
        },
    )?;
    let frame = jwe_frame(&Value::Object(sealed.envelope.clone()));
    let wraps = frame["recipient_wraps"].as_array().unwrap();
    assert_eq!(wraps.len(), 1);
    assert_key_wrap(&wraps[0]);
    assert_eq!(wraps[0]["recipient_identity"], reader.did());
    assert!(!sealed.wire.contains(secret));

    let received_path = reader_temp.path().join("received.tn.json");
    std::fs::write(&received_path, sealed.wire.as_bytes())?;
    let received_wire = std::fs::read_to_string(received_path)?;
    let opened = reader.unseal(&received_wire, UnsealOptions::default())?;
    assert!(
        opened.fields.contains_key("message"),
        "reader_did={} wrap={} opened={opened:#?}",
        reader.did(),
        wraps[0]
    );
    assert_eq!(opened.fields["message"], secret);
    assert_eq!(opened.fields["run_id"], run_id);
    assert!(opened.hidden_groups.is_empty());

    let denied = stranger.unseal(&received_wire, UnsealOptions::default())?;
    assert_eq!(denied.hidden_groups, vec!["default"]);
    assert!(!denied.fields.contains_key("message"));
    assert_eq!(denied.fields["run_id"], run_id);

    writer.close()?;
    reader.close()?;
    stranger.close()?;
    Ok(())
}
