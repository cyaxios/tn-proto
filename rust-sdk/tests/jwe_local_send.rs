//! Public Rust SDK proof for local JWE logging and sealed-object transport.

mod common;

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};
use tn_core::DeviceKey;
use tn_proto::{ReadOptions, SealOptions, Tn, UnsealOptions};

struct JweCeremony {
    yaml_path: PathBuf,
    keystore: PathBuf,
}

struct JweReader {
    did: String,
    private: [u8; 32],
    public: [u8; 32],
}

fn jwe_reader(device: &DeviceKey, fill: u8) -> JweReader {
    let private = [fill; 32];
    let public = tn_core::trusted_enrollment::x25519_public_key(&private);
    JweReader {
        did: device.did().to_owned(),
        private,
        public,
    }
}

fn setup_jwe_ceremony(
    root: &Path,
    ceremony_id: &str,
    device: &DeviceKey,
    recipients: &[&JweReader],
    my_private: Option<[u8; 32]>,
    public_fields: &[&str],
) -> JweCeremony {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();
    std::fs::write(keystore.join("local.private"), device.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x31_u8; 32]).unwrap();
    if let Some(private) = my_private {
        std::fs::write(keystore.join("default.jwe.mykey"), private).unwrap();
    }
    let recipient_doc = recipients
        .iter()
        .map(|reader| {
            json!({
                "recipient_identity": reader.did,
                "pub_b64": STANDARD.encode(reader.public),
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        keystore.join("default.jwe.recipients"),
        serde_json::to_vec_pretty(&recipient_doc).unwrap(),
    )
    .unwrap();
    let recipient_rows = recipients
        .iter()
        .map(|reader| {
            format!(
                "     - {{recipient_identity: \"{}\", pub_b64: \"{}\"}}\n",
                reader.did,
                STANDARD.encode(reader.public)
            )
        })
        .collect::<String>();
    let recipient_section = if recipient_rows.is_empty() {
        "   recipients: []\n".to_owned()
    } else {
        format!("   recipients:\n{recipient_rows}")
    };
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
         \x20{recipient_section}\
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

#[test]
fn enrolling_reader_refreshes_the_live_rust_sealer() -> tn_proto::Result<()> {
    let writer_temp = tempfile::tempdir()?;
    let reader_temp = tempfile::tempdir()?;
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipient = jwe_reader(&reader_device, 9);
    let writer_ceremony = setup_jwe_ceremony(
        writer_temp.path(),
        "cer_live_enrollment",
        &writer_device,
        &[],
        None,
        &[],
    );
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        "cer_live_reader",
        &reader_device,
        &[&recipient],
        Some(recipient.private),
        &[],
    );
    let mut writer = Tn::init(&writer_ceremony.yaml_path)?;
    let reader = Tn::init(&reader_ceremony.yaml_path)?;

    writer.admin().register_jwe_raw_unsafe(
        "default",
        reader_device.did(),
        recipient.public,
        true,
    )?;
    let sealed = writer.seal(
        "obj.enrolled.v1",
        json!({"message": "available without restart"}),
        SealOptions {
            receipt: false,
            ..SealOptions::default()
        },
    )?;
    let opened = reader.unseal(&sealed.wire, UnsealOptions::default())?;

    assert_eq!(opened.fields["message"], "available without restart");
    writer.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn unprovisioned_jwe_rejects_seal_and_logging_without_data_loss() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let device = DeviceKey::generate();
    let ceremony = setup_jwe_ceremony(
        temp.path(),
        "cer_unprovisioned_jwe",
        &device,
        &[],
        None,
        &[],
    );
    let tn = Tn::init(&ceremony.yaml_path)?;
    let log_before = std::fs::read(tn.log_path()).unwrap_or_default();
    let secret = "must-never-be-silently-dropped";

    let seal_error = tn
        .seal(
            "obj.unprovisioned.v1",
            json!({"message": secret}),
            SealOptions::default(),
        )
        .expect_err("seal must fail without an enrolled JWE recipient");
    assert!(matches!(
        seal_error,
        tn_proto::Error::Core(tn_core::Error::NotAPublisher { ref group, .. })
            if group == "default"
    ));

    let log_error = tn
        .info("message.unprovisioned", json!({"message": secret}))
        .expect_err("logging must fail without an enrolled JWE recipient");
    assert!(matches!(
        log_error,
        tn_proto::Error::Core(tn_core::Error::NotAPublisher { ref group, .. })
            if group == "default"
    ));
    assert_eq!(std::fs::read(tn.log_path()).unwrap_or_default(), log_before);

    tn.close()?;
    Ok(())
}

fn jwe_frame(envelope: &Value) -> Value {
    let ciphertext = envelope["default"]["ciphertext"]
        .as_str()
        .expect("default group ciphertext");
    let bytes = STANDARD
        .decode(ciphertext)
        .expect("group ciphertext base64");
    serde_json::from_slice(&bytes).expect("RFC 7516 General JSON JWE")
}

fn assert_recipient_block(recipient: &Value) {
    assert_eq!(recipient["header"]["alg"], "ECDH-ES+A256KW");
    assert_eq!(recipient["header"]["epk"]["kty"], "OKP");
    assert_eq!(recipient["header"]["epk"]["crv"], "X25519");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(recipient["header"]["epk"]["x"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(recipient["encrypted_key"].as_str().unwrap())
            .unwrap()
            .len(),
        40
    );
    assert!(recipient["header"].get("kid").is_none());
}

#[test]
fn local_jwe_log_wraps_one_content_key_per_recipient() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let writer_reader = jwe_reader(&writer_device, 1);
    let external_reader = jwe_reader(&reader_device, 2);
    let ceremony = setup_jwe_ceremony(
        temp.path(),
        "cer_local_jwe",
        &writer_device,
        &[&writer_reader, &external_reader],
        Some(writer_reader.private),
        &[],
    );
    let tn = Tn::init(&ceremony.yaml_path)?;
    let secret = "local-log-secret-that-must-not-appear-on-disk";

    let receipt = tn.info("message.logged", json!({ "message": secret }))?;
    let envelope = receipt.envelope.expect("emitted envelope");
    let frame = jwe_frame(&envelope);
    let recipients = frame["recipients"].as_array().unwrap();
    let protected: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(frame["protected"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(protected, json!({"enc": "A256GCM"}));
    assert_eq!(recipients.len(), 2);
    recipients.iter().for_each(assert_recipient_block);
    assert_ne!(
        recipients[0]["encrypted_key"],
        recipients[1]["encrypted_key"]
    );
    assert_ne!(
        recipients[0]["header"]["epk"]["x"],
        recipients[1]["header"]["epk"]["x"]
    );
    assert!(frame.get("frame").is_none());
    assert!(frame.get("body").is_none());
    assert!(frame.get("recipient_wraps").is_none());

    let raw_log = std::fs::read_to_string(tn.log_path())?;
    assert!(!raw_log.contains(secret));
    assert!(ceremony.keystore.join("default.jwe.mykey").exists());
    tn.close()?;
    Ok(())
}

#[test]
fn local_jwe_read_unwraps_and_recovers_the_logged_string() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let device = DeviceKey::generate();
    let reader = jwe_reader(&device, 3);
    let ceremony = setup_jwe_ceremony(
        temp.path(),
        "cer_local_read",
        &device,
        &[&reader],
        Some(reader.private),
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
    let recipient = jwe_reader(&reader_device, 4);
    let stranger_reader = jwe_reader(&stranger_device, 5);
    let writer_ceremony = setup_jwe_ceremony(
        writer_temp.path(),
        "cer_sender",
        &writer_device,
        &[&recipient],
        None,
        &["run_id"],
    );
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        "cer_reader",
        &reader_device,
        &[&recipient],
        Some(recipient.private),
        &[],
    );
    let stranger_ceremony = setup_jwe_ceremony(
        stranger_temp.path(),
        "cer_stranger",
        &stranger_device,
        &[&stranger_reader],
        Some(stranger_reader.private),
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
    let recipients = frame["recipients"].as_array().unwrap();
    assert_eq!(recipients.len(), 1);
    assert_recipient_block(&recipients[0]);
    assert!(!sealed.wire.contains(secret));

    let received_path = reader_temp.path().join("received.tn.json");
    std::fs::write(&received_path, sealed.wire.as_bytes())?;
    let received_wire = std::fs::read_to_string(received_path)?;
    let opened = reader.unseal(&received_wire, UnsealOptions::default())?;
    assert!(
        opened.fields.contains_key("message"),
        "reader_did={} recipient={} opened={opened:#?}",
        reader.did(),
        recipients[0]
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
