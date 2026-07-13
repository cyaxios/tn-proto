//! Configured-runtime coverage for RFC 7516 General JSON JWE.

#![cfg(all(feature = "fs", feature = "native-jwe"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use curve25519_dalek::montgomery::MontgomeryPoint;
use serde_json::{json, Map, Value};
use tn_core::cipher::{jwe::JweCipher, GroupCipher};
use tn_core::read_as_recipient::{read_as_recipient, ReadAsRecipientOptions};
use tn_core::runtime::unseal_as_recipient;
use tn_core::{DeviceKey, Runtime, SealOptions, UnsealOptions};

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
    let public = *MontgomeryPoint::mul_base_clamped(private).as_bytes();
    JweReader {
        did: device.did().to_owned(),
        private,
        public,
    }
}

fn setup_jwe_ceremony(
    root: &Path,
    device: &DeviceKey,
    recipients: &[&JweReader],
    my_private: Option<[u8; 32]>,
) -> JweCeremony {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();
    std::fs::write(keystore.join("local.private"), device.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11_u8; 32]).unwrap();
    if let Some(private) = my_private {
        std::fs::write(keystore.join("default.jwe.mykey"), private).unwrap();
    }
    let recipient_doc = recipients
        .iter()
        .map(|recipient| {
            json!({
                "recipient_identity": recipient.did,
                "pub_b64": STANDARD.encode(recipient.public),
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        keystore.join("default.jwe.recipients"),
        serde_json::to_vec_pretty(&recipient_doc).unwrap(),
    )
    .unwrap();
    let did = device.did();
    let recipient_rows = recipients
        .iter()
        .map(|recipient| {
            format!(
                "     - {{recipient_identity: \"{}\", pub_b64: \"{}\"}}\n",
                recipient.did,
                STANDARD.encode(recipient.public)
            )
        })
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
fn python_joserfc_fixtures_open_in_rust() {
    for fixture_text in [
        include_str!("../../../csharp-sdk/tests/TnProto.Tests/Fixtures/jwe_single_recipient.json"),
        include_str!("../../../csharp-sdk/tests/TnProto.Tests/Fixtures/jwe_aad_bound.json"),
    ] {
        let fixture: Value = serde_json::from_str(fixture_text).unwrap();
        let private = STANDARD
            .decode(fixture["reader_sk_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = STANDARD
            .decode(fixture["plaintext_b64"].as_str().unwrap())
            .unwrap();
        let aad = fixture["aad_b64"]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(|value| STANDARD.decode(value).unwrap())
            .unwrap_or_default();
        let cipher = JweCipher::new("fixture", &[], &[private]).unwrap();

        assert_eq!(
            cipher
                .decrypt_with_aad(fixture["jwe"].as_str().unwrap().as_bytes(), &aad)
                .unwrap(),
            plaintext
        );
    }
}

#[test]
fn python_two_recipient_fixture_opens_with_either_rust_reader_key() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../csharp-sdk/tests/TnProto.Tests/Fixtures/jwe_two_recipients.json"
    ))
    .unwrap();
    let expected = STANDARD
        .decode(fixture["plaintext_b64"].as_str().unwrap())
        .unwrap();
    for field in ["first_recipient_sk_b64", "second_recipient_sk_b64"] {
        let private = STANDARD
            .decode(fixture[field].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let reader = JweCipher::new("fixture", &[], &[private]).unwrap();
        assert_eq!(
            reader
                .decrypt(fixture["jwe"].as_str().unwrap().as_bytes())
                .unwrap(),
            expected
        );
    }
}

#[test]
#[ignore = "requires TN_INTEROP_PYTHON pointing to Python with joserfc"]
fn rust_jwe_opens_in_python_joserfc() {
    let first_device = DeviceKey::generate();
    let second_device = DeviceKey::generate();
    let first = jwe_reader(&first_device, 21);
    let second = jwe_reader(&second_device, 22);
    let cipher = JweCipher::new("interop", &[first.public, second.public], &[]).unwrap();
    let plaintext = b"rust-to-joserfc";
    let aad = br#"{"case":"R-17"}"#;
    let jwe = String::from_utf8(cipher.encrypt_with_aad(plaintext, aad).unwrap()).unwrap();
    let input = json!({
        "jwe": jwe,
        "reader_sk_b64": STANDARD.encode(second.private),
        "reader_pk_b64": STANDARD.encode(second.public),
        "plaintext_b64": STANDARD.encode(plaintext),
        "aad_b64": STANDARD.encode(aad),
    });
    let python = std::env::var("TN_INTEROP_PYTHON").expect("set TN_INTEROP_PYTHON");
    let mut child = Command::new(python)
        .args(["-B", "-c", PYTHON_JOSERFC_OPEN])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Python joserfc interop process");
    serde_json::to_writer(child.stdin.take().unwrap(), &input).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "joserfc failed to open Rust JWE:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const PYTHON_JOSERFC_OPEN: &str = r#"
import base64, json, sys
from joserfc import jwe
from joserfc.jwk import OKPKey

doc = json.load(sys.stdin)
b64u = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
raw_sk = base64.b64decode(doc['reader_sk_b64'])
raw_pk = base64.b64decode(doc['reader_pk_b64'])
key = OKPKey.import_key({'kty': 'OKP', 'crv': 'X25519', 'x': b64u(raw_pk), 'd': b64u(raw_sk)})
obj = json.loads(doc['jwe'])
base = {name: obj[name] for name in ('protected', 'aad', 'iv', 'ciphertext', 'tag') if name in obj}
expected_plaintext = base64.b64decode(doc['plaintext_b64'])
expected_aad = base64.b64decode(doc['aad_b64'])
for recipient in obj['recipients']:
    flattened = dict(base, header=recipient['header'], encrypted_key=recipient['encrypted_key'])
    try:
        opened = jwe.decrypt_json(flattened, key, algorithms=['ECDH-ES+A256KW', 'A256GCM'])
    except Exception:
        continue
    assert opened.plaintext == expected_plaintext
    assert (opened.aad or b'') == expected_aad
    break
else:
    raise AssertionError('no anonymous recipient block opened with the second Rust recipient key')
"#;

#[test]
fn configured_jwe_runtime_writes_and_reads() {
    let temp = tempfile::tempdir().unwrap();
    let device = DeviceKey::generate();
    let reader = jwe_reader(&device, 1);
    let ceremony = setup_jwe_ceremony(temp.path(), &device, &[&reader], Some(reader.private));
    let runtime = Runtime::init(&ceremony.yaml_path).unwrap();

    runtime.info("invoice.created", private_fields()).unwrap();
    let entries = runtime.read().unwrap();
    let invoice = entries
        .iter()
        .find(|entry| entry["event_type"] == "invoice.created")
        .unwrap();

    assert_eq!(invoice["amount"], 42);
    assert_eq!(invoice["note"], "wrapped once per reader");
    assert!(ceremony.keystore.join("default.jwe.mykey").exists());
}

#[test]
fn configured_jwe_runtime_seals_and_unseals() {
    let temp = tempfile::tempdir().unwrap();
    let device = DeviceKey::generate();
    let reader = jwe_reader(&device, 2);
    let ceremony = setup_jwe_ceremony(temp.path(), &device, &[&reader], Some(reader.private));
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
    assert!(ceremony.keystore.join("default.jwe.mykey").exists());
}

#[test]
fn tampered_jwe_aad_is_a_decrypt_error_during_read() {
    let temp = tempfile::tempdir().unwrap();
    let device = DeviceKey::generate();
    let reader = jwe_reader(&device, 8);
    let ceremony = setup_jwe_ceremony(temp.path(), &device, &[&reader], Some(reader.private));
    let runtime = Runtime::init(&ceremony.yaml_path).unwrap();
    let aad = Map::from_iter([("purpose".to_string(), json!("original"))]);
    let line = runtime
        .emit_with_aad_returning_line(
            "info",
            "invoice.aad",
            private_fields(),
            None,
            None,
            None,
            &aad,
        )
        .unwrap()
        .expect("info event is emitted");
    let mut row: Value = serde_json::from_str(&line).unwrap();
    let mut aad_echo: Value = serde_json::from_str(row["tn_aad"].as_str().unwrap()).unwrap();
    aad_echo["default"]["purpose"] = json!("tampered");
    row["tn_aad"] = Value::String(serde_json::to_string(&aad_echo).unwrap());
    let tampered_log = temp.path().join("tampered.ndjson");
    std::fs::write(&tampered_log, format!("{row}\n")).unwrap();

    let entries = runtime.read_from(&tampered_log).unwrap();

    assert_eq!(
        entries[0].plaintext_per_group["default"]["$decrypt_error"],
        true
    );
    assert!(entries[0].plaintext_per_group["default"]
        .get("$no_read_key")
        .is_none());
}

#[test]
fn named_jwe_reader_unseals_writer_object() {
    let writer_temp = tempfile::tempdir().unwrap();
    let reader_temp = tempfile::tempdir().unwrap();
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipient = jwe_reader(&reader_device, 3);
    let writer_ceremony =
        setup_jwe_ceremony(writer_temp.path(), &writer_device, &[&recipient], None);
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        &reader_device,
        &[&recipient],
        Some(recipient.private),
    );
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
    assert!(reader_ceremony.keystore.join("default.jwe.mykey").exists());
}

#[test]
fn standalone_jwe_reader_uses_its_raw_x25519_key() {
    let writer_temp = tempfile::tempdir().unwrap();
    let reader_temp = tempfile::tempdir().unwrap();
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let recipient = jwe_reader(&reader_device, 4);
    let writer_ceremony =
        setup_jwe_ceremony(writer_temp.path(), &writer_device, &[&recipient], None);
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        &reader_device,
        &[&recipient],
        Some(recipient.private),
    );
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
    let recipient = jwe_reader(&reader_device, 5);
    let writer_ceremony =
        setup_jwe_ceremony(writer_temp.path(), &writer_device, &[&recipient], None);
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        &reader_device,
        &[&recipient],
        Some(recipient.private),
    );
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

#[test]
fn archived_jwe_reader_key_opens_pre_rotation_log() {
    let writer_temp = tempfile::tempdir().unwrap();
    let reader_temp = tempfile::tempdir().unwrap();
    let writer_device = DeviceKey::generate();
    let reader_device = DeviceKey::generate();
    let prior = jwe_reader(&reader_device, 6);
    let current = jwe_reader(&reader_device, 7);
    let writer_ceremony = setup_jwe_ceremony(writer_temp.path(), &writer_device, &[&prior], None);
    let reader_ceremony = setup_jwe_ceremony(
        reader_temp.path(),
        &reader_device,
        &[&current],
        Some(current.private),
    );
    std::fs::write(
        reader_ceremony.keystore.join("default.jwe.mykey.revoked.1"),
        prior.private,
    )
    .unwrap();
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
}
