//! JWE-specific trusted enrollment surfaces in the Rust SDK.
//!
//! Rust uses the same raw X25519 enrollment material and RFC 7516 wire as the
//! sibling SDKs. These cases cover the trust boundary: typed recipient
//! registration from an `AcceptedOffer`, and the mandatory-flag raw
//! compatibility path with its warning/audit observability.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use tn_proto::enrollment::{self, AbsorbOptionsV1, OfferOptionsV1};
use tn_proto::Tn;

fn keystore_dir(tn: &Tn) -> PathBuf {
    let raw = fs::read_to_string(tn.yaml_path()).expect("read yaml");
    let doc: serde_yml::Value = serde_yml::from_str(&raw).expect("parse yaml");
    let keystore = doc["keystore"]["path"].as_str().expect("keystore.path");
    let path = Path::new(keystore);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        tn.yaml_path().parent().expect("yaml parent").join(path)
    }
}

fn jwe_publisher(root: &Path, ceremony_id: &str) -> Tn {
    let keystore = root.join(".tn").join("keys");
    fs::create_dir_all(&keystore).expect("keystore dir");
    let device = tn_core::DeviceKey::generate();
    let private = [0x51_u8; 32];
    let public = tn_core::trusted_enrollment::x25519_public_key(&private);
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x52_u8; 32]).expect("index key");
    fs::write(keystore.join("default.jwe.mykey"), private).expect("reader key");
    fs::write(
        keystore.join("default.jwe.recipients"),
        serde_json::to_vec(&serde_json::json!([{
            "recipient_identity": device.did(),
            "pub_b64": STANDARD.encode(public),
        }]))
        .expect("recipient json"),
    )
    .expect("recipient list");
    let yaml = format!(
        "ceremony: {{id: {ceremony_id}, mode: local, cipher: jwe, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
        did = device.did(),
    );
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("ceremony yaml");
    Tn::init(yaml_path).expect("JWE publisher")
}

fn accepted_offer_for(
    publisher: &Tn,
    reader: &Tn,
    td: &Path,
) -> tn_proto::Result<tn_proto::enrollment::AcceptedOffer> {
    let challenge = publisher.pkg().issue_enrollment_challenge(
        reader.did(),
        "default",
        Duration::from_secs(600),
    )?;
    let offer_path = td.join("offer.tnpkg");
    reader.pkg().offer_v1(OfferOptionsV1 {
        group: "default".into(),
        publisher_did: publisher.did().to_string(),
        out_path: offer_path.clone(),
        challenge: Some(challenge),
    })?;
    publisher.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(&offer_path),
        AbsorbOptionsV1::default(),
    )?;
    let artifact = fs::read(&offer_path).expect("offer bytes");
    let digest = enrollment::offer_digest_of_artifact(&artifact)?;
    publisher.pkg().approve_and_reconcile(&digest)
}

#[test]
fn native_jwe_group_initializes_without_publisher_or_reader_material() {
    // Provisioning is independent of runtime construction. An empty JWE group
    // can initialize; seal/open report their directional capability errors
    // only when those operations are requested.
    let td = tempfile::tempdir().expect("tempdir");
    let keystore = td.path().join(".tn").join("keys");
    fs::create_dir_all(&keystore).expect("keystore dir");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("seed");
    fs::write(keystore.join("index_master.key"), [0x11u8; 32]).expect("index key");
    let yaml = format!(
        "ceremony: {{id: cer_jwe_sentinel, mode: local, cipher: jwe}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
        did = device.did(),
    );
    let yaml_path = td.path().join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("write yaml");

    let runtime = Tn::init(&yaml_path).expect("native JWE group initializes");
    runtime.close().expect("close runtime");
}

#[test]
fn jwe_registration_rejects_wrong_or_unknown_groups_without_persisting() {
    for group in ["default", "missing"] {
        let mut publisher = Tn::ephemeral().expect("ephemeral BTN publisher");
        let reader_did = tn_core::DeviceKey::generate().did().to_string();
        let keystore = keystore_dir(&publisher);

        let error = publisher
            .admin()
            .register_jwe_raw_unsafe(group, &reader_did, [0x41_u8; 32], true)
            .expect_err("JWE registration requires an existing JWE group");

        assert!(
            error.to_string().contains("JWE group"),
            "unexpected error: {error}"
        );
        assert!(!keystore.join(format!("{group}.jwe.recipients")).exists());
        publisher.close().expect("close publisher");
    }
}

#[test]
fn register_jwe_offer_persists_the_verified_binding() -> tn_proto::Result<()> {
    let publisher_dir = tempfile::tempdir().expect("publisher dir");
    let mut publisher = jwe_publisher(publisher_dir.path(), "cer_verified_jwe");
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");
    let accepted = accepted_offer_for(&publisher, &reader, td.path())?;

    let result = publisher.admin().register_jwe_offer("default", &accepted)?;
    assert_eq!(result.group, "default");
    assert_eq!(result.recipient_did.as_deref(), Some(reader.did()));

    // Python-compatible recipients list.
    let recipients_path = keystore_dir(&publisher).join("default.jwe.recipients");
    let recipients: Value =
        serde_json::from_str(&fs::read_to_string(&recipients_path).expect("recipients file"))
            .expect("recipients json");
    let entries = recipients.as_array().expect("recipients list");
    assert_eq!(entries.len(), 2);
    let registered = entries
        .iter()
        .find(|entry| entry["recipient_identity"].as_str() == Some(reader.did()))
        .expect("registered reader");
    assert!(registered["pub_b64"].is_string());

    // Verified trust registry entry with the proof and offer digests.
    let registry_path = keystore_dir(&publisher)
        .join("trust")
        .join("jwe_recipients.v1.json");
    let registry: Value =
        serde_json::from_str(&fs::read_to_string(&registry_path).expect("registry file"))
            .expect("registry json");
    let entry = &registry["recipients"]["default"][reader.did()];
    assert_eq!(entry["verified"].as_bool(), Some(true));
    assert_eq!(
        entry["proof_digest"].as_str(),
        Some(accepted.binding.proof_digest.as_str())
    );
    assert_eq!(
        entry["offer_digest"].as_str(),
        Some(accepted.offer_digest.as_str())
    );

    // Registration attests once.
    let entries = publisher.read(tn_proto::ReadOptions::default())?;
    let added = entries
        .iter()
        .find(|entry| entry.event_type() == Some("tn.recipient.added"))
        .expect("tn.recipient.added attested");
    assert_eq!(added.get("cipher").and_then(Value::as_str), Some("jwe"));
    assert_eq!(
        added.get("recipient_identity").and_then(Value::as_str),
        Some(reader.did())
    );

    // Idempotent for the same accepted offer.
    publisher.admin().register_jwe_offer("default", &accepted)?;
    let recipients: Value =
        serde_json::from_str(&fs::read_to_string(&recipients_path).expect("recipients file"))
            .expect("recipients json");
    assert_eq!(recipients.as_array().expect("list").len(), 2);

    // Scope re-check: another ceremony's admin refuses this accepted offer.
    let stranger_dir = tempfile::tempdir().expect("stranger dir");
    let mut stranger = jwe_publisher(stranger_dir.path(), "cer_stranger_jwe");
    let err = stranger
        .admin()
        .register_jwe_offer("default", &accepted)
        .expect_err("accepted offer is bound to its publisher scope");
    let message = err.to_string();
    assert!(
        message.starts_with("invalid argument: wrong_recipient:")
            || message.starts_with("invalid argument: scope_mismatch:"),
        "got {message}"
    );

    publisher.close()?;
    reader.close()?;
    stranger.close()?;
    Ok(())
}

#[test]
fn register_jwe_raw_unsafe_requires_the_flag_and_is_observable() -> tn_proto::Result<()> {
    let publisher_dir = tempfile::tempdir().expect("publisher dir");
    let mut publisher = jwe_publisher(publisher_dir.path(), "cer_raw_jwe");
    let reader_did = tn_core::DeviceKey::generate().did().to_string();
    let public_key = [0x42u8; 32];

    // The mandatory flag is a hard parameter error when omitted.
    let err = publisher
        .admin()
        .register_jwe_raw_unsafe("default", &reader_did, public_key, false)
        .expect_err("unsafe_unverified=false is a hard parameter error");
    assert!(err.to_string().contains("unsafe_unverified"), "got {err}");

    // With the flag: registered, but stored as unverified, plus exactly one
    // audit event naming the relaxation.
    let result =
        publisher
            .admin()
            .register_jwe_raw_unsafe("default", &reader_did, public_key, true)?;
    assert_eq!(result.recipient_did.as_deref(), Some(reader_did.as_str()));

    let registry_path = keystore_dir(&publisher)
        .join("trust")
        .join("jwe_recipients.v1.json");
    let registry: Value =
        serde_json::from_str(&fs::read_to_string(&registry_path).expect("registry file"))
            .expect("registry json");
    let entry = &registry["recipients"]["default"][&reader_did];
    assert_eq!(
        entry["verified"].as_bool(),
        Some(false),
        "raw registration can never be promoted to verified silently"
    );

    let entries = publisher.read(tn_proto::ReadOptions::default())?;
    let audits: Vec<_> = entries
        .iter()
        .filter(|entry| entry.event_type() == Some("tn.security.unsafe_operation"))
        .collect();
    assert_eq!(audits.len(), 1, "exactly one best-effort audit event");
    assert_eq!(
        audits[0].get("operation").and_then(Value::as_str),
        Some("jwe_add_recipient")
    );
    assert_eq!(
        audits[0]
            .get("relaxations")
            .and_then(Value::as_array)
            .map(|relaxations| {
                relaxations
                    .iter()
                    .map(|value| value.as_str().unwrap_or_default().to_string())
                    .collect::<Vec<_>>()
            }),
        Some(vec!["unverified_key_binding".to_string()])
    );
    assert_eq!(
        audits[0].get("subject_did").and_then(Value::as_str),
        Some(reader_did.as_str())
    );

    publisher.close()?;
    Ok(())
}

#[test]
fn conflicting_key_for_a_registered_reader_is_a_replay_conflict() -> tn_proto::Result<()> {
    let publisher_dir = tempfile::tempdir().expect("publisher dir");
    let mut publisher = jwe_publisher(publisher_dir.path(), "cer_conflict_jwe");
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");
    let accepted = accepted_offer_for(&publisher, &reader, td.path())?;
    publisher.admin().register_jwe_offer("default", &accepted)?;

    let err = publisher
        .admin()
        .register_jwe_raw_unsafe("default", reader.did(), [0x99u8; 32], true)
        .expect_err("a different key for the same DID conflicts");
    assert!(
        err.to_string()
            .starts_with("invalid argument: replay_conflict:"),
        "got {err}"
    );

    publisher.close()?;
    reader.close()?;
    Ok(())
}
