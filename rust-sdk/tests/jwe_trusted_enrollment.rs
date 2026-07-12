//! JWE-specific trusted enrollment surfaces in the Rust SDK.
//!
//! The Rust runtime keeps its documented native JWE `NotImplemented` sentinel
//! (managed JWE and first decrypt belong to Python, TypeScript, and C#).
//! What Rust owns here is the trust boundary: typed recipient registration
//! from an `AcceptedOffer`, and the mandatory-flag raw compatibility path with
//! its warning/audit observability.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
fn native_jwe_group_keeps_the_documented_not_implemented_sentinel() {
    // A ceremony declaring a jwe group cannot open in the Rust runtime; the
    // sentinel points the operator at the managed JWE SDKs instead of
    // pretending to seal.
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

    let err = Tn::init(&yaml_path).expect_err("jwe groups are not native in Rust");
    let message = err.to_string();
    assert!(
        message.contains("JWE"),
        "sentinel names the JWE boundary: {message}"
    );
    assert!(
        matches!(
            err,
            tn_proto::Error::Core(tn_core::Error::NotImplemented(_))
        ),
        "documented NotImplemented sentinel: {message}"
    );
}

#[test]
fn register_jwe_offer_persists_the_verified_binding() -> tn_proto::Result<()> {
    let mut publisher = Tn::ephemeral()?;
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
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["recipient_identity"].as_str(),
        Some(reader.did())
    );
    assert!(entries[0]["pub_b64"].is_string());

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
    assert_eq!(recipients.as_array().expect("list").len(), 1);

    // Scope re-check: another ceremony's admin refuses this accepted offer.
    let mut stranger = Tn::ephemeral()?;
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
    let mut publisher = Tn::ephemeral()?;
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
    let mut publisher = Tn::ephemeral()?;
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
