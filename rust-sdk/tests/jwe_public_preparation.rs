//! Public-only JWE recipient preparation, including mixed BTN/JWE requests.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tn_core::tnpkg::TnpkgSource;
use tn_proto::enrollment::{self, AbsorbOptionsV1, OfferOptionsV1};
use tn_proto::{
    PrepareRecipientOptions, ReadOptions, SealOptions, Tn, TnInitOptions, UnsealOptions,
};

fn mixed_publisher(root: &Path) -> Tn {
    let keystore = root.join(".tn").join("keys");
    fs::create_dir_all(&keystore).expect("keystore");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x41_u8; 32]).expect("index key");

    let mut state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x42_u8; 32]).expect("btn");
    let kit = state.mint().expect("self kit");
    fs::write(keystore.join("broadcast.btn.state"), state.to_bytes()).expect("btn state");
    fs::write(keystore.join("broadcast.btn.mykit"), kit.to_bytes()).expect("btn kit");

    let did = device.did();
    let yaml = format!(
        "ceremony: {{id: cer_public_prepare, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 broadcast:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 partners:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   recipients: []\n\
         \x20   fields: [message]\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n"
    );
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("yaml");
    Tn::init(yaml_path).expect("mixed publisher")
}

fn jwe_reader(root: &Path, publisher: &Tn) -> Tn {
    let keystore = root.join(".tn").join("keys");
    fs::create_dir_all(&keystore).expect("keystore");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x51_u8; 32]).expect("index key");
    let log_path = publisher.log_path().to_string_lossy().replace('\\', "/");
    let did = device.did();
    let yaml = format!(
        "ceremony: {{id: cer_reader, mode: local, cipher: jwe, admin_log_location: ./.tn/admin/admin.ndjson}}\n\
         logs: {{path: \"{log_path}\"}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 partners:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   recipients: []\n\
         \x20   fields: [message]\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n"
    );
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("yaml");
    Tn::init_with_options(
        yaml_path,
        TnInitOptions {
            skip_ceremony_init_emit: true,
            skip_policy_published_emit: true,
        },
    )
    .expect("JWE reader")
}

fn keystore_dir(tn: &Tn) -> PathBuf {
    let raw = fs::read_to_string(tn.yaml_path()).expect("yaml");
    let doc: serde_yml::Value = serde_yml::from_str(&raw).expect("parse yaml");
    let configured = Path::new(doc["keystore"]["path"].as_str().expect("keystore.path"));
    tn.yaml_path()
        .parent()
        .expect("yaml parent")
        .join(configured)
}

fn accepted_offer(
    publisher: &Tn,
    reader: &Tn,
    temp: &Path,
) -> tn_proto::Result<enrollment::AcceptedOffer> {
    let challenge = publisher.pkg().issue_enrollment_challenge(
        reader.did(),
        "partners",
        Duration::from_secs(600),
    )?;
    let offer_path = temp.join("partners.offer.tnpkg");
    reader.pkg().offer_v1(OfferOptionsV1 {
        group: "partners".into(),
        publisher_did: publisher.did().to_string(),
        out_path: offer_path.clone(),
        challenge: Some(challenge),
    })?;
    publisher.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(&offer_path),
        AbsorbOptionsV1::default(),
    )?;
    let digest = enrollment::offer_digest_of_artifact(&fs::read(offer_path)?)?;
    publisher.pkg().approve_and_reconcile(&digest)
}

fn assert_public_only(path: &Path, reader_private: &[u8]) {
    let (_, body) =
        tn_core::tnpkg::read_tnpkg_verified(TnpkgSource::Path(path)).expect("verified package");
    for (name, bytes) in body {
        assert!(!name.ends_with(".jwe.mykey"), "private-key entry: {name}");
        assert_ne!(bytes, reader_private, "raw JWE private key in {name}");
    }
}

#[test]
fn activation_absorb_makes_reader_ready_for_jwe_seal_unseal_and_read() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = mixed_publisher(&temp.path().join("publisher"));
    let reader = jwe_reader(&temp.path().join("reader"), &publisher);
    let accepted = accepted_offer(&publisher, &reader, temp.path())?;
    let offer_digest = accepted.offer_digest.clone();

    let sent_offers: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        keystore_dir(&reader)
            .join("trust")
            .join("enrollment_offers.v1.json"),
    )?)?;
    let retained = &sent_offers["offers"][&offer_digest];
    assert_eq!(retained["publisher_did"], publisher.did());
    assert_eq!(retained["reader_did"], reader.did());
    assert_eq!(retained["ceremony_id"], "cer_public_prepare");
    assert_eq!(retained["group"], "partners");
    assert_eq!(
        retained["x25519_public_key_sha256"],
        accepted.binding.public_key_sha256
    );
    assert_eq!(
        retained["expires_at"],
        accepted.binding.principal.expires_at
    );

    let prepared = publisher.pkg().prepare_recipient(
        reader.did(),
        temp.path().join("ready"),
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into()]),
            accepted_offers: vec![accepted],
            ..PrepareRecipientOptions::default()
        },
    )?;
    let activation = &prepared.jwe_activations[0].package.path;
    let receipt = reader.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(activation),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(receipt.legacy_status, "enrolment_applied");
    assert_eq!(receipt.accepted_count, 1);
    assert!(keystore_dir(&reader)
        .join("trust")
        .join("verified_publishers.v1.json")
        .is_file());

    let sealed = publisher.seal(
        "message.local.v1",
        serde_json::json!({"message": "wrapped for the enrolled reader"}),
        SealOptions {
            receipt: false,
            ..SealOptions::default()
        },
    )?;
    let opened = reader.unseal(
        &sealed.wire,
        UnsealOptions {
            as_recipient: Some(keystore_dir(&reader)),
            group: "partners".into(),
            ..UnsealOptions::default()
        },
    )?;
    assert_eq!(
        opened.plaintext["partners"]["message"],
        "wrapped for the enrolled reader"
    );

    publisher.info(
        "message.sent",
        serde_json::json!({"message": "read from the publisher log"}),
    )?;
    let entries = reader.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    let emitted = entries
        .iter()
        .find(|entry| entry.event_type() == Some("message.sent"))
        .expect("publisher event readable by enrolled reader");
    assert_eq!(
        emitted.get("message"),
        Some(&serde_json::json!("read from the publisher log"))
    );

    publisher.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn jwe_only_preparation_returns_one_public_activation_without_a_kit_bundle() -> tn_proto::Result<()>
{
    let temp = tempfile::tempdir()?;
    let publisher = mixed_publisher(&temp.path().join("publisher"));
    let reader = Tn::ephemeral()?;
    let accepted = accepted_offer(&publisher, &reader, temp.path())?;
    let reader_private = fs::read(keystore_dir(&reader).join("partners.jwe.mykey"))?;

    let result = publisher.pkg().prepare_recipient(
        reader.did(),
        temp.path().join("jwe-only"),
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into()]),
            accepted_offers: vec![accepted],
            activation_ttl: Duration::from_secs(600),
            ..PrepareRecipientOptions::default()
        },
    )?;

    assert_eq!(result.requested_groups, vec!["partners"]);
    assert!(result.kit_bundle.is_none());
    assert_eq!(result.jwe_activations.len(), 1);
    assert_eq!(result.jwe_activations[0].group, "partners");
    assert_public_only(&result.jwe_activations[0].package.path, &reader_private);
    assert!(!keystore_dir(&publisher).join("partners.jwe.mykey").exists());
    publisher.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn mixed_preparation_returns_btn_bundle_and_separate_jwe_activation() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = mixed_publisher(&temp.path().join("publisher"));
    let reader = Tn::ephemeral()?;
    let accepted = accepted_offer(&publisher, &reader, temp.path())?;
    let reader_private = fs::read(keystore_dir(&reader).join("partners.jwe.mykey"))?;

    let result = publisher.pkg().prepare_recipient(
        reader.did(),
        temp.path().join("mixed"),
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into(), "broadcast".into()]),
            accepted_offers: vec![accepted],
            activation_ttl: Duration::from_secs(600),
            ..PrepareRecipientOptions::default()
        },
    )?;

    assert_eq!(result.requested_groups, vec!["partners", "broadcast"]);
    let bundle = result.kit_bundle.expect("BTN/HIBE kit bundle");
    assert_eq!(bundle.groups, vec!["broadcast"]);
    let (_, body) = tn_core::tnpkg::read_tnpkg_verified(TnpkgSource::Path(&bundle.path))?;
    assert!(body.contains_key("body/broadcast.btn.mykit"));
    assert_public_only(&bundle.path, &reader_private);
    assert_eq!(result.jwe_activations.len(), 1);
    assert_public_only(&result.jwe_activations[0].package.path, &reader_private);
    publisher.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn mixed_preparation_rejects_wrong_scope_before_writing_the_btn_bundle() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = mixed_publisher(&temp.path().join("publisher"));
    let reader = Tn::ephemeral()?;
    let mut accepted = accepted_offer(&publisher, &reader, temp.path())?;
    accepted.binding.principal.audience_did = tn_core::DeviceKey::generate().did().to_string();
    let out_dir = temp.path().join("wrong-scope");

    let error = publisher
        .pkg()
        .prepare_recipient(
            reader.did(),
            &out_dir,
            PrepareRecipientOptions {
                groups: Some(vec!["broadcast".into(), "partners".into()]),
                accepted_offers: vec![accepted],
                ..PrepareRecipientOptions::default()
            },
        )
        .expect_err("wrong-scope JWE evidence must fail closed");

    assert!(error
        .to_string()
        .starts_with("invalid argument: wrong_recipient:"));
    assert!(!out_dir.join("reader-bundle.tnpkg").exists());
    publisher.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn mixed_preparation_rejects_key_conflict_before_writing_the_btn_bundle() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut publisher = mixed_publisher(&temp.path().join("publisher"));
    let reader = Tn::ephemeral()?;
    let accepted = accepted_offer(&publisher, &reader, temp.path())?;
    publisher
        .admin()
        .register_jwe_raw_unsafe("partners", reader.did(), [0x99_u8; 32], true)?;
    let out_dir = temp.path().join("key-conflict");

    let error = publisher
        .pkg()
        .prepare_recipient(
            reader.did(),
            &out_dir,
            PrepareRecipientOptions {
                groups: Some(vec!["broadcast".into(), "partners".into()]),
                accepted_offers: vec![accepted],
                ..PrepareRecipientOptions::default()
            },
        )
        .expect_err("conflicting JWE key must fail closed");

    assert!(error
        .to_string()
        .starts_with("invalid argument: replay_conflict:"));
    assert!(!out_dir.join("reader-bundle.tnpkg").exists());
    publisher.close()?;
    reader.close()?;
    Ok(())
}
