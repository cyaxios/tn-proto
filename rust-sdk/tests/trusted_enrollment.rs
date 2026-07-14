//! Rust SDK surface tests for the trusted JWE enrollment lifecycle:
//! publisher challenge, reader offer artifact, verified absorb into pending
//! state, atomic exact-digest approval/reconcile, enrollment-response
//! compilation, reader-side response install, and the explicit unsafe
//! legacy-import path.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tn_proto::enrollment::{
    self, AbsorbOptionsV1, CompileEnrolmentOptionsV1, OfferOptionsV1, ResponseExpectation,
};
use tn_proto::{AbsorbReceiptExt as _, AbsorbStatus, Tn};

/// Zip raw members without the strict `.tnpkg` writer, so tests can produce
/// tampered and legacy (index-less) archives the strict writer refuses.
fn raw_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in members {
        writer.start_file(*name, options).expect("zip member");
        writer.write_all(data).expect("zip data");
    }
    writer.finish().expect("finish zip").into_inner()
}

/// Two device ceremonies (publisher, reader) sharing one logical ceremony
/// id, so an unsolicited offer's scope matches the receiving store.
fn shared_ceremony_pair(root: &Path) -> (Tn, Tn) {
    let make = |dir: &Path| -> Tn {
        let keystore = dir.join(".tn").join("keys");
        fs::create_dir_all(&keystore).expect("keystore dir");
        let device = tn_core::DeviceKey::generate();
        fs::write(keystore.join("local.private"), device.private_bytes()).expect("seed");
        fs::write(keystore.join("index_master.key"), [0x11u8; 32]).expect("index key");
        let mut btn_seed = [0u8; 32];
        {
            use rand_core::RngCore as _;
            rand_core::OsRng.fill_bytes(&mut btn_seed);
        }
        let mut state =
            tn_btn::PublisherState::setup_with_seed(tn_btn::Config, btn_seed).expect("btn");
        let kit = state.mint().expect("btn kit");
        fs::write(keystore.join("default.btn.state"), state.to_bytes()).expect("state");
        fs::write(keystore.join("default.btn.mykit"), kit.to_bytes()).expect("kit");
        let did = device.did();
        let yaml = [
            "ceremony: {id: cer_shared_enrollment, mode: local, cipher: btn}".to_string(),
            "keystore: {path: ./.tn/keys}".to_string(),
            format!("device: {{device_identity: \"{did}\"}}"),
            "public_fields: []".to_string(),
            "default_policy: private".to_string(),
            "groups:".to_string(),
            "  default:".to_string(),
            "    policy: private".to_string(),
            "    cipher: btn".to_string(),
            "    recipients:".to_string(),
            format!("      - {{recipient_identity: \"{did}\"}}"),
            "    index_epoch: 0".to_string(),
            "fields: {}".to_string(),
            "llm_classifier: {enabled: false, provider: \"\", model: \"\"}".to_string(),
        ]
        .join("\n");
        let yaml_path = dir.join("tn.yaml");
        fs::write(&yaml_path, yaml).expect("yaml");
        Tn::init(&yaml_path).expect("init shared ceremony")
    };
    let publisher = make(&root.join("publisher"));
    let reader = make(&root.join("reader"));
    (publisher, reader)
}

fn state_root(tn: &Tn) -> PathBuf {
    let yaml = tn.yaml_path();
    let stem = yaml
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("yaml stem");
    yaml.parent()
        .expect("yaml parent")
        .join(".tn")
        .join(stem)
        .join("enrollment")
        .join("v1")
}

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

fn device_key(tn: &Tn) -> tn_core::DeviceKey {
    let seed = fs::read(keystore_dir(tn).join("local.private")).expect("read device seed");
    tn_core::DeviceKey::from_private_bytes(&seed).expect("device key")
}

fn jwe_tn(root: &Path) -> Tn {
    let keystore = root.join(".tn/keys");
    fs::create_dir_all(&keystore).expect("keystore dir");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x31_u8; 32]).expect("index key");
    let yaml = format!(
        "ceremony: {{id: cer_jwe_enrollment, mode: local, cipher: jwe}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   recipients: []\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
        device.did()
    );
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("yaml");
    Tn::init(yaml_path).expect("JWE ceremony")
}

#[test]
fn jwe_enrollment_lifecycle_completes_through_response_install() -> tn_proto::Result<()> {
    let td = tempfile::tempdir().expect("tempdir");
    let publisher = jwe_tn(&td.path().join("publisher"));
    let reader = jwe_tn(&td.path().join("reader"));

    // 1. Publisher pre-authorizes the exact reader and issues a signed
    //    one-time challenge. The challenge is durably retained.
    let challenge = publisher.pkg().issue_enrollment_challenge(
        reader.did(),
        "default",
        Duration::from_secs(600),
    )?;
    assert_eq!(challenge.publisher_did, publisher.did());
    assert_eq!(challenge.expected_reader_did, reader.did());
    assert_eq!(challenge.group, "default");
    assert!(!challenge.signature_b64.is_empty());
    let challenges_dir = state_root(&publisher).join("challenges");
    assert_eq!(
        fs::read_dir(&challenges_dir)
            .expect("challenges dir")
            .count(),
        1,
        "issued challenge is retained on disk"
    );

    // 2. Reader builds a signed offer artifact bound to the challenge. The
    //    reader's static X25519 key is created once and reused exactly.
    let offer_path = td.path().join("offer.tnpkg");
    let receipt = reader.pkg().offer_v1(OfferOptionsV1 {
        group: "default".into(),
        publisher_did: publisher.did().to_string(),
        out_path: offer_path.clone(),
        challenge: Some(challenge.clone()),
    })?;
    assert_eq!(receipt.status, "offered");
    assert_eq!(receipt.peer_did, publisher.did());
    let mykey_path = keystore_dir(&reader).join("default.jwe.mykey");
    let mykey_before = fs::read(&mykey_path).expect("reader mykey exists");
    assert_eq!(mykey_before.len(), 32, "raw 32-byte X25519 private key");

    let second_offer = td.path().join("offer-2.tnpkg");
    reader.pkg().offer_v1(OfferOptionsV1 {
        group: "default".into(),
        publisher_did: publisher.did().to_string(),
        out_path: second_offer,
        challenge: Some(challenge.clone()),
    })?;
    assert_eq!(
        fs::read(&mykey_path).expect("reader mykey"),
        mykey_before,
        "re-running offer creation reuses the exact existing reader key"
    );

    // The artifact itself is a body-indexed, signed offer package.
    let artifact = fs::read(&offer_path).expect("offer bytes");
    let (manifest, _body) =
        tn_core::tnpkg::read_tnpkg_verified(tn_core::tnpkg::TnpkgSource::Bytes(&artifact))
            .expect("offer artifact passes strict verified read");
    assert_eq!(manifest.kind, tn_core::ManifestKind::Offer);
    assert_eq!(manifest.publisher_identity, reader.did());
    assert_eq!(
        manifest.recipient_identity.as_deref(),
        Some(publisher.did())
    );

    // 3. Publisher absorbs the offer. It lands in pending state without any
    //    recipient mutation.
    let absorb = publisher.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(&offer_path),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(absorb.legacy_status, "offer_stashed");
    assert_eq!(absorb.status(), AbsorbStatus::Stashed);
    let offers_dir = state_root(&publisher).join("offers");
    assert!(offers_dir.is_dir(), "pending offers tree exists");

    // 4. Atomic exact-digest approval, challenge consumption, and promotion.
    let offer_digest = enrollment::offer_digest_of_artifact(&artifact)?;
    let accepted = publisher.pkg().approve_and_reconcile(&offer_digest)?;
    assert_eq!(accepted.offer_digest, offer_digest);
    assert_eq!(accepted.binding.principal.did, reader.did());
    assert_eq!(accepted.binding.principal.audience_did, publisher.did());
    assert_eq!(accepted.binding.principal.group, "default");

    // The reader public key in the accepted binding is exactly the key the
    // reader retained.
    let reader_private: [u8; 32] = mykey_before.as_slice().try_into().expect("32 bytes");
    let reader_public = enrollment::x25519_public_key(&reader_private);
    assert_eq!(accepted.binding.public_key, reader_public);

    // Exact replays converge on the same accepted state.
    let replay = publisher.pkg().approve_and_reconcile(&offer_digest)?;
    assert_eq!(replay.offer_digest, accepted.offer_digest);
    assert_eq!(replay.artifact_digest, accepted.artifact_digest);
    let reconciled = publisher.pkg().reconcile_pending(&offer_digest)?;
    assert_eq!(reconciled.offer_digest, accepted.offer_digest);

    // An unknown digest is not promotable.
    let missing = publisher
        .pkg()
        .approve_and_reconcile(&enrollment::sha256_tagged(b"another-offer"))
        .expect_err("unknown digest cannot be approved");
    assert!(
        missing
            .to_string()
            .starts_with("invalid argument: untrusted_principal:"),
        "got {missing}"
    );

    // 5. Publisher compiles the signed enrollment response for the reader.
    let response_path = td.path().join("response.tnpkg");
    let compiled = publisher
        .pkg()
        .compile_enrolment_v1(CompileEnrolmentOptionsV1 {
            group: "default".into(),
            reader_did: reader.did().to_string(),
            out_path: response_path.clone(),
            accepted_offer: accepted.clone(),
            ttl: Duration::from_secs(600),
        })?;
    assert_eq!(compiled.recipient_did, reader.did());
    let response_artifact = fs::read(&response_path).expect("response bytes");
    let (response_manifest, _) =
        tn_core::tnpkg::read_tnpkg_verified(tn_core::tnpkg::TnpkgSource::Bytes(&response_artifact))
            .expect("response artifact passes strict verified read");
    assert_eq!(response_manifest.kind, tn_core::ManifestKind::Enrolment);
    assert_eq!(
        response_manifest.recipient_identity.as_deref(),
        Some(reader.did())
    );

    let (_, response_body) =
        tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(&response_artifact))?;
    let attacker = tn_core::DeviceKey::generate();
    let mut wrong_outer_signer = response_manifest.clone();
    wrong_outer_signer.publisher_identity = attacker.did().to_string();
    let attacker_signing = ed25519_dalek::SigningKey::from_bytes(&attacker.private_bytes());
    tn_core::tnpkg::sign_manifest_with_body(
        &mut wrong_outer_signer,
        &response_body,
        &attacker_signing,
    )?;
    let wrong_outer_signer =
        tn_core::tnpkg::write_tnpkg_bytes(&wrong_outer_signer, &response_body)?;
    let signer_error = enrollment::read_enrollment_response(&wrong_outer_signer)
        .expect_err("outer and inner publishers must match");
    assert!(signer_error
        .to_string()
        .starts_with("invalid argument: outer_inner_signer_mismatch:"));

    let mut wrong_outer_reader = response_manifest.clone();
    wrong_outer_reader.recipient_identity = Some(attacker.did().to_string());
    let publisher_key = device_key(&publisher);
    let publisher_signing = ed25519_dalek::SigningKey::from_bytes(&publisher_key.private_bytes());
    tn_core::tnpkg::sign_manifest_with_body(
        &mut wrong_outer_reader,
        &response_body,
        &publisher_signing,
    )?;
    let wrong_outer_reader =
        tn_core::tnpkg::write_tnpkg_bytes(&wrong_outer_reader, &response_body)?;
    let reader_error = enrollment::read_enrollment_response(&wrong_outer_reader)
        .expect_err("outer and inner readers must match");
    assert!(reader_error
        .to_string()
        .starts_with("invalid argument: wrong_recipient:"));

    // 6. Reader verifies the accepted response against its retained offer and
    //    installs the publisher into its private trust record.
    let response = enrollment::read_enrollment_response(&response_artifact)?;
    assert_eq!(response.publisher_did, publisher.did());
    assert_eq!(response.reader_did, reader.did());
    assert_eq!(response.accepted_offer_digest, offer_digest);
    let outcome = enrollment::install_publisher_response(
        &reader,
        &response,
        &ResponseExpectation {
            publisher_did: publisher.did().to_string(),
            reader_did: reader.did().to_string(),
            ceremony_id: challenge.ceremony_id.clone(),
            group: "default".into(),
            offer_digest: offer_digest.clone(),
            public_key_sha256: enrollment::sha256_tagged(&reader_public),
            now: std::time::SystemTime::now(),
        },
    )?;
    assert_eq!(outcome.publisher_did, publisher.did());
    let record_path = keystore_dir(&reader)
        .join("trust")
        .join("verified_publishers.v1.json");
    assert_eq!(outcome.record_path, record_path);
    let record: Value =
        serde_json::from_str(&fs::read_to_string(&record_path).expect("read record"))
            .expect("record json");
    let entry = &record["publishers"][publisher.did()];
    assert!(entry.is_object(), "publisher entry installed: {record}");
    assert_eq!(
        entry["accepted_offer_digest"].as_str(),
        Some(offer_digest.as_str())
    );
    assert_eq!(entry["group"].as_str(), Some("default"));

    // A response for a different retained offer is out of scope.
    let mismatch = enrollment::install_publisher_response(
        &reader,
        &response,
        &ResponseExpectation {
            publisher_did: publisher.did().to_string(),
            reader_did: reader.did().to_string(),
            ceremony_id: challenge.ceremony_id.clone(),
            group: "default".into(),
            offer_digest: enrollment::sha256_tagged(b"another-offer"),
            public_key_sha256: enrollment::sha256_tagged(&reader_public),
            now: std::time::SystemTime::now(),
        },
    )
    .expect_err("response for a different offer is rejected");
    assert!(
        mismatch
            .to_string()
            .starts_with("invalid argument: scope_mismatch:"),
        "got {mismatch}"
    );

    publisher.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn tampered_offer_bodies_are_rejected_with_stable_reasons() -> tn_proto::Result<()> {
    let publisher = Tn::ephemeral()?;
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");

    let challenge = publisher.pkg().issue_enrollment_challenge(
        reader.did(),
        "default",
        Duration::from_secs(600),
    )?;
    let offer_path = td.path().join("offer.tnpkg");
    reader.pkg().offer_v1(OfferOptionsV1 {
        group: "default".into(),
        publisher_did: publisher.did().to_string(),
        out_path: offer_path.clone(),
        challenge: Some(challenge),
    })?;
    let artifact = fs::read(&offer_path).expect("offer bytes");

    // Substitute a body member: the signed body index must fail closed.
    // The strict writer refuses to produce such an archive, so zip it raw.
    let (manifest, mut body) =
        tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(&artifact))
            .expect("plain read");
    let package = body.get_mut("body/package.json").expect("package body");
    package.extend_from_slice(b"\n");
    let manifest_json = serde_json::to_vec(&manifest.to_json()).expect("serialize signed manifest");
    let mut members: Vec<(&str, &[u8])> = vec![("manifest.json", manifest_json.as_slice())];
    members.extend(
        body.iter()
            .map(|(name, data)| (name.as_str(), data.as_slice())),
    );
    let tampered = raw_zip(&members);
    let receipt = publisher.pkg().absorb_with_options(
        tn_core::AbsorbSource::Bytes(&tampered),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(receipt.legacy_status, "rejected");
    assert!(
        receipt.legacy_reason.starts_with("body_digest_mismatch:"),
        "got {}",
        receipt.legacy_reason
    );

    // An offer addressed to a different publisher is rejected before any
    // pending mutation.
    let stranger = Tn::ephemeral()?;
    let receipt = stranger.pkg().absorb_with_options(
        tn_core::AbsorbSource::Bytes(&artifact),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(receipt.legacy_status, "rejected");
    assert!(
        receipt.legacy_reason.starts_with("wrong_recipient:"),
        "got {}",
        receipt.legacy_reason
    );
    assert!(
        !state_root(&stranger).join("offers").exists(),
        "no pending mutation for a rejected offer"
    );

    publisher.close()?;
    reader.close()?;
    stranger.close()?;
    Ok(())
}

#[test]
fn unsafe_legacy_import_is_explicit_observable_and_unverified() -> tn_proto::Result<()> {
    let receiver = Tn::ephemeral()?;

    // A legacy package: signed manifest, but no body digest index.
    let device = device_key(&receiver);
    let signing = ed25519_dalek::SigningKey::from_bytes(&device.private_bytes());
    let mut manifest = tn_core::Manifest {
        kind: tn_core::ManifestKind::AdminLogSnapshot,
        version: 1,
        publisher_identity: device.did().to_string(),
        recipient_identity: None,
        ceremony_id: "cer_legacy".into(),
        as_of: "2026-07-11T14:00:00Z".into(),
        scope: "admin".into(),
        clock: std::collections::BTreeMap::new(),
        event_count: 0,
        head_row_hash: None,
        state: None,
        body_sha256: std::collections::BTreeMap::new(),
        body_sha256_present: false,
        manifest_signature_b64: None,
    };
    tn_core::tnpkg::sign_manifest(&mut manifest, &signing).expect("legacy sign");
    let manifest_json = serde_json::to_vec(&manifest.to_json()).expect("serialize legacy manifest");
    let legacy = raw_zip(&[
        ("manifest.json", manifest_json.as_slice()),
        ("body/admin.ndjson", b""),
    ]);

    // Default absorb fails closed on the missing signed body index.
    let rejected = receiver.pkg().absorb_with_options(
        tn_core::AbsorbSource::Bytes(&legacy),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(rejected.legacy_status, "rejected");

    // The named unsafe path imports it as retained-but-unverified material and
    // emits the one structured audit event.
    let stashed = receiver.pkg().absorb_with_options(
        tn_core::AbsorbSource::Bytes(&legacy),
        AbsorbOptionsV1 {
            unsafe_legacy_signer: true,
        },
    )?;
    assert_eq!(stashed.legacy_status, "stashed");
    assert!(
        stashed.legacy_reason.contains("unverified"),
        "got {}",
        stashed.legacy_reason
    );

    let entries = receiver.read(tn_proto::ReadOptions::default())?;
    let audit = entries
        .iter()
        .find(|entry| entry.event_type() == Some("tn.security.unsafe_operation"))
        .expect("one best-effort audit event");
    assert_eq!(
        audit.get("operation").and_then(Value::as_str),
        Some("legacy_package_import")
    );
    assert_eq!(
        audit
            .get("relaxations")
            .and_then(Value::as_array)
            .map(|relaxations| {
                relaxations
                    .iter()
                    .map(|value| value.as_str().unwrap_or_default().to_string())
                    .collect::<Vec<_>>()
            }),
        Some(vec!["legacy_signer_mismatch".to_string()])
    );
    let audit_count = entries
        .iter()
        .filter(|entry| entry.event_type() == Some("tn.security.unsafe_operation"))
        .count();
    assert_eq!(
        audit_count, 1,
        "exactly one audit event per unsafe operation"
    );

    // Offers stay fail-closed even on the unsafe path: security-sensitive
    // version-1 statements never ride the legacy import.
    let publisher = Tn::ephemeral()?;
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");
    let challenge = publisher.pkg().issue_enrollment_challenge(
        reader.did(),
        "default",
        Duration::from_secs(600),
    )?;
    let offer_path = td.path().join("offer.tnpkg");
    reader.pkg().offer_v1(OfferOptionsV1 {
        group: "default".into(),
        publisher_did: publisher.did().to_string(),
        out_path: offer_path.clone(),
        challenge: Some(challenge),
    })?;
    let receipt = receiver.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(&offer_path),
        AbsorbOptionsV1 {
            unsafe_legacy_signer: true,
        },
    )?;
    assert_eq!(
        receipt.legacy_status, "rejected",
        "offers do not enter through the unsafe legacy path"
    );

    receiver.close()?;
    publisher.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn offer_requires_a_real_publisher_did() -> tn_proto::Result<()> {
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");
    let err = reader
        .pkg()
        .offer_v1(OfferOptionsV1 {
            group: "default".into(),
            publisher_did: "did:key:zLabel-publisher".into(),
            out_path: td.path().join("offer.tnpkg"),
            challenge: None,
        })
        .expect_err("placeholder publisher DID is rejected");
    assert!(
        err.to_string()
            .starts_with("invalid argument: did_invalid:"),
        "got {err}"
    );
    reader.close()?;
    Ok(())
}

#[test]
fn unsolicited_offer_stages_pending_but_cannot_self_authorize() -> tn_proto::Result<()> {
    let td = tempfile::tempdir().expect("tempdir");
    // Unsolicited offers scope to the reader's active ceremony id, so this
    // flow uses two devices of one logical ceremony (a foreign publisher's
    // ceremony is reached through its challenge instead).
    let (publisher, reader) = shared_ceremony_pair(td.path());

    // No challenge: the reader proves the key binding, but nothing authorizes
    // the enrollment until an administrator approves the exact digest.
    let offer_path = td.path().join("unsolicited.tnpkg");
    reader.pkg().offer_v1(OfferOptionsV1 {
        group: "default".into(),
        publisher_did: publisher.did().to_string(),
        out_path: offer_path.clone(),
        challenge: None,
    })?;
    let receipt = publisher.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(&offer_path),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(receipt.legacy_status, "offer_stashed");

    let artifact = fs::read(&offer_path).expect("offer bytes");
    let offer_digest = enrollment::offer_digest_of_artifact(&artifact)?;
    let unauthorized = publisher
        .pkg()
        .reconcile_pending(&offer_digest)
        .expect_err("unsolicited offers cannot self-authorize");
    assert!(
        unauthorized
            .to_string()
            .starts_with("invalid argument: untrusted_principal:"),
        "got {unauthorized}"
    );

    // Explicit exact-digest approval promotes it.
    let accepted = publisher.pkg().approve_and_reconcile(&offer_digest)?;
    assert_eq!(accepted.binding.principal.did, reader.did());
    assert_eq!(accepted.binding.challenge_digest, None);

    publisher.close()?;
    reader.close()?;
    Ok(())
}
