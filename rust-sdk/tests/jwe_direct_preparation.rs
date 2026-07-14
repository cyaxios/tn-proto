//! Direct authenticated JWE binding routes and explicit reader approval.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::{Digest as _, Sha512};
use tn_core::tnpkg::TnpkgSource;
use tn_proto::enrollment::{self, AbsorbOptionsV1};
use tn_proto::{
    ApproveJweActivationOptions, FingerprintPin, JweBindingScope, JweReaderKeyInfo,
    PrepareRecipientOptions, ReadOptions, SealOptions, Tn, TnInitOptions, UnsealOptions,
    VerifiedJweRecipient,
};

#[derive(Clone, Copy)]
enum DirectRoute {
    DidDocument,
    Fingerprint,
}

fn publisher(root: &Path) -> Tn {
    let keystore = root.join(".tn/keys");
    fs::create_dir_all(&keystore).expect("keystore");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x41_u8; 32]).expect("index key");
    let log = root
        .join("main.ndjson")
        .to_string_lossy()
        .replace('\\', "/");
    let yaml = jwe_yaml("cer_direct", device.did(), &log);
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("yaml");
    Tn::init(yaml_path).expect("publisher")
}

fn reader(root: &Path, publisher: &Tn) -> Tn {
    let keystore = root.join(".tn/keys");
    fs::create_dir_all(&keystore).expect("keystore");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x51_u8; 32]).expect("index key");
    let log = publisher.log_path().to_string_lossy().replace('\\', "/");
    let yaml = jwe_yaml("cer_reader", device.did(), &log);
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("yaml");
    Tn::init_with_options(
        yaml_path,
        TnInitOptions {
            skip_ceremony_init_emit: true,
            skip_policy_published_emit: true,
        },
    )
    .expect("reader")
}

fn jwe_yaml(ceremony: &str, did: &str, log: &str) -> String {
    format!(
        "ceremony: {{id: {ceremony}, mode: local, cipher: jwe, protocol_events_location: main_log}}\n\
         logs: {{path: \"{log}\"}}\n\
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
         \x20 secondary:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   recipients: []\n\
         \x20   fields: []\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n"
    )
}

fn keystore(tn: &Tn) -> PathBuf {
    tn.yaml_path()
        .parent()
        .expect("yaml parent")
        .join(".tn/keys")
}

fn binding(
    route: DirectRoute,
    publisher: &Tn,
    reader: &Tn,
    key: &JweReaderKeyInfo,
) -> VerifiedJweRecipient {
    let scope = JweBindingScope {
        audience_did: publisher.did().to_string(),
        ceremony_id: "cer_direct".into(),
        group: "partners".into(),
        now: SystemTime::now(),
        ttl: Duration::from_secs(600),
    };
    match route {
        DirectRoute::DidDocument => did_document_binding(reader, key, scope),
        DirectRoute::Fingerprint => fingerprint_binding(reader, key, scope),
    }
}

fn did_document_binding(
    reader: &Tn,
    key: &JweReaderKeyInfo,
    scope: JweBindingScope,
) -> VerifiedJweRecipient {
    let expected_public = did_key_agreement_public(reader);
    assert_eq!(key.public_key, expected_public);
    let mut multicodec = vec![0xec, 0x01];
    multicodec.extend_from_slice(&expected_public);
    let multibase = format!("z{}", bs58::encode(multicodec).into_string());
    let method = format!("{}#{multibase}", reader.did());
    let document = serde_json::json!({
        "id": reader.did(),
        "verificationMethod": [{
            "id": method,
            "type": "Multikey",
            "controller": reader.did(),
            "publicKeyMultibase": multibase,
        }],
        "keyAgreement": [method],
    });
    VerifiedJweRecipient::from_authenticated_did_document(
        &document,
        reader.did(),
        None,
        scope,
        "did:test authenticated resolver",
        &enrollment::sha256_tagged(b"authenticated resolution result"),
    )
    .expect("DID-document binding")
}

fn did_key_agreement_public(reader: &Tn) -> [u8; 32] {
    let seed: [u8; 32] = fs::read(keystore(reader).join("local.private"))
        .expect("device seed")
        .try_into()
        .expect("32-byte device seed");
    let digest = Sha512::digest(seed);
    let mut private = [0_u8; 32];
    private.copy_from_slice(&digest[..32]);
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    enrollment::x25519_public_key(&private)
}

fn fingerprint_binding(
    reader: &Tn,
    key: &JweReaderKeyInfo,
    scope: JweBindingScope,
) -> VerifiedJweRecipient {
    VerifiedJweRecipient::from_fingerprint_pin(
        reader.did(),
        key.public_key,
        scope,
        FingerprintPin {
            expected_fingerprint: key.public_key_sha256.clone(),
            verified_by: "operator@example.test".into(),
            verification_method: "authenticated video call".into(),
            evidence: "case:jwe-pin-17".into(),
        },
    )
    .expect("fingerprint binding")
}

fn approve(reader: &Tn, publisher: &Tn, binding: &VerifiedJweRecipient) {
    reader
        .pkg()
        .approve_jwe_activation(ApproveJweActivationOptions {
            publisher_did: publisher.did().to_string(),
            ceremony_id: "cer_direct".into(),
            group: "partners".into(),
            binding_digest: binding.binding_digest.clone(),
            x25519_public_key_sha256: binding.public_key_sha256.clone(),
            ttl: Duration::from_secs(600),
        })
        .expect("approve direct activation");
}

fn assert_round_trip(route: DirectRoute) -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);
    let key = match route {
        DirectRoute::DidDocument => reader.pkg().prepare_jwe_did_key_agreement_key("partners")?,
        DirectRoute::Fingerprint => reader.pkg().prepare_jwe_reader_key("partners")?,
    };
    let binding = binding(route, &publisher, &reader, &key);
    let out = temp.path().join("activation");
    let prepared = publisher.pkg().prepare_recipient(
        reader.did(),
        &out,
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into()]),
            verified_bindings: vec![binding.clone()],
            ..PrepareRecipientOptions::default()
        },
    )?;
    assert_activation(&publisher, &reader, &binding, &prepared, &out)?;
    publisher.close()?;
    reader.close()?;
    Ok(())
}

fn assert_activation(
    publisher: &Tn,
    reader: &Tn,
    binding: &VerifiedJweRecipient,
    prepared: &tn_proto::PrepareRecipientResult,
    out: &Path,
) -> tn_proto::Result<()> {
    let activation = &prepared.jwe_activations[0];
    assert_eq!(activation.binding_digest, binding.binding_digest);
    assert_eq!(
        activation.x25519_public_key_sha256,
        binding.public_key_sha256
    );
    let response = enrollment::read_enrollment_response(&fs::read(&activation.package.path)?)?;
    assert_eq!(response.group_epoch, 0);
    assert_public_only(
        &activation.package.path,
        &fs::read(keystore(reader).join("partners.jwe.mykey"))?,
    );
    assert_registry(publisher, binding)?;
    approve(reader, publisher, binding);
    let expectation_path = keystore(reader).join("trust/jwe_activation_expectations.v1.json");
    let first_approval = fs::read(&expectation_path)?;
    approve(reader, publisher, binding);
    assert_eq!(fs::read(expectation_path)?, first_approval);
    let receipt = reader.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(&activation.package.path),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(receipt.legacy_status, "enrolment_applied");
    assert_crypto_round_trip(publisher, reader)?;
    assert_eq!(fs::read_dir(out)?.count(), 1);
    Ok(())
}

fn assert_registry(publisher: &Tn, binding: &VerifiedJweRecipient) -> tn_proto::Result<()> {
    let path = keystore(publisher).join("trust/jwe_recipients.v1.json");
    let registry: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let entry = &registry["recipients"]["partners"][&binding.reader_did];
    assert_eq!(entry["binding_digest"], binding.binding_digest);
    assert_eq!(entry["evidence_kind"], binding.evidence.kind());
    assert_eq!(entry["evidence"]["kind"], binding.evidence.kind());
    Ok(())
}

fn assert_crypto_round_trip(publisher: &Tn, reader: &Tn) -> tn_proto::Result<()> {
    let sealed = publisher.seal(
        "message.local.v1",
        serde_json::json!({"message": "direct binding"}),
        SealOptions::default(),
    )?;
    let opened = reader.unseal(
        &sealed.wire,
        UnsealOptions {
            as_recipient: Some(keystore(reader)),
            group: "partners".into(),
            ..UnsealOptions::default()
        },
    )?;
    assert_eq!(opened.plaintext["partners"]["message"], "direct binding");
    publisher.info(
        "message.sent",
        serde_json::json!({"message": "secure read"}),
    )?;
    let rows = reader.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    let row = rows
        .iter()
        .find(|row| row.event_type() == Some("message.sent"))
        .expect("read row");
    assert_eq!(row.get("message"), Some(&serde_json::json!("secure read")));
    Ok(())
}

fn assert_public_only(path: &Path, private: &[u8]) {
    let (_, body) = tn_core::tnpkg::read_tnpkg_verified(TnpkgSource::Path(path)).expect("package");
    for (name, bytes) in body {
        assert!(!name.ends_with(".jwe.mykey"), "private-key entry: {name}");
        assert_ne!(bytes, private, "raw JWE private key in {name}");
    }
}

#[test]
fn did_document_route_seals_unseals_and_secure_reads() -> tn_proto::Result<()> {
    assert_round_trip(DirectRoute::DidDocument)
}

#[test]
fn fingerprint_route_seals_unseals_and_secure_reads() -> tn_proto::Result<()> {
    assert_round_trip(DirectRoute::Fingerprint)
}

#[test]
fn unsolicited_direct_activation_requires_explicit_reader_approval() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);
    let key = reader.pkg().prepare_jwe_reader_key("partners")?;
    let binding = binding(DirectRoute::Fingerprint, &publisher, &reader, &key);
    let prepared = publisher.pkg().prepare_recipient(
        reader.did(),
        temp.path().join("activation"),
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into()]),
            verified_bindings: vec![binding.clone()],
            ..PrepareRecipientOptions::default()
        },
    )?;
    let path = &prepared.jwe_activations[0].package.path;
    let rejected = reader.pkg().absorb_with_options(
        tn_core::AbsorbSource::Path(path),
        AbsorbOptionsV1::default(),
    )?;
    assert_eq!(rejected.legacy_status, "rejected");
    assert!(
        rejected.legacy_reason.contains("scope_mismatch:"),
        "unexpected rejection: {}",
        rejected.legacy_reason
    );
    approve(&reader, &publisher, &binding);
    assert_eq!(
        reader
            .pkg()
            .absorb_with_options(
                tn_core::AbsorbSource::Path(path),
                AbsorbOptionsV1::default(),
            )?
            .legacy_status,
        "enrolment_applied"
    );
    Ok(())
}

#[test]
fn preparation_rejects_missing_duplicate_and_conflicting_sources() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);
    let key = reader.pkg().prepare_jwe_reader_key("partners")?;
    let binding = binding(DirectRoute::Fingerprint, &publisher, &reader, &key);
    let missing = temp.path().join("missing");
    let error = publisher
        .pkg()
        .prepare_recipient(
            reader.did(),
            &missing,
            PrepareRecipientOptions {
                groups: Some(vec!["partners".into()]),
                ..PrepareRecipientOptions::default()
            },
        )
        .expect_err("missing source");
    assert!(error
        .to_string()
        .contains("requires exactly one verified JWE binding source"));
    assert!(!missing.exists());
    let duplicate = temp.path().join("duplicate");
    let error = publisher
        .pkg()
        .prepare_recipient(
            reader.did(),
            &duplicate,
            PrepareRecipientOptions {
                groups: Some(vec!["partners".into()]),
                verified_bindings: vec![binding.clone(), binding.clone()],
                ..PrepareRecipientOptions::default()
            },
        )
        .expect_err("duplicate source");
    assert!(error
        .to_string()
        .contains("received multiple verified JWE binding sources"));
    assert!(!duplicate.exists());
    publisher
        .admin()
        .register_jwe_raw_unsafe("partners", reader.did(), [0x99; 32], true)?;
    let conflict = temp.path().join("conflict");
    assert!(publisher
        .pkg()
        .prepare_recipient(
            reader.did(),
            &conflict,
            PrepareRecipientOptions {
                groups: Some(vec!["partners".into()]),
                verified_bindings: vec![binding],
                ..PrepareRecipientOptions::default()
            },
        )
        .is_err());
    assert!(!conflict.exists());
    Ok(())
}

#[test]
fn malformed_trust_registry_never_activates_recipient_key() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);
    let key = reader.pkg().prepare_jwe_reader_key("partners")?;
    let binding = binding(DirectRoute::Fingerprint, &publisher, &reader, &key);
    let trust = keystore(&publisher).join("trust");
    fs::create_dir_all(&trust)?;
    fs::write(trust.join("jwe_recipients.v1.json"), b"not-json")?;

    let out = temp.path().join("malformed");
    let result = publisher.pkg().prepare_recipient(
        reader.did(),
        &out,
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into()]),
            verified_bindings: vec![binding],
            ..PrepareRecipientOptions::default()
        },
    );
    assert!(result.is_err());
    assert!(!out.exists());
    assert!(!keystore(&publisher)
        .join("partners.jwe.recipients")
        .exists());
    Ok(())
}

#[test]
fn zero_activation_ttl_fails_before_output_writes() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);
    let key = reader.pkg().prepare_jwe_reader_key("partners")?;
    let binding = binding(DirectRoute::Fingerprint, &publisher, &reader, &key);
    let out = temp.path().join("zero-ttl");

    let result = publisher.pkg().prepare_recipient(
        reader.did(),
        &out,
        PrepareRecipientOptions {
            groups: Some(vec!["partners".into()]),
            verified_bindings: vec![binding],
            activation_ttl: Duration::ZERO,
            ..PrepareRecipientOptions::default()
        },
    );

    assert!(result.is_err());
    assert!(!out.exists());
    Ok(())
}

#[test]
fn existing_non_did_derived_reader_key_fails_closed() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);
    fs::write(keystore(&reader).join("partners.jwe.mykey"), [0x99_u8; 32])?;

    let error = reader
        .pkg()
        .prepare_jwe_did_key_agreement_key("partners")
        .expect_err("unrelated existing JWE key must not impersonate the reader DID");

    assert!(error.to_string().contains("does not match"));
    Ok(())
}

#[test]
fn default_reader_keys_are_independent_per_group() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);

    let partners = reader.pkg().prepare_jwe_reader_key("partners")?;
    let secondary = reader.pkg().prepare_jwe_reader_key("secondary")?;

    assert_ne!(partners.public_key, secondary.public_key);
    Ok(())
}

#[test]
fn did_key_agreement_preparation_reuses_exact_derived_key() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let publisher = publisher(&temp.path().join("publisher"));
    let reader = reader(&temp.path().join("reader"), &publisher);

    let first = reader.pkg().prepare_jwe_did_key_agreement_key("partners")?;
    let stored = fs::read(keystore(&reader).join("partners.jwe.mykey"))?;
    let second = reader.pkg().prepare_jwe_did_key_agreement_key("partners")?;

    assert_eq!(first, second);
    assert_eq!(
        fs::read(keystore(&reader).join("partners.jwe.mykey"))?,
        stored
    );
    assert_eq!(first.public_key, did_key_agreement_public(&reader));
    Ok(())
}
