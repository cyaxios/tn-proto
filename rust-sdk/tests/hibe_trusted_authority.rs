//! Trusted HIBE authority surfaces in the Rust SDK: signed authority
//! assertions with monotonic path epochs, pin/update state, scoped reader
//! challenges and proofs, and the fail-closed reader-grant gate with its
//! explicit unsafe plaintext escape hatch.
//!
//! HIBE stays evaluation-only (`tn-bbg` and its pairing stack are unaudited);
//! these tests exercise fail-closed trust behavior, not new primitives. The
//! synthetic MPK below is structurally valid (`version | depth | points`) so
//! depth/digest binding checks run without minting pairing material.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use tn_proto::enrollment::{
    self, GrantReaderOptionsV1, InstallHibeAssertionOptions, KeyBindingProofV1, ProofExpectation,
    TrustReason,
};
use tn_proto::Tn;

const MPK_DEPTH: usize = 3;

fn synthetic_mpk(fill: u8, depth: usize) -> Vec<u8> {
    // Canonical tn-bbg PublicParams frame:
    // version(1) | max_depth(1) | g(48) | g1(48) | g2(96) | g3(96) | hs(96*depth)
    let mut mpk = vec![1u8, depth as u8];
    mpk.extend(std::iter::repeat(fill).take(48 + 48 + 96 + 96 + 96 * depth));
    mpk
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

fn ceremony_id(tn: &Tn) -> String {
    let raw = fs::read_to_string(tn.yaml_path()).expect("read yaml");
    let doc: serde_yml::Value = serde_yml::from_str(&raw).expect("parse yaml");
    doc["ceremony"]["id"]
        .as_str()
        .expect("ceremony.id")
        .to_string()
}

fn device_key(tn: &Tn) -> tn_core::DeviceKey {
    let seed = fs::read(keystore_dir(tn).join("local.private")).expect("read device seed");
    tn_core::DeviceKey::from_private_bytes(&seed).expect("device key")
}

/// A btn ceremony acting as detached HIBE authority: the authority key files
/// exist in the keystore, so assertion issuance and pinning run without the
/// evaluation-only pairing stack.
fn hibe_authority() -> (Tn, Vec<u8>) {
    let tn = Tn::ephemeral().expect("ephemeral ceremony");
    let mpk = synthetic_mpk(0x5A, MPK_DEPTH);
    let keystore = keystore_dir(&tn);
    fs::write(keystore.join("default.hibe.mpk"), &mpk).expect("mpk");
    fs::write(keystore.join("default.hibe.idpath"), b"org/fraud/case-17").expect("idpath");
    fs::write(keystore.join("default.hibe.msk"), [0xAAu8; 32]).expect("msk");
    (tn, mpk)
}

fn authority_assertion_with(
    tn: &Tn,
    mpk: &[u8],
    id_path: &str,
    max_depth: u64,
    path_epoch: u64,
) -> KeyBindingProofV1 {
    let device = device_key(tn);
    let now = SystemTime::now();
    let issued_at = enrollment::canonical_utc_timestamp(now).expect("issued_at");
    let expires_at =
        enrollment::canonical_utc_timestamp(now + Duration::from_secs(600)).expect("expires_at");
    use base64::Engine as _;
    KeyBindingProofV1 {
        version: 1,
        purpose: "hibe-authority".into(),
        subject_did: tn.did().to_string(),
        audience_did: tn.did().to_string(),
        ceremony_id: ceremony_id(tn),
        group: "default".into(),
        issued_at,
        expires_at,
        nonce_b64: base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]),
        binding: json!({
            "algorithm": "TN-BBG-HIBE-BLS12-381",
            "mpk_sha256": enrollment::sha256_tagged(mpk),
            "max_depth": max_depth,
            "id_path": id_path,
            "path_epoch": path_epoch,
        }),
        signature_b64: String::new(),
    }
    .signed(&device)
    .expect("sign assertion")
}

fn trust_reason(err: &tn_proto::Error, reason: TrustReason) -> bool {
    err.to_string()
        .starts_with(&format!("invalid argument: {}:", reason.as_str()))
}

#[test]
fn authority_assertion_issue_install_and_signed_rotation() -> tn_proto::Result<()> {
    let (mut authority, mpk) = hibe_authority();
    let authority_did = authority.did().to_string();
    // Statements are stamped strictly after this instant; verify one second
    // later so freshness never sees an issued-in-the-future statement.
    let now = SystemTime::now() + Duration::from_secs(1);

    // Issue: the authority signs its current MPK, path, and epoch.
    let assertion = authority
        .admin()
        .issue_hibe_authority_assertion("default", Duration::from_secs(600))?;
    assert_eq!(assertion.purpose, "hibe-authority");
    assert_eq!(assertion.subject_did, authority.did());
    assert_eq!(
        assertion.binding["mpk_sha256"].as_str(),
        Some(enrollment::sha256_tagged(&mpk).as_str())
    );
    assert_eq!(
        assertion.binding["id_path"].as_str(),
        Some("org/fraud/case-17")
    );
    assert_eq!(assertion.binding["path_epoch"].as_u64(), Some(0));
    assert_eq!(
        assertion.binding["max_depth"].as_u64(),
        Some(MPK_DEPTH as u64)
    );

    // Install pins authority DID, MPK fingerprint, depth, path, and epoch.
    authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: mpk.clone(),
            assertion: assertion.clone(),
            expected_authority_did: authority_did.clone(),
            now,
        })?;
    let pin_path = keystore_dir(&authority)
        .join("trust")
        .join("hibe_authority.default.v1.json");
    let pin: Value =
        serde_json::from_str(&fs::read_to_string(&pin_path).expect("pin file")).expect("pin json");
    assert_eq!(pin["authority_did"].as_str(), Some(authority.did()));
    assert_eq!(pin["path_epoch"].as_u64(), Some(0));
    assert_eq!(pin["id_path"].as_str(), Some("org/fraud/case-17"));
    assert_eq!(
        pin["mpk_sha256"].as_str(),
        Some(enrollment::sha256_tagged(&mpk).as_str())
    );

    // Exact re-install is an idempotent no-op.
    authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: mpk.clone(),
            assertion: assertion.clone(),
            expected_authority_did: authority_did.clone(),
            now,
        })?;

    // Substituted MPK bytes cannot satisfy the signed digest.
    let err = authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: synthetic_mpk(0x77, MPK_DEPTH),
            assertion: assertion.clone(),
            expected_authority_did: authority_did.clone(),
            now,
        })
        .expect_err("substituted MPK bytes fail the signed digest");
    assert!(trust_reason(&err, TrustReason::BindingInvalid), "got {err}");

    // A signed path rotation returns the next higher epoch and re-pins.
    let update = authority
        .admin()
        .rotate_hibe_path_with_assertion("default", "org/fraud/case-18")?;
    assert_eq!(update.group, "default");
    assert_eq!(update.id_path, "org/fraud/case-18");
    assert_eq!(update.path_epoch, 1);
    assert_eq!(update.assertion.binding["path_epoch"].as_u64(), Some(1));
    let pin: Value =
        serde_json::from_str(&fs::read_to_string(&pin_path).expect("pin file")).expect("pin json");
    assert_eq!(pin["path_epoch"].as_u64(), Some(1));
    assert_eq!(pin["id_path"].as_str(), Some("org/fraud/case-18"));
    assert_eq!(
        fs::read_to_string(keystore_dir(&authority).join("default.hibe.idpath"))
            .expect("idpath file"),
        "org/fraud/case-18",
        "the authority's declared sealing path follows the rotation"
    );

    // Epoch rollback fails closed.
    let rollback = authority_assertion_with(&authority, &mpk, "org/fraud/case-17", 3, 0);
    let err = authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: mpk.clone(),
            assertion: rollback,
            expected_authority_did: authority_did.clone(),
            now,
        })
        .expect_err("epoch rollback fails closed");
    assert!(trust_reason(&err, TrustReason::EpochRollback), "got {err}");

    // A conflicting MPK at the pinned epoch is a conflict, not an update.
    let other_mpk = synthetic_mpk(0x99, MPK_DEPTH);
    let conflict = authority_assertion_with(&authority, &other_mpk, "org/fraud/case-18", 3, 1);
    let err = authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: other_mpk,
            assertion: conflict,
            expected_authority_did: authority_did.clone(),
            now,
        })
        .expect_err("conflicting MPK at the pinned epoch");
    assert!(trust_reason(&err, TrustReason::EpochConflict), "got {err}");

    // The asserted depth must match the encoded MPK depth.
    let depth_lie = authority_assertion_with(&authority, &mpk, "org/fraud", 2, 2);
    let err = authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: mpk.clone(),
            assertion: depth_lie,
            expected_authority_did: authority_did.clone(),
            now,
        })
        .expect_err("asserted depth must match the encoded depth");
    assert!(trust_reason(&err, TrustReason::BindingInvalid), "got {err}");

    // The wrong expected authority never installs.
    let assertion = authority_assertion_with(&authority, &mpk, "org/fraud/case-18", 3, 2);
    let stranger_did = tn_core::DeviceKey::generate().did().to_string();
    let err = authority
        .admin()
        .install_hibe_authority_assertion(InstallHibeAssertionOptions {
            group: "default".into(),
            mpk: mpk.clone(),
            assertion,
            expected_authority_did: stranger_did,
            now,
        })
        .expect_err("the wrong expected authority never installs");
    assert!(
        trust_reason(&err, TrustReason::DidSignerMismatch),
        "got {err}"
    );

    authority.close()?;
    Ok(())
}

#[test]
fn hibe_reader_challenge_and_proof_round_trip() -> tn_proto::Result<()> {
    let (mut authority, _mpk) = hibe_authority();
    let reader = Tn::ephemeral()?;
    let now = SystemTime::now() + Duration::from_secs(1);

    let challenge = authority.admin().issue_hibe_reader_challenge(
        "default",
        reader.did(),
        Duration::from_secs(600),
    )?;
    assert_eq!(challenge.publisher_did, authority.did());
    assert_eq!(challenge.expected_reader_did, reader.did());

    let reader_device = device_key(&reader);
    let proof = enrollment::create_hibe_reader_proof(&challenge, &reader_device, now)
        .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
    assert_eq!(proof.purpose, "hibe-reader");
    assert_eq!(proof.subject_did, reader.did());
    assert_eq!(proof.audience_did, authority.did());
    assert_eq!(
        proof.binding["delivery"].as_str(),
        Some("recipient-seal-v1")
    );

    let principal = enrollment::verify_key_binding_proof(
        &proof,
        &ProofExpectation {
            purpose: "hibe-reader".into(),
            audience_did: authority.did().to_string(),
            ceremony_id: ceremony_id(&authority),
            group: "default".into(),
            now,
        },
        Some(&challenge),
    )
    .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
    assert_eq!(principal.did, reader.did());

    // A different reader cannot produce a proof for this challenge.
    let intruder = tn_core::DeviceKey::generate();
    let err = enrollment::create_hibe_reader_proof(&challenge, &intruder, now)
        .expect_err("challenge names a different reader");
    assert_eq!(err.reason, TrustReason::WrongRecipient);

    authority.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn grant_reader_verified_fails_closed_without_proof_or_real_did() -> tn_proto::Result<()> {
    let (mut authority, _mpk) = hibe_authority();
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");

    let challenge = authority.admin().issue_hibe_reader_challenge(
        "default",
        reader.did(),
        Duration::from_secs(600),
    )?;
    let reader_device = device_key(&reader);
    // Created strictly after the challenge, so the grant's own
    // verification clock never sees a future-issued proof.
    let proof = enrollment::create_hibe_reader_proof(&challenge, &reader_device, SystemTime::now())
        .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;

    // A placeholder DID is a hard error — never an implicit plaintext grant.
    let out_path = td.path().join("grant-stub.tnpkg");
    let err = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: "did:key:zLabel-alice".into(),
            out_path: out_path.clone(),
            id_path: None,
            proof: proof.clone(),
            allow_subauthority: false,
            unsafe_plaintext: false,
        })
        .expect_err("placeholder DID fails closed");
    assert!(trust_reason(&err, TrustReason::DidInvalid), "got {err}");
    assert!(!out_path.exists(), "no artifact for a failed grant");

    // A proof for a different subject cannot authorize the grant.
    let other_did = tn_core::DeviceKey::generate().did().to_string();
    let err = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: other_did,
            out_path: td.path().join("grant-mismatch.tnpkg"),
            id_path: None,
            proof: proof.clone(),
            allow_subauthority: false,
            unsafe_plaintext: false,
        })
        .expect_err("proof subject mismatch fails closed");
    assert!(
        trust_reason(&err, TrustReason::DidSignerMismatch),
        "got {err}"
    );

    // An ancestor path is subtree delegation and needs the explicit opt-in.
    let err = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: reader.did().to_string(),
            out_path: td.path().join("grant-ancestor.tnpkg"),
            id_path: Some("org/fraud".into()),
            proof: proof.clone(),
            allow_subauthority: false,
            unsafe_plaintext: false,
        })
        .expect_err("ancestor grant requires allow_subauthority");
    assert!(err.to_string().contains("allow_subauthority"), "got {err}");

    authority.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn unsafe_plaintext_grant_is_explicit_and_audited() -> tn_proto::Result<()> {
    let (mut authority, _mpk) = hibe_authority();
    let td = tempfile::tempdir().expect("tempdir");

    // The explicit unsafe path emits the one audit event before attempting
    // the grant. This ceremony's `default` group is btn, so the underlying
    // hibe-only mint then refuses — the observability contract holds either
    // way, and no plaintext artifact appears implicitly.
    let stub_proof = {
        let reader = Tn::ephemeral()?;
        let challenge = authority.admin().issue_hibe_reader_challenge(
            "default",
            reader.did(),
            Duration::from_secs(600),
        )?;
        let reader_device = device_key(&reader);
        let proof =
            enrollment::create_hibe_reader_proof(&challenge, &reader_device, SystemTime::now())
                .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
        reader.close()?;
        proof
    };

    let out_path = td.path().join("grant-plaintext.tnpkg");
    let result = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: "did:key:zLabel-legacy".into(),
            out_path,
            id_path: None,
            proof: stub_proof,
            allow_subauthority: false,
            unsafe_plaintext: true,
        });
    assert!(
        result.is_err(),
        "this ceremony's default group is btn; the hibe-only mint refuses"
    );

    let entries = authority.read(tn_proto::ReadOptions::default())?;
    let audits: Vec<_> = entries
        .iter()
        .filter(|entry| entry.event_type() == Some("tn.security.unsafe_operation"))
        .collect();
    assert_eq!(audits.len(), 1, "exactly one best-effort audit event");
    assert_eq!(
        audits[0].get("operation").and_then(Value::as_str),
        Some("hibe_grant")
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
        Some(vec!["plaintext_bearer_delivery".to_string()])
    );

    authority.close()?;
    Ok(())
}

#[test]
fn grant_requires_a_bound_authority_challenge() -> tn_proto::Result<()> {
    use base64::Engine as _;

    let (mut authority, _mpk) = hibe_authority();
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");
    let reader_device = device_key(&reader);
    let now = SystemTime::now();

    // An externally crafted hibe-reader proof with challenge_digest: null is
    // authentic but unauthorized: grants demand an authority-issued challenge.
    let issued_at = enrollment::canonical_utc_timestamp(now).expect("issued_at");
    let expires_at =
        enrollment::canonical_utc_timestamp(now + Duration::from_secs(600)).expect("expires_at");
    let unsolicited = enrollment::KeyBindingProofV1 {
        version: 1,
        purpose: "hibe-reader".into(),
        subject_did: reader.did().to_string(),
        audience_did: authority.did().to_string(),
        ceremony_id: ceremony_id(&authority),
        group: "default".into(),
        issued_at,
        expires_at,
        nonce_b64: base64::engine::general_purpose::STANDARD.encode([0x44u8; 32]),
        binding: json!({
            "algorithm": "Ed25519-did-key",
            "delivery": "recipient-seal-v1",
            "challenge_digest": serde_json::Value::Null,
        }),
        signature_b64: String::new(),
    }
    .signed(&reader_device)
    .expect("sign unsolicited proof");

    let out_path = td.path().join("grant-null-digest.tnpkg");
    let err = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: reader.did().to_string(),
            out_path: out_path.clone(),
            id_path: None,
            proof: unsolicited,
            allow_subauthority: false,
            unsafe_plaintext: false,
        })
        .expect_err("a proof without a bound challenge cannot authorize a grant");
    assert!(
        trust_reason(&err, TrustReason::ChallengeMissing),
        "got {err}"
    );
    assert!(
        err.to_string()
            .contains("must bind an authority-issued challenge"),
        "got {err}"
    );
    assert!(!out_path.exists(), "no artifact for a refused grant");

    authority.close()?;
    reader.close()?;
    Ok(())
}

#[test]
fn grant_challenges_are_one_time() -> tn_proto::Result<()> {
    let (mut authority, _mpk) = hibe_authority();
    let reader = Tn::ephemeral()?;
    let td = tempfile::tempdir().expect("tempdir");

    let challenge = authority.admin().issue_hibe_reader_challenge(
        "default",
        reader.did(),
        Duration::from_secs(600),
    )?;
    let reader_device = device_key(&reader);
    let proof = enrollment::create_hibe_reader_proof(&challenge, &reader_device, SystemTime::now())
        .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;

    // A grant attempt that fails at the mint (this ceremony's default group
    // is btn, so the hibe-only mint refuses) must NOT consume the challenge.
    let consumed_path = {
        let yaml = authority.yaml_path();
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
            .join("consumed")
            .join(format!("{}.json", challenge.challenge_id))
    };
    let err = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: reader.did().to_string(),
            out_path: td.path().join("grant-failed-mint.tnpkg"),
            id_path: None,
            proof: proof.clone(),
            allow_subauthority: false,
            unsafe_plaintext: false,
        })
        .expect_err("btn group cannot mint a hibe grant");
    assert!(
        !trust_reason(&err, TrustReason::ChallengeReplayed),
        "mint failure is not a replay: {err}"
    );
    assert!(
        !consumed_path.exists(),
        "a failed grant never consumes the challenge"
    );

    // Simulate one delivered grant: commit the challenge one-time through the
    // same locked consumed/ machinery the SDK uses.
    let proof_digest = proof
        .digest()
        .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
    let grant_digest = tn_core::trusted_enrollment::hibe_grant_digest(
        &proof_digest,
        reader.did(),
        &challenge.ceremony_id,
        "default",
        "org/fraud/case-17",
    )
    .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
    let store = tn_core::trusted_enrollment::EnrollmentStore::new(
        device_key(&authority),
        ceremony_id(&authority),
        authority.group_names(),
        consumed_path
            .parent()
            .expect("consumed dir")
            .parent()
            .expect("state root")
            .to_path_buf(),
    )
    .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
    store
        .commit_hibe_grant(
            &challenge.challenge_id,
            &tn_core::trusted_enrollment::HibeGrantConsumptionV1 {
                proof_digest,
                grant_digest,
                artifact_digest: enrollment::sha256_tagged(b"delivered-grant"),
            },
            b"delivered-grant",
        )
        .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
    assert!(consumed_path.exists(), "grant consumption is durable");

    // The consumed challenge now rejects every further grant attempt.
    let err = authority
        .admin()
        .grant_reader_verified(GrantReaderOptionsV1 {
            group: "default".into(),
            reader_did: reader.did().to_string(),
            out_path: td.path().join("grant-replayed.tnpkg"),
            id_path: None,
            proof,
            allow_subauthority: false,
            unsafe_plaintext: false,
        })
        .expect_err("a consumed challenge cannot back another grant");
    assert!(
        trust_reason(&err, TrustReason::ChallengeReplayed)
            || trust_reason(&err, TrustReason::ReplayConflict),
        "got {err}"
    );

    authority.close()?;
    reader.close()?;
    Ok(())
}
