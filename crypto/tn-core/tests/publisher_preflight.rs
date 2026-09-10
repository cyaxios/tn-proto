use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;
use tn_core::cipher::{
    btn::{BtnPublisherCipher, BtnReaderCipher},
    hibe::HibePlaceholder,
    GroupCipher, PublicationCapability,
};
use tn_core::governed::{Governance, GovernedDraft, GovernedReader, GovernedWriter};
use tn_core::{DeviceKey, Result};

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## output\n### instruction\nCreate the approved output.\n### use_for\nApproved processing.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

fn btn_material() -> (BtnPublisherCipher, BtnReaderCipher) {
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
    let kit = state.mint().unwrap().to_bytes();
    (
        BtnPublisherCipher::from_state(state),
        BtnReaderCipher::from_kit_bytes(&kit).unwrap(),
    )
}

// A pre-existing external implementation: real BTN encryption and no
// publication_capability override. Count only encryption to catch a preflight
// implementation that probes by encrypting a dummy payload.
struct LegacyCipher {
    inner: BtnPublisherCipher,
    encryptions: AtomicUsize,
}

impl GroupCipher for LegacyCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encryptions.fetch_add(1, Ordering::SeqCst);
        self.inner.encrypt(plaintext)
    }

    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.encryptions.fetch_add(1, Ordering::SeqCst);
        self.inner.encrypt_with_aad(plaintext, aad)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(ciphertext)
    }

    fn kind(&self) -> &'static str {
        "legacy-btn"
    }
}

#[test]
fn missing_output_groups_are_reported_together_with_automatic_governance() {
    let device = DeviceKey::generate();
    let writer = GovernedWriter::new(&device);
    let report = writer.check_groups(["reply", "audit", "reply"]).unwrap();
    assert_eq!(report.required_groups(), ["audit", "reply", "tn.agents"]);
    assert_eq!(report.missing_groups(), ["audit", "reply", "tn.agents"]);
    assert!(!report.is_ready());
    let error = writer.require_groups(["reply", "audit"]).unwrap_err();
    for group in ["audit", "reply", "tn.agents"] {
        assert!(error.to_string().contains(group), "{error}");
    }
    assert_eq!(
        writer
            .check_groups([] as [&str; 0])
            .unwrap()
            .missing_groups(),
        ["tn.agents"]
    );
}

#[test]
fn preflight_reports_every_failure_category_without_trial_encryption() {
    let device = DeviceKey::generate();
    let (publisher, reader) = btn_material();
    let legacy = Arc::new(LegacyCipher {
        inner: btn_material().0,
        encryptions: AtomicUsize::new(0),
    });
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", Arc::new(publisher), &[1; 32])
        .unwrap()
        .with_group("reader", Arc::new(reader), &[2; 32])
        .unwrap()
        .with_group("disabled", Arc::new(HibePlaceholder), &[3; 32])
        .unwrap()
        .with_group("legacy", legacy.clone(), &[4; 32])
        .unwrap();
    let names = ["missing_b", "reader", "legacy", "missing_a", "disabled"];
    let report = writer.check_groups(names).unwrap();
    assert_eq!(report.supported_groups(), ["tn.agents"]);
    assert_eq!(report.missing_groups(), ["missing_a", "missing_b"]);
    assert_eq!(report.unavailable_groups(), ["disabled", "reader"]);
    assert_eq!(report.unknown_groups(), ["legacy"]);
    assert!(!report.is_ready());
    let error = writer.require_groups(names).unwrap_err();
    for group in names {
        assert!(error.to_string().contains(group), "{error}");
    }
    assert_eq!(legacy.encryptions.load(Ordering::SeqCst), 0);
}

#[test]
fn reader_only_material_fails_explicit_startup_validation() {
    let device = DeviceKey::generate();
    let (publisher, reader) = btn_material();
    assert_eq!(
        publisher.publication_capability(),
        PublicationCapability::Supported
    );
    assert_eq!(
        reader.publication_capability(),
        PublicationCapability::Unsupported
    );
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", Arc::new(publisher), &[1; 32])
        .unwrap()
        .with_group("reply", Arc::new(reader), &[2; 32])
        .unwrap();
    assert_eq!(
        writer.check_groups(["reply"]).unwrap().unavailable_groups(),
        ["reply"]
    );
    assert!(writer.require_groups(["reply"]).is_err());
    assert!(writer.require_groups([] as [&str; 0]).is_ok());
}

#[test]
fn unknown_external_cipher_remains_usable_by_the_existing_seal_api() {
    let device = DeviceKey::generate();
    let (publisher, reader) = btn_material();
    let legacy = Arc::new(LegacyCipher {
        inner: publisher,
        encryptions: AtomicUsize::new(0),
    });
    assert_eq!(
        legacy.publication_capability(),
        PublicationCapability::Unknown
    );
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", legacy.clone(), &[1; 32])
        .unwrap()
        .with_group("reply", legacy.clone(), &[2; 32])
        .unwrap();
    let report = writer.check_groups(["reply"]).unwrap();
    assert_eq!(report.unknown_groups(), ["reply", "tn.agents"]);
    assert!(writer.require_groups(["reply"]).is_err());
    assert_eq!(legacy.encryptions.load(Ordering::SeqCst), 0);
    let policy = Governance::from_markdown(device.did(), POLICY, "agents.md", "output").unwrap();
    let object = writer
        .seal(
            GovernedDraft::new("output", policy)
                .unwrap()
                .group("reply", json!({"ok": true}))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(legacy.encryptions.load(Ordering::SeqCst), 2);
    let reader = Arc::new(reader);
    let reader = GovernedReader::new()
        .with_group("tn.agents", reader.clone())
        .unwrap()
        .with_group("reply", reader)
        .unwrap();
    let admitted = reader
        .governance(&object)
        .unwrap()
        .authorize("process", |_, _| Ok(true))
        .unwrap();
    assert_eq!(
        reader.open(&admitted, ["reply"]).unwrap().groups()["reply"]["ok"],
        true
    );
}

#[test]
fn ready_checks_accept_owned_names_and_deduplicate_governance() {
    let device = DeviceKey::generate();
    let publisher = Arc::new(btn_material().0);
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", publisher.clone(), &[1; 32])
        .unwrap()
        .with_group("reply", publisher, &[2; 32])
        .unwrap();
    let names = vec!["tn.agents".to_owned(), "reply".to_owned()];
    let report = writer.check_groups(&names).unwrap();
    assert_eq!(report.required_groups(), ["reply", "tn.agents"]);
    assert_eq!(report.supported_groups(), ["reply", "tn.agents"]);
    assert!(report.is_ready());
    writer.require_groups(names).unwrap();
    for invalid in ["", "tn.other", "tn_aad", "bad name"] {
        assert!(writer.check_groups([invalid]).is_err());
        assert!(writer.require_groups([invalid]).is_err());
    }
}

#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
#[test]
fn jwe_rejects_noncontributory_recipient_points_before_publication_preflight() {
    use curve25519_dalek::{constants::EIGHT_TORSION, montgomery::MontgomeryPoint};
    use tn_core::cipher::jwe::JweCipher;

    let valid = MontgomeryPoint::mul_base_clamped([51; 32]).to_bytes();
    let mut low_order: Vec<_> = EIGHT_TORSION
        .iter()
        .map(|point| point.to_montgomery().to_bytes())
        .collect();
    // Include the twist's low-order point -1, plus noncanonical encodings
    // of zero and one accepted by X25519 input decoding.
    for first in [0xec, 0xed, 0xee] {
        let mut alias = [0xff; 32];
        alias[0] = first;
        alias[31] = 0x7f;
        low_order.push(alias);
    }
    for point in low_order {
        // The high input bit is ignored by X25519, so both forms must fail.
        for high_bit in [0, 0x80] {
            let mut encoded = point;
            encoded[31] |= high_bit;
            for recipients in [vec![encoded], vec![valid, encoded]] {
                assert!(
                    matches!(JweCipher::new("reply", &recipients, &[]), Err(tn_core::Error::InvalidConfig(_))),
                    "invalid recipient material must fail before a writer can report readiness: {encoded:?}"
                );
            }
        }
    }
}

#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
#[test]
fn jwe_preflight_accepts_contributory_recipients_and_x25519_high_bit_aliases() {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use tn_core::cipher::jwe::JweCipher;

    for private in [[0; 32], [23; 32], [255; 32]] {
        let public = MontgomeryPoint::mul_base_clamped(private).to_bytes();
        let mut alias = public;
        alias[31] |= 0x80;
        let publisher = JweCipher::new("reply", &[public, alias], &[]).unwrap();
        assert_eq!(
            publisher.publication_capability(),
            PublicationCapability::Supported
        );
        let ciphertext = publisher
            .encrypt_with_aad(b"reply", b"governance marker")
            .unwrap();
        let reader = JweCipher::new("reply", &[], &[private]).unwrap();
        assert_eq!(
            reader
                .decrypt_with_aad(&ciphertext, b"governance marker")
                .unwrap(),
            b"reply"
        );
    }
}

#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
#[test]
fn jwe_requires_recipients_for_publication_even_when_reader_keys_are_present() {
    use tn_core::cipher::jwe::JweCipher;
    let device = DeviceKey::generate();
    let private = [51; 32];
    let public =
        curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(private).to_bytes();
    let publisher = JweCipher::new("tn.agents", &[public], &[]).unwrap();
    let reader = JweCipher::new("reader", &[], &[private]).unwrap();
    let empty = JweCipher::new("empty", &[], &[]).unwrap();
    assert_eq!(
        publisher.publication_capability(),
        PublicationCapability::Supported
    );
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", Arc::new(publisher), &[1; 32])
        .unwrap()
        .with_group("reader", Arc::new(reader), &[2; 32])
        .unwrap()
        .with_group("empty", Arc::new(empty), &[3; 32])
        .unwrap();
    assert_eq!(
        writer
            .check_groups(["reader", "empty"])
            .unwrap()
            .unavailable_groups(),
        ["empty", "reader"]
    );
    assert!(writer.require_groups(["reader"]).is_err());
    assert!(writer.require_groups([] as [&str; 0]).is_ok());
}

#[cfg(feature = "hibe")]
#[test]
fn hibe_public_parameters_allow_publication_without_secret_keys() {
    use rand_core::OsRng;
    use tn_core::cipher::hibe::HibeCipher;
    use tn_hibe::{keygen, setup, Identity};

    let device = DeviceKey::generate();
    let (pp, msk) = setup(2, OsRng).unwrap();
    let key = keygen(&pp, &msk, &Identity::from_str_path("reply"), OsRng).unwrap();
    let publisher = HibeCipher::new(&pp.to_bytes(), "rules", None, None, vec![], vec![]).unwrap();
    let reader = HibeCipher::new(
        &pp.to_bytes(),
        "reply",
        Some(key.to_bytes()),
        None,
        vec![],
        vec![],
    )
    .unwrap();
    let too_deep = HibeCipher::new(&pp.to_bytes(), "a/b/c", None, None, vec![], vec![]).unwrap();
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", Arc::new(publisher), &[1; 32])
        .unwrap()
        .with_group("reply", Arc::new(reader), &[2; 32])
        .unwrap()
        .with_group("too_deep", Arc::new(too_deep), &[3; 32])
        .unwrap();
    assert!(writer.check_groups(["reply"]).unwrap().is_ready());
    writer.require_groups(["reply"]).unwrap();
    assert_eq!(
        writer
            .check_groups(["too_deep"])
            .unwrap()
            .unavailable_groups(),
        ["too_deep"]
    );
}

#[cfg(all(
    feature = "fs",
    any(not(feature = "native-jwe"), target_arch = "wasm32")
))]
#[test]
fn unavailable_jwe_build_reports_unsupported() {
    assert_eq!(
        tn_core::cipher::jwe::JweCipher.publication_capability(),
        PublicationCapability::Unsupported
    );
}
