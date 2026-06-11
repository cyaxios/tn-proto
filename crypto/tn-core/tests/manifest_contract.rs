use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use tn_core::tnpkg::{verify_manifest, Manifest, ManifestKind};

fn fixture_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("tests");
    p.push("fixtures");
    p.push("manifest");
    p
}

fn read_json(name: &str) -> Value {
    let raw = fs::read_to_string(fixture_dir().join(name)).expect("read manifest fixture");
    serde_json::from_str(&raw).expect("parse manifest fixture")
}

fn read_hex(name: &str) -> String {
    fs::read_to_string(fixture_dir().join(name))
        .expect("read hex fixture")
        .trim()
        .to_string()
}

#[test]
fn manifest_kind_catalog_matches_shared_fixture() {
    let expected = read_json("kinds.json");
    let mut expected: Vec<String> = expected
        .as_array()
        .expect("kinds fixture is array")
        .iter()
        .map(|v| v.as_str().expect("kind is string").to_string())
        .collect();
    let mut got = vec![
        ManifestKind::AdminLogSnapshot.as_str().to_string(),
        ManifestKind::Offer.as_str().to_string(),
        ManifestKind::Enrolment.as_str().to_string(),
        ManifestKind::RecipientInvite.as_str().to_string(),
        ManifestKind::KitBundle.as_str().to_string(),
        ManifestKind::FullKeystore.as_str().to_string(),
        ManifestKind::ContactUpdate.as_str().to_string(),
        ManifestKind::IdentitySeed.as_str().to_string(),
        ManifestKind::ProjectSeed.as_str().to_string(),
        ManifestKind::GroupKeys.as_str().to_string(),
    ];
    expected.sort();
    got.sort();
    assert_eq!(got, expected);
}

#[test]
fn project_seed_manifest_fixture_canonical_bytes() {
    let doc = read_json("project_seed_unsigned.json");
    let manifest = Manifest::from_json(&doc).expect("parse project_seed manifest");

    assert_eq!(manifest.kind, ManifestKind::ProjectSeed);
    assert_eq!(
        manifest.recipient_identity.as_ref(),
        Some(&manifest.publisher_identity)
    );
    assert_eq!(
        manifest
            .state
            .as_ref()
            .and_then(|s| s.get("project"))
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str),
        Some("payroll")
    );

    let got = hex::encode(manifest.signing_bytes().expect("canonical bytes"));
    assert_eq!(got, read_hex("project_seed_unsigned.canonical.hex"));
}

#[test]
fn manifest_signing_bytes_strip_signature_field() {
    let mut doc = read_json("project_seed_unsigned.json");
    let unsigned = Manifest::from_json(&doc)
        .expect("parse unsigned")
        .signing_bytes()
        .expect("unsigned canonical bytes");

    doc.as_object_mut().expect("fixture is object").insert(
        "manifest_signature_b64".to_string(),
        Value::String("not-a-real-signature".into()),
    );
    let signed_shape = Manifest::from_json(&doc)
        .expect("parse signed shape")
        .signing_bytes()
        .expect("signed shape canonical bytes");

    assert_eq!(signed_shape, unsigned);
}

#[test]
fn manifest_missing_required_field_rejected() {
    let mut doc = read_json("project_seed_unsigned.json");
    doc.as_object_mut()
        .expect("fixture is object")
        .remove("publisher_identity");

    assert!(Manifest::from_json(&doc).is_err());
}

#[test]
fn manifest_unknown_kind_rejected() {
    let mut doc = read_json("project_seed_unsigned.json");
    doc.as_object_mut().expect("fixture is object").insert(
        "kind".to_string(),
        Value::String("future_experimental_kind".into()),
    );

    assert!(Manifest::from_json(&doc).is_err());
}

#[test]
fn signed_project_seed_manifest_fixture_verifies() {
    let doc = read_json("project_seed_signed.json");
    let manifest = Manifest::from_json(&doc).expect("parse signed project_seed manifest");

    assert!(manifest.manifest_signature_b64.is_some());
    let got = hex::encode(manifest.signing_bytes().expect("canonical bytes"));
    assert_eq!(got, read_hex("project_seed_signed.canonical.hex"));
    verify_manifest(&manifest).expect("valid manifest signature");
}

#[test]
fn signed_project_seed_manifest_rejects_tampering() {
    let mut doc = read_json("project_seed_signed.json");
    doc.as_object_mut()
        .expect("fixture is object")
        .insert("event_count".to_string(), Value::Number(3.into()));
    let manifest = Manifest::from_json(&doc).expect("parse tampered signed manifest");

    assert!(verify_manifest(&manifest).is_err());
}
