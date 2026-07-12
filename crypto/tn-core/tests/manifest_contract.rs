use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use tn_core::signing::DeviceKey;
use tn_core::tnpkg::{
    compute_body_sha256, sign_manifest_with_body, verify_manifest, verify_manifest_body_index,
    BodyContents, Manifest, ManifestKind,
};

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

fn body_index_fixture() -> Value {
    let mut p = fixture_dir();
    p.pop();
    p.push("trust");
    p.push("v1");
    let raw =
        fs::read_to_string(p.join("package_body_index.json")).expect("read body-index fixture");
    serde_json::from_str(&raw).expect("parse body-index fixture")
}

fn body_index_case(case_id: &str) -> Value {
    body_index_fixture()["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .find(|case| case["id"].as_str() == Some(case_id))
        .unwrap_or_else(|| panic!("missing fixture case {case_id}"))
        .clone()
}

fn decode_body_index_case(case_id: &str) -> (Manifest, BodyContents, Vec<u8>) {
    let case = body_index_case(case_id);
    let manifest_bytes = B64_STANDARD
        .decode(
            case["input"]["manifest_b64"]
                .as_str()
                .expect("manifest b64"),
        )
        .expect("decode manifest");
    let manifest_doc: Value = serde_json::from_slice(&manifest_bytes).expect("manifest json");
    let manifest = Manifest::from_json(&manifest_doc).expect("parse manifest");
    let body = case["input"]["body_members_b64"]
        .as_object()
        .expect("body map")
        .iter()
        .map(|(name, encoded)| {
            (
                name.clone(),
                B64_STANDARD
                    .decode(encoded.as_str().expect("body b64"))
                    .expect("decode body"),
            )
        })
        .collect();
    let canonical = B64_STANDARD
        .decode(case["canonical_b64"].as_str().expect("canonical b64"))
        .expect("decode canonical");
    (manifest, body, canonical)
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
fn manifest_rejects_present_non_object_body_index() {
    for malformed_index in [Value::Null, Value::Array(Vec::new())] {
        let mut doc = read_json("project_seed_unsigned.json");
        doc.as_object_mut()
            .expect("fixture is object")
            .insert("body_sha256".to_string(), malformed_index);

        let err = Manifest::from_json(&doc).expect_err("non-object body index rejected");
        assert!(
            format!("{err:?}").contains("body_sha256 must be a JSON object"),
            "unexpected error: {err:?}"
        );
    }
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

#[test]
fn offer_body_index_fixture_exact_digests_signing_bytes_and_signature() {
    let (manifest, body, canonical) = decode_body_index_case("valid_offer_body_index");
    let expected = BTreeMap::from([
        (
            "body/metadata.json".to_string(),
            "sha256:c94350b6169c800eb2fab2666d1caaf7c07b81227da9a49942ce307f187ced99".to_string(),
        ),
        (
            "body/package.json".to_string(),
            "sha256:ccae14e62acb7dcab2e5ad0491d3b40d7fb577b5fedec86543b6c2eeb8e95249".to_string(),
        ),
    ]);

    assert_eq!(manifest.body_sha256, expected);
    assert_eq!(compute_body_sha256(&body).expect("compute index"), expected);
    assert_eq!(manifest.signing_bytes().expect("signing bytes"), canonical);
    verify_manifest(&manifest).expect("fixture signature");
    verify_manifest_body_index(&manifest, &body, true).expect("fixture body index");
}

#[test]
fn offer_body_index_fixture_rejects_every_index_mismatch() {
    for case_id in [
        "substituted_offer_body",
        "missing_indexed_body",
        "extra_unindexed_body",
        "malformed_body_digest",
        "missing_body_index",
    ] {
        let (manifest, body, canonical) = decode_body_index_case(case_id);
        assert_eq!(manifest.signing_bytes().expect("signing bytes"), canonical);
        verify_manifest(&manifest).expect("negative index vector has valid signature");
        let err = verify_manifest_body_index(&manifest, &body, true)
            .expect_err("body-index mismatch rejected");
        assert!(
            format!("{err:?}").contains("body_digest_mismatch"),
            "unexpected error for {case_id}: {err:?}"
        );
    }
}

#[test]
fn sign_manifest_with_body_indexes_final_bytes_before_signing() {
    let seed = [17u8; 32];
    let device = DeviceKey::from_private_bytes(&seed).expect("device key");
    let signing_key = SigningKey::from_bytes(&seed);
    let mut manifest = Manifest::from_json(&read_json("project_seed_unsigned.json"))
        .expect("parse unsigned manifest");
    manifest.publisher_identity = device.did().to_string();
    manifest.recipient_identity = Some(device.did().to_string());
    let body = BTreeMap::from([
        ("body/a.bin".to_string(), b"final stored bytes\0".to_vec()),
        ("body/nested/b.json".to_string(), br#"{"ok":true}"#.to_vec()),
    ]);

    sign_manifest_with_body(&mut manifest, &body, &signing_key).expect("sign with body");

    assert_eq!(manifest.body_sha256, compute_body_sha256(&body).unwrap());
    verify_manifest(&manifest).expect("signed manifest");
}
