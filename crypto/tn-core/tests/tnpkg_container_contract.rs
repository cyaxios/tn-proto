use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use serde_json::Value;
use sha2::Digest;
use tn_core::signing::DeviceKey;
use tn_core::tnpkg::{
    read_tnpkg, sign_manifest, verify_manifest, write_tnpkg, BodyContents, Manifest, ManifestKind,
    TnpkgSource,
};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

fn fixture_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("tests");
    p.push("fixtures");
    p.push("manifest");
    p
}

fn signed_project_seed_manifest() -> Manifest {
    let raw = fs::read_to_string(fixture_dir().join("project_seed_signed.json"))
        .expect("read manifest fixture");
    let doc: Value = serde_json::from_str(&raw).expect("parse manifest fixture");
    Manifest::from_json(&doc).expect("parse signed project_seed manifest")
}

fn manifest_json_bytes() -> Vec<u8> {
    fs::read(fixture_dir().join("project_seed_signed.json")).expect("read manifest fixture")
}

fn zip_with_members(members: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut seen = HashSet::new();
    let mut name_patches: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (name, data) in members {
        let write_name = if seen.insert(*name) {
            (*name).to_owned()
        } else {
            let mut placeholder = (*name).to_owned();
            placeholder.replace_range(0..1, "~");
            name_patches.push((placeholder.as_bytes().to_vec(), name.as_bytes().to_vec()));
            placeholder
        };
        writer
            .start_file(write_name, opts)
            .expect("start zip member");
        writer.write_all(data).expect("write zip member");
    }
    let mut bytes = writer.finish().expect("finish zip").into_inner();
    for (from, to) in name_patches {
        for i in 0..=bytes.len().saturating_sub(from.len()) {
            if bytes[i..i + from.len()] == from {
                bytes[i..i + to.len()].copy_from_slice(&to);
            }
        }
    }
    bytes
}

#[test]
fn tnpkg_reader_accepts_manifest_and_body_members() {
    let td = tempfile::tempdir().unwrap();
    let pkg = td.path().join("ok.tnpkg");
    let manifest = signed_project_seed_manifest();
    let mut body: BodyContents = BTreeMap::new();
    body.insert(
        "body/tn.yaml".into(),
        b"ceremony:\n  id: payroll\n".to_vec(),
    );
    body.insert(
        "body/keys/local.public".into(),
        manifest.publisher_identity.as_bytes().to_vec(),
    );

    write_tnpkg(&pkg, &manifest, &body).expect("write valid package");
    let (got_manifest, got_body) = read_tnpkg(TnpkgSource::Path(&pkg)).expect("read package");

    assert_eq!(got_manifest.kind, ManifestKind::ProjectSeed);
    assert!(got_body.contains_key("body/tn.yaml"));
    assert!(got_body.contains_key("body/keys/local.public"));
}

#[test]
fn tnpkg_reader_rejects_invalid_non_manifest_members() {
    for bad_name in [
        "README.txt",
        "keys/local.private",
        "body/",
        "body/../manifest.json",
        "body\\keys\\local.private",
    ] {
        let manifest = manifest_json_bytes();
        let bytes = zip_with_members(&[("manifest.json", &manifest), (bad_name, b"bad")]);

        let err = read_tnpkg(TnpkgSource::Bytes(&bytes)).expect_err("invalid member rejected");
        assert!(
            format!("{err:?}").contains("invalid package member"),
            "unexpected error for {bad_name:?}: {err:?}"
        );
    }
}

#[test]
fn tnpkg_reader_rejects_duplicate_manifest_entries() {
    let manifest = manifest_json_bytes();
    let bytes = zip_with_members(&[
        ("manifest.json", &manifest),
        ("manifest.json", &manifest),
        ("body/tn.yaml", b"ceremony:\n  id: payroll\n"),
    ]);

    let err = read_tnpkg(TnpkgSource::Bytes(&bytes)).expect_err("duplicate manifest rejected");
    assert!(
        format!("{err:?}").contains("exactly one"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn tnpkg_writer_rejects_invalid_body_members() {
    let td = tempfile::tempdir().unwrap();
    let manifest = signed_project_seed_manifest();
    let mut body: BodyContents = BTreeMap::new();
    body.insert("root.txt".into(), b"bad".to_vec());

    let err =
        write_tnpkg(&td.path().join("bad.tnpkg"), &manifest, &body).expect_err("writer rejects");
    assert!(format!("{err:?}").contains("invalid package member"));
}

#[test]
fn sealed_package_shape_is_manifest_plus_single_encrypted_body_member() {
    let td = tempfile::tempdir().unwrap();
    let pkg = td.path().join("sealed.tnpkg");
    let seed = [9u8; 32];
    let device = DeviceKey::from_private_bytes(&seed).expect("device key");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let encrypted = b"nonce-12byteciphertext-and-tag".to_vec();
    let ciphertext_sha256 = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&encrypted)));

    let mut manifest = Manifest {
        kind: ManifestKind::FullKeystore,
        version: 1,
        publisher_identity: device.did().to_string(),
        recipient_identity: None,
        ceremony_id: "payroll".into(),
        as_of: "2026-05-31T00:00:00.000+00:00".into(),
        scope: "full".into(),
        clock: BTreeMap::new(),
        event_count: 0,
        head_row_hash: None,
        state: Some(serde_json::json!({
            "kind": "full-keystore",
            "body_encryption": {
                "cipher_suite": "aes-256-gcm",
                "nonce_bytes": 12,
                "frame": "tn-encrypted-body-v2-zip",
                "ciphertext_sha256": ciphertext_sha256,
            }
        })),
        manifest_signature_b64: None,
    };
    sign_manifest(&mut manifest, &signing_key).expect("sign manifest");

    let mut body: BodyContents = BTreeMap::new();
    body.insert("body/encrypted.bin".into(), encrypted.clone());
    write_tnpkg(&pkg, &manifest, &body).expect("write sealed package");

    let (got_manifest, got_body) = read_tnpkg(TnpkgSource::Path(&pkg)).expect("read package");
    verify_manifest(&got_manifest).expect("valid manifest signature");
    assert_eq!(got_manifest.kind, ManifestKind::FullKeystore);
    assert_eq!(
        got_body.keys().collect::<Vec<_>>(),
        vec!["body/encrypted.bin"]
    );
    assert_eq!(got_body["body/encrypted.bin"], encrypted);

    let body_encryption = got_manifest
        .state
        .as_ref()
        .and_then(|s| s.get("body_encryption"))
        .expect("body_encryption block");
    assert_eq!(
        body_encryption.get("frame").and_then(Value::as_str),
        Some("tn-encrypted-body-v2-zip")
    );
    assert_eq!(
        body_encryption.get("cipher_suite").and_then(Value::as_str),
        Some("aes-256-gcm")
    );
}
