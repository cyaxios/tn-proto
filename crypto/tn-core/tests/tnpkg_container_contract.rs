use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use serde_json::Value;
use sha2::Digest;
use tn_core::signing::DeviceKey;
use tn_core::tnpkg::{
    read_tnpkg, read_tnpkg_verified, sign_manifest_with_body, verify_manifest, write_tnpkg,
    write_tnpkg_bytes, BodyContents, Manifest, ManifestKind, TnpkgSource, MAX_PKG_ENTRY_COUNT,
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

fn body_signed_project_seed_manifest(body: &BodyContents) -> Manifest {
    let raw = fs::read_to_string(fixture_dir().join("project_seed_unsigned.json"))
        .expect("read unsigned manifest fixture");
    let doc: Value = serde_json::from_str(&raw).expect("parse unsigned manifest fixture");
    let mut manifest = Manifest::from_json(&doc).expect("parse unsigned project_seed manifest");
    let seed = [23u8; 32];
    let device = DeviceKey::from_private_bytes(&seed).expect("device key");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    manifest.publisher_identity = device.did().to_string();
    manifest.recipient_identity = Some(device.did().to_string());
    sign_manifest_with_body(&mut manifest, body, &signing_key).expect("sign manifest with body");
    manifest
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

fn decode_body_index_case(case_id: &str) -> (Vec<u8>, BodyContents) {
    let case = body_index_case(case_id);
    let manifest = B64_STANDARD
        .decode(
            case["input"]["manifest_b64"]
                .as_str()
                .expect("manifest b64"),
        )
        .expect("decode manifest");
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
    (manifest, body)
}

fn body_index_package(case_id: &str) -> (Vec<u8>, BodyContents) {
    let (manifest, body) = decode_body_index_case(case_id);
    let mut members: Vec<(&str, &[u8])> = vec![("manifest.json", manifest.as_slice())];
    members.extend(
        body.iter()
            .map(|(name, data)| (name.as_str(), data.as_slice())),
    );
    (zip_with_members(&members), body)
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

fn last_eocd_offset(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("EOCD signature")
}

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn archive_with_fake_eocd_comment_and_oversized_directory() -> Vec<u8> {
    let manifest = manifest_json_bytes();
    let mut bytes = zip_with_members(&[("manifest.json", &manifest)]);
    let eocd = last_eocd_offset(&bytes);

    set_u32(&mut bytes, eocd + 12, 16 * 1024 * 1024 + 1);

    let mut comment = [0u8; 26];
    comment[..4].copy_from_slice(b"PK\x05\x06");
    set_u16(&mut comment, 20, u16::MAX);
    set_u16(&mut bytes, eocd + 20, comment.len() as u16);
    bytes.extend_from_slice(&comment);
    bytes
}

fn assert_bytes_preflight_error(bytes: &[u8], reason: &str) {
    let err = read_tnpkg(TnpkgSource::Bytes(bytes)).expect_err("bytes preflight must reject");
    assert!(
        format!("{err:?}").contains(reason),
        "unexpected bytes error: {err:?}"
    );
}

fn assert_path_preflight_error(bytes: &[u8], reason: &str) {
    let td = tempfile::tempdir().expect("tempdir");
    let path = td.path().join("malformed.tnpkg");
    fs::write(&path, bytes).expect("write malformed package");
    let err = read_tnpkg(TnpkgSource::Path(&path)).expect_err("path preflight must reject package");
    assert!(
        format!("{err:?}").contains(reason),
        "unexpected path error: {err:?}"
    );
}

#[test]
fn bytes_preflight_skips_fake_eocd_in_comment_and_rejects_oversized_directory() {
    let bytes = archive_with_fake_eocd_comment_and_oversized_directory();

    assert_bytes_preflight_error(&bytes, "central directory size");
}

#[test]
fn path_preflight_skips_fake_eocd_in_comment_and_rejects_oversized_directory() {
    let bytes = archive_with_fake_eocd_comment_and_oversized_directory();

    assert_path_preflight_error(&bytes, "central directory size");
}

#[test]
fn preflight_rejects_classic_entry_count_before_archive_construction() {
    let manifest = manifest_json_bytes();
    let mut bytes = zip_with_members(&[("manifest.json", &manifest)]);
    let eocd = last_eocd_offset(&bytes);
    let oversized_count = (MAX_PKG_ENTRY_COUNT + 1) as u16;
    set_u16(&mut bytes, eocd + 8, oversized_count);
    set_u16(&mut bytes, eocd + 10, oversized_count);

    assert_bytes_preflight_error(&bytes, "entry count");
    assert_path_preflight_error(&bytes, "entry count");
}

#[test]
fn preflight_explicitly_rejects_zip64_sentinel_metadata() {
    let manifest = manifest_json_bytes();
    let base = zip_with_members(&[("manifest.json", &manifest)]);

    for sentinel_field in [
        "entry count",
        "central directory size",
        "central directory offset",
    ] {
        let mut bytes = base.clone();
        let eocd = last_eocd_offset(&bytes);
        match sentinel_field {
            "entry count" => {
                set_u16(&mut bytes, eocd + 8, u16::MAX);
                set_u16(&mut bytes, eocd + 10, u16::MAX);
            }
            "central directory size" => set_u32(&mut bytes, eocd + 12, u32::MAX),
            "central directory offset" => set_u32(&mut bytes, eocd + 16, u32::MAX),
            _ => unreachable!(),
        }

        assert_bytes_preflight_error(&bytes, "ZIP64");
        assert_path_preflight_error(&bytes, "ZIP64");
    }
}

#[test]
fn preflight_rejects_inconsistent_eocd_and_truncated_directory_metadata() {
    let manifest = manifest_json_bytes();
    let base = zip_with_members(&[("manifest.json", &manifest)]);

    let mut trailing_bytes = base.clone();
    trailing_bytes.extend_from_slice(b"trailing data");
    assert_bytes_preflight_error(&trailing_bytes, "EOCD");
    assert_path_preflight_error(&trailing_bytes, "EOCD");

    let mut truncated_directory = base;
    let eocd = last_eocd_offset(&truncated_directory);
    set_u32(&mut truncated_directory, eocd + 12, 45);
    assert_bytes_preflight_error(&truncated_directory, "central directory metadata");
    assert_path_preflight_error(&truncated_directory, "central directory metadata");
}

#[test]
fn tnpkg_reader_accepts_manifest_and_body_members() {
    let td = tempfile::tempdir().unwrap();
    let pkg = td.path().join("ok.tnpkg");
    let mut body: BodyContents = BTreeMap::new();
    body.insert(
        "body/tn.yaml".into(),
        b"ceremony:\n  id: payroll\n".to_vec(),
    );
    body.insert(
        "body/keys/local.public".into(),
        b"did:key:zBodyIndexedPublisher".to_vec(),
    );
    let manifest = body_signed_project_seed_manifest(&body);

    write_tnpkg(&pkg, &manifest, &body).expect("write valid package");
    let (got_manifest, got_body) =
        read_tnpkg_verified(TnpkgSource::Path(&pkg)).expect("read verified package");

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
fn verified_reader_rejects_duplicate_body_entries() {
    let td = tempfile::tempdir().expect("tempdir");
    let body = BTreeMap::from([("body/payload.bin".into(), b"same bytes".to_vec())]);
    let manifest = body_signed_project_seed_manifest(&body);
    let manifest_json = serde_json::to_vec(&manifest.to_json()).expect("manifest json");
    let bytes = zip_with_members(&[
        ("manifest.json", &manifest_json),
        ("body/payload.bin", b"same bytes"),
        ("body/payload.bin", b"same bytes"),
    ]);
    assert!(
        bytes
            .windows(b"body/payload.bin".len())
            .filter(|window| *window == b"body/payload.bin")
            .count()
            >= 4,
        "fixture must carry duplicate local and central-directory names"
    );

    let err = read_tnpkg_verified(TnpkgSource::Bytes(&bytes))
        .expect_err("duplicate body member rejected");
    assert!(format!("{err:?}").contains("duplicate package member"));

    let path = td.path().join("duplicate-body.tnpkg");
    fs::write(&path, &bytes).expect("write duplicate package");
    let path_err = read_tnpkg_verified(TnpkgSource::Path(&path))
        .expect_err("duplicate body member rejected from path");
    assert!(format!("{path_err:?}").contains("duplicate package member"));
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
fn tnpkg_writers_reject_manifest_signed_for_different_body() {
    let td = tempfile::tempdir().unwrap();
    let signed_body = BTreeMap::from([("body/payload.bin".into(), b"final bytes".to_vec())]);
    let manifest = body_signed_project_seed_manifest(&signed_body);
    let substituted = BTreeMap::from([("body/payload.bin".into(), b"different bytes".to_vec())]);

    let path_err = write_tnpkg(&td.path().join("bad.tnpkg"), &manifest, &substituted)
        .expect_err("path writer rejects mismatched body");
    assert!(format!("{path_err:?}").contains("body_digest_mismatch"));

    let bytes_err = write_tnpkg_bytes(&manifest, &substituted)
        .expect_err("bytes writer rejects mismatched body");
    assert!(format!("{bytes_err:?}").contains("body_digest_mismatch"));
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

    let mut body: BodyContents = BTreeMap::new();
    body.insert("body/encrypted.bin".into(), encrypted.clone());
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
        body_sha256: BTreeMap::new(),
        body_sha256_present: false,
        manifest_signature_b64: None,
    };
    sign_manifest_with_body(&mut manifest, &body, &signing_key).expect("sign manifest");

    write_tnpkg(&pkg, &manifest, &body).expect("write sealed package");

    let (got_manifest, got_body) =
        read_tnpkg_verified(TnpkgSource::Path(&pkg)).expect("read package");
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

#[test]
fn verified_reader_accepts_shared_body_index_fixture() {
    let (bytes, expected_body) = body_index_package("valid_offer_body_index");

    let (manifest, body) =
        read_tnpkg_verified(TnpkgSource::Bytes(&bytes)).expect("read fixture package");

    assert_eq!(manifest.kind, ManifestKind::Offer);
    assert_eq!(body, expected_body);
}

#[test]
fn verified_reader_rejects_shared_body_index_mismatches() {
    for case_id in [
        "substituted_offer_body",
        "missing_indexed_body",
        "extra_unindexed_body",
        "malformed_body_digest",
        "missing_body_index",
    ] {
        let (bytes, _) = body_index_package(case_id);
        let err = read_tnpkg_verified(TnpkgSource::Bytes(&bytes))
            .expect_err("body-index mismatch rejected");
        assert!(
            format!("{err:?}").contains("body_digest_mismatch"),
            "unexpected error for {case_id}: {err:?}"
        );
    }
}

#[test]
fn verified_reader_checks_manifest_signature_before_corrupt_body_bytes() {
    let (mut bytes, body) = body_index_package("manifest_signature_mutated");
    let body_prefix = &body["body/package.json"][..16];
    let offset = bytes
        .windows(body_prefix.len())
        .position(|window| window == body_prefix)
        .expect("find stored body bytes");
    bytes[offset] ^= 0xff;

    let err = read_tnpkg_verified(TnpkgSource::Bytes(&bytes))
        .expect_err("invalid signature rejected before corrupt body");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("manifest signature"),
        "unexpected error: {err:?}"
    );
    assert!(
        !rendered.contains("CRC"),
        "body was read before signature: {err:?}"
    );
}

#[test]
fn verified_reader_rejects_non_object_body_index_before_corrupt_body_bytes() {
    for malformed_index in [Value::Null, Value::Array(Vec::new())] {
        let mut doc: Value = serde_json::from_slice(&manifest_json_bytes()).expect("manifest JSON");
        doc.as_object_mut()
            .expect("manifest object")
            .insert("body_sha256".to_string(), malformed_index);
        let manifest = serde_json::to_vec(&doc).expect("serialize malformed manifest");
        let body = b"untrusted body payload";
        let mut bytes = zip_with_members(&[
            ("manifest.json", manifest.as_slice()),
            ("body/payload.bin", body),
        ]);
        let offset = bytes
            .windows(body.len())
            .position(|window| window == body)
            .expect("find stored body bytes");
        bytes[offset] ^= 0xff;

        let err = read_tnpkg_verified(TnpkgSource::Bytes(&bytes))
            .expect_err("non-object body index rejected before corrupt body");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("body_sha256 must be a JSON object"),
            "unexpected error: {err:?}"
        );
        assert!(
            !rendered.contains("CRC"),
            "body was read before manifest shape validation: {err:?}"
        );
    }
}

#[test]
fn low_level_reader_keeps_named_legacy_unverified_inspection_boundary() {
    let manifest = manifest_json_bytes();
    let bytes = zip_with_members(&[
        ("manifest.json", &manifest),
        ("body/tn.yaml", b"ceremony:\n  id: payroll\n"),
    ]);

    let (got_manifest, got_body) =
        read_tnpkg(TnpkgSource::Bytes(&bytes)).expect("legacy inspection read");

    assert_eq!(got_manifest.kind, ManifestKind::ProjectSeed);
    assert_eq!(got_body["body/tn.yaml"], b"ceremony:\n  id: payroll\n");
}
