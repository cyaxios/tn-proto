//! Tests for the Rust `fs.drop` handler.
//!
//! Mirrors `python/tests/test_fs_drop_handler.py`. Verifies the
//! handler emits a signed `.tnpkg` to the configured `out_dir`, that
//! the filename template substitutes, and that the `on:` allowlist
//! filters event types.

#![cfg(feature = "fs")]

mod common;

use std::sync::Arc;

use serde_json::json;
use tn_core::handlers::fs_drop::{FsDropHandler, DEFAULT_FILENAME_TEMPLATE};
use tn_core::handlers::TnHandler;
use tn_core::tnpkg::{read_tnpkg, ManifestKind, TnpkgSource};

use common::setup_minimal_btn_ceremony;

#[test]
fn drops_signed_snapshot_on_admin_event() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(tn_core::Runtime::init(&cer.yaml_path).unwrap());
    let outbox = td.path().join("outbox");

    let h = FsDropHandler::new("fd", outbox.clone(), rt.clone(), None);
    let env = json!({"event_type": "tn.recipient.added", "did": cer.did.clone()});
    h.emit(&env, b"");

    let mut files: Vec<_> = std::fs::read_dir(&outbox)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("tnpkg"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 1, "{files:?}");

    let bytes = std::fs::read(&files[0]).unwrap();
    let (manifest, _body) = read_tnpkg(TnpkgSource::Bytes(&bytes)).unwrap();
    assert_eq!(manifest.kind, ManifestKind::AdminLogSnapshot);
    assert!(manifest.head_row_hash.is_some(), "head_row_hash should be set");
    // The default template includes the short head hash; verify it appears in
    // the filename.
    let head = manifest.head_row_hash.as_ref().unwrap();
    let short = head
        .strip_prefix("sha256:")
        .unwrap_or(head)
        .chars()
        .take(12)
        .collect::<String>();
    let fname = files[0].file_name().unwrap().to_string_lossy().to_string();
    assert!(
        fname.contains(&short),
        "expected filename {fname} to contain short hash {short}"
    );
    assert!(fname.starts_with("snapshot_"));
}

#[test]
fn idempotent_when_head_unchanged() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(tn_core::Runtime::init(&cer.yaml_path).unwrap());
    let outbox = td.path().join("outbox");

    let h = FsDropHandler::new("fd", outbox.clone(), rt, None);
    let env = json!({"event_type": "tn.recipient.added"});
    h.emit(&env, b"");
    h.emit(&env, b""); // head hasn't advanced, expect no second file

    let n = std::fs::read_dir(&outbox)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().and_then(|s| s.to_str()) == Some("tnpkg")
        })
        .count();
    assert_eq!(n, 1, "second emit should not duplicate when head unchanged");
}

#[test]
fn allowlist_filters_event_types() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(tn_core::Runtime::init(&cer.yaml_path).unwrap());
    let outbox = td.path().join("outbox");
    let h = FsDropHandler::new(
        "fd",
        outbox.clone(),
        rt,
        Some(vec!["tn.recipient.added".into()]),
    );
    assert!(h.accepts(&json!({"event_type": "tn.recipient.added"})));
    assert!(!h.accepts(&json!({"event_type": "tn.recipient.revoked"})));
    assert!(!h.accepts(&json!({"event_type": "user.signup"})));
}

#[test]
fn default_filename_template_round_trip() {
    // Sanity: the public constant matches the documented value.
    assert_eq!(
        DEFAULT_FILENAME_TEMPLATE,
        "snapshot_{ceremony_id}_{date}_{head_row_hash:short}.tnpkg"
    );
}
