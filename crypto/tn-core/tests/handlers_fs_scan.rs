//! Tests for the Rust `fs.scan` handler.
//!
//! Builds a sender ceremony, writes one `.tnpkg` snapshot via
//! `Runtime::export`, then drives the receiver's `FsScanHandler` and
//! verifies absorb + archive routing.

#![cfg(feature = "fs")]

mod common;

use std::sync::Arc;

use tn_core::handlers::fs_scan::{FsScanHandler, OnProcessed};
use tn_core::runtime_export::ExportOptions;
use tn_core::tnpkg::ManifestKind;

use common::setup_minimal_btn_ceremony;

#[test]
fn absorbs_dropped_snapshot_and_archives() {
    let sender_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let inbox_root = tempfile::tempdir().unwrap();
    let inbox_dir = inbox_root.path().to_path_buf();
    std::fs::create_dir_all(&inbox_dir).unwrap();

    // Sender runtime — emit some events so a snapshot has content.
    let sender_cer = setup_minimal_btn_ceremony(sender_root.path());
    let sender_rt = tn_core::Runtime::init(&sender_cer.yaml_path).unwrap();
    let mut f = serde_json::Map::new();
    f.insert("note".into(), serde_json::json!("first"));
    sender_rt
        .emit_with(
            "info",
            "order.created",
            f,
            Some("2026-04-21T12:00:00.000000Z"),
            Some("00000000-0000-0000-0000-00000000000a"),
        )
        .unwrap();
    let snap_path = inbox_dir.join("snap.tnpkg");
    sender_rt
        .export(
            &snap_path,
            ExportOptions {
                kind: Some(ManifestKind::AdminLogSnapshot),
                ..ExportOptions::default()
            },
        )
        .unwrap();
    drop(sender_rt);

    // Receiver runtime — fresh ceremony.
    let recv_cer = setup_minimal_btn_ceremony(receiver_root.path());
    let recv_rt = Arc::new(tn_core::Runtime::init(&recv_cer.yaml_path).unwrap());
    let h = FsScanHandler::new("fs", inbox_dir.clone(), recv_rt, OnProcessed::Archive);
    let n = h.tick_once().unwrap();
    assert_eq!(n, 1, "expected exactly one absorbed file");

    // Inbox should now be empty (file was archived).
    let still_inbox = std::fs::read_dir(&inbox_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().and_then(|s| s.to_str()) == Some("tnpkg")
                && e.path().is_file()
        })
        .count();
    assert_eq!(still_inbox, 0, "archived file should have moved");

    // Archive directory should contain it.
    let archive = inbox_dir.join(".processed");
    let archived: Vec<_> = std::fs::read_dir(&archive)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert_eq!(archived.len(), 1, "{archived:?}");
}

#[test]
fn skips_non_tnpkg_files() {
    let inbox = tempfile::tempdir().unwrap();
    std::fs::write(inbox.path().join("foo.txt"), b"junk").unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let recv_cer = setup_minimal_btn_ceremony(receiver_root.path());
    let recv_rt = Arc::new(tn_core::Runtime::init(&recv_cer.yaml_path).unwrap());
    let h = FsScanHandler::new(
        "fs",
        inbox.path().to_path_buf(),
        recv_rt,
        OnProcessed::Archive,
    );
    assert_eq!(h.tick_once().unwrap(), 0);
    // foo.txt should still be there
    assert!(inbox.path().join("foo.txt").exists());
}

#[test]
fn missing_in_dir_returns_zero() {
    let receiver_root = tempfile::tempdir().unwrap();
    let recv_cer = setup_minimal_btn_ceremony(receiver_root.path());
    let recv_rt = Arc::new(tn_core::Runtime::init(&recv_cer.yaml_path).unwrap());
    let h = FsScanHandler::new(
        "fs",
        receiver_root.path().join("does_not_exist"),
        recv_rt,
        OnProcessed::Archive,
    );
    assert_eq!(h.tick_once().unwrap(), 0);
}
