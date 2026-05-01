//! Tests for the Rust `vault.pull` handler. Builds a sender ceremony,
//! produces a `.tnpkg` snapshot, returns it from a mock vault inbox,
//! then verifies the receiver's `tick_once` absorbs it and persists a
//! cursor at `<yaml_dir>/.tn/admin/vault_pull.cursor.json`.

#![cfg(feature = "fs")]

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tn_core::handlers::vault_pull::{
    VaultInboxClient, VaultInboxItem, VaultPullHandler,
};
use tn_core::runtime_export::ExportOptions;
use tn_core::tnpkg::ManifestKind;

use common::setup_minimal_btn_ceremony;

struct MockInbox {
    inner: Mutex<MockState>,
}

struct MockState {
    pending: Vec<(VaultInboxItem, Vec<u8>)>,
    listed: Vec<Option<String>>,
    downloaded: Vec<String>,
}

impl MockInbox {
    fn new(items: Vec<(VaultInboxItem, Vec<u8>)>) -> Self {
        Self {
            inner: Mutex::new(MockState {
                pending: items,
                listed: vec![],
                downloaded: vec![],
            }),
        }
    }
}

impl VaultInboxClient for MockInbox {
    fn list_incoming(
        &self,
        _did: &str,
        since: Option<&str>,
    ) -> std::result::Result<Vec<VaultInboxItem>, String> {
        let mut g = self.inner.lock().unwrap();
        g.listed.push(since.map(str::to_string));
        // Filter pending by `since` lexicographically, mirroring how
        // the real vault would.
        let out: Vec<VaultInboxItem> = g
            .pending
            .iter()
            .filter(|(item, _)| match (&item.received_at, since) {
                (Some(t), Some(s)) => t.as_str() > s,
                _ => true,
            })
            .map(|(item, _)| item.clone())
            .collect();
        Ok(out)
    }

    fn download(&self, path: &str) -> std::result::Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        g.downloaded.push(path.to_string());
        if let Some((_, bytes)) = g.pending.iter().find(|(item, _)| item.path == path) {
            return Ok(bytes.clone());
        }
        Err(format!("not found: {path}"))
    }
}

#[test]
fn absorbs_inbox_items_and_persists_cursor() {
    // Sender produces one .tnpkg snapshot.
    let sender_root = tempfile::tempdir().unwrap();
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
    let snap_path = sender_root.path().join("out.tnpkg");
    sender_rt
        .export(
            &snap_path,
            ExportOptions {
                kind: Some(ManifestKind::AdminLogSnapshot),
                ..ExportOptions::default()
            },
        )
        .unwrap();
    let snap_bytes = std::fs::read(&snap_path).unwrap();
    drop(sender_rt);

    // Receiver runtime + mock inbox returning the snapshot.
    let receiver_root = tempfile::tempdir().unwrap();
    let recv_cer = setup_minimal_btn_ceremony(receiver_root.path());
    let recv_rt = Arc::new(tn_core::Runtime::init(&recv_cer.yaml_path).unwrap());

    let item = VaultInboxItem {
        path: "/api/v1/inbox/abc/snapshots/cer/2026.tnpkg".into(),
        head_row_hash: Some("sha256:dummy".into()),
        received_at: Some("2026-04-21T12:00:01.000000Z".into()),
        since_marker: None,
    };
    let mock = Arc::new(MockInbox::new(vec![(item, snap_bytes)]));

    let cursor_path: PathBuf = receiver_root
        .path()
        .join(".tn")
        .join("admin")
        .join("vault_pull.cursor.json");
    let h = VaultPullHandler::new(
        "pull",
        "https://api.example.com",
        "proj_xxx",
        recv_rt,
        mock.clone(),
        cursor_path.clone(),
    );

    let n = h.tick_once().unwrap();
    assert_eq!(n, 1, "expected one absorbed snapshot");

    // Cursor file should exist and record the received_at timestamp.
    assert!(cursor_path.exists(), "cursor file should be persisted");
    let cursor: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cursor_path).unwrap()).unwrap();
    assert_eq!(
        cursor.get("last_seen").and_then(|v| v.as_str()).unwrap(),
        "2026-04-21T12:00:01.000000Z"
    );

    // A second tick should pass the cursor as `since` and absorb nothing
    // new (mock returns no items past the cursor).
    let n2 = h.tick_once().unwrap();
    assert_eq!(n2, 0, "second tick should noop");
    let listed = &mock.inner.lock().unwrap().listed;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0], None);
    assert_eq!(listed[1].as_deref(), Some("2026-04-21T12:00:01.000000Z"));
}

#[test]
fn empty_inbox_returns_zero_no_cursor() {
    let receiver_root = tempfile::tempdir().unwrap();
    let recv_cer = setup_minimal_btn_ceremony(receiver_root.path());
    let recv_rt = Arc::new(tn_core::Runtime::init(&recv_cer.yaml_path).unwrap());
    let mock = Arc::new(MockInbox::new(vec![]));
    let cursor_path = receiver_root
        .path()
        .join(".tn")
        .join("admin")
        .join("vault_pull.cursor.json");
    let h = VaultPullHandler::new(
        "pull",
        "https://api.example.com",
        "proj_xxx",
        recv_rt,
        mock,
        cursor_path.clone(),
    );
    assert_eq!(h.tick_once().unwrap(), 0);
    assert!(!cursor_path.exists(), "cursor should not be created on empty");
}
