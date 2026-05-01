//! Tests for the Rust `vault.push` handler — exercises the
//! mock-injected HTTP client to verify a signed `.tnpkg` is POSTed
//! to the expected URL with the correct body and idempotency guard.

#![cfg(feature = "fs")]

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tn_core::handlers::vault_push::{VaultPostClient, VaultPushHandler};
use tn_core::tnpkg::{read_tnpkg, ManifestKind, TnpkgSource};

use common::setup_minimal_btn_ceremony;

type RecordedCall = (String, BTreeMap<String, String>, Vec<u8>);

#[derive(Default)]
struct MockClient {
    calls: Mutex<Vec<RecordedCall>>,
}

impl VaultPostClient for MockClient {
    fn post_snapshot(
        &self,
        path: &str,
        query: &BTreeMap<String, String>,
        body: &[u8],
    ) -> std::result::Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push((path.to_string(), query.clone(), body.to_vec()));
        Ok(())
    }
}

#[test]
fn pushes_signed_snapshot_to_mock_endpoint() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(tn_core::Runtime::init(&cer.yaml_path).unwrap());
    let mock = Arc::new(MockClient::default());

    let h = VaultPushHandler::new(
        "push",
        "https://api.example.com",
        "proj_xxx",
        rt,
        mock.clone(),
    );

    let pushed = h.push_snapshot().expect("push");
    assert!(pushed, "first push should ship");
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "exactly one POST expected");
    let (path, query, body) = &calls[0];
    assert!(
        path.starts_with("/api/v1/inbox/"),
        "url path should be vault inbox shape: {path}"
    );
    assert!(path.contains("/snapshots/"));
    assert!(path.ends_with(".tnpkg"));
    assert!(query.contains_key("head_row_hash"));

    // Body parses as a valid signed manifest of kind admin_log_snapshot.
    let (manifest, _body) = read_tnpkg(TnpkgSource::Bytes(body)).unwrap();
    assert_eq!(manifest.kind, ManifestKind::AdminLogSnapshot);
    assert_eq!(manifest.from_did, cer.did);
}

#[test]
fn idempotent_when_head_unchanged() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(tn_core::Runtime::init(&cer.yaml_path).unwrap());
    let mock = Arc::new(MockClient::default());

    let h = VaultPushHandler::new(
        "push",
        "https://api.example.com",
        "proj_xxx",
        rt,
        mock.clone(),
    );

    assert!(h.push_snapshot().unwrap(), "first push should ship");
    assert!(
        !h.push_snapshot().unwrap(),
        "second push with unchanged head should noop"
    );
    let n = mock.calls.lock().unwrap().len();
    assert_eq!(n, 1);
}

#[test]
fn rejects_unknown_trigger() {
    use tn_core::handlers::spec::parse_handler_spec;

    let yaml = "kind: vault.push\n\
                endpoint: https://api.example.com\n\
                project_id: proj_xxx\n\
                trigger: bogus\n";
    let parsed: serde_yml::Value = serde_yml::from_str(yaml).unwrap();
    let spec = parse_handler_spec(&parsed).unwrap();

    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(tn_core::Runtime::init(&cer.yaml_path).unwrap());

    let res = VaultPushHandler::from_spec(&spec, rt);
    assert!(res.is_err(), "bogus trigger should be rejected");
}
