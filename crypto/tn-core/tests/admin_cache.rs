//! Integration tests for `AdminStateCache`.

#![cfg(feature = "fs")]

mod common;

use std::sync::Arc;

use tn_core::{AdminStateCache, Runtime};

fn cache_for(rt: &Arc<Runtime>) -> AdminStateCache {
    AdminStateCache::from_runtime_arc(rt).unwrap()
}

#[test]
fn empty_cache_starts_at_offset_zero() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    let mut cache = cache_for(&rt);
    let _state = cache.state().unwrap();
    // ceremony.init was emitted on init, so at_offset should reflect at
    // least one admin event after refresh.
    assert!(cache.at_offset() >= 1);
}

#[test]
fn cache_state_matches_admin_state_after_add() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());

    rt.admin_add_recipient(
        "default",
        &td.path().join("kA.btn.mykit"),
        Some("did:key:zRecipientA"),
    )
    .unwrap();

    let mut cache = cache_for(&rt);
    let state = cache.state().unwrap();
    let recipients = state.get("recipients").unwrap().as_array().unwrap();
    assert!(recipients
        .iter()
        .any(|r| r.get("recipient_did").and_then(|v| v.as_str())
            == Some("did:key:zRecipientA")));
}

#[test]
fn revoke_marks_recipient_revoked_in_cache() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());

    let leaf = rt
        .admin_add_recipient(
            "default",
            &td.path().join("kA.btn.mykit"),
            Some("did:key:zRecipientA"),
        )
        .unwrap();
    rt.admin_revoke_recipient("default", leaf).unwrap();

    let mut cache = cache_for(&rt);
    let _ = cache.state().unwrap();
    let recipients = cache.recipients("default", true).unwrap();
    let row = recipients
        .iter()
        .find(|r| r.get("leaf_index").and_then(|v| v.as_u64()) == Some(leaf))
        .unwrap();
    assert_eq!(
        row.get("active_status").and_then(|v| v.as_str()),
        Some("revoked")
    );
}

#[test]
fn recipients_filter_active_only_by_default() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    let leaf = rt
        .admin_add_recipient(
            "default",
            &td.path().join("kA.btn.mykit"),
            Some("did:key:zRecipientA"),
        )
        .unwrap();
    rt.admin_revoke_recipient("default", leaf).unwrap();

    let mut cache = cache_for(&rt);
    let _ = cache.state().unwrap();
    let active = cache.recipients("default", false).unwrap();
    assert!(active.is_empty(), "revoked rows must be excluded by default");
    let all = cache.recipients("default", true).unwrap();
    assert!(!all.is_empty());
}

#[test]
fn diverged_is_false_when_no_fork() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    let mut cache = cache_for(&rt);
    let _ = cache.state().unwrap();
    assert!(!cache.diverged());
}

#[test]
fn cache_persists_to_disk_across_instances() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    rt.admin_add_recipient(
        "default",
        &td.path().join("kA.btn.mykit"),
        Some("did:key:zRecipientA"),
    )
    .unwrap();

    {
        let mut cache = cache_for(&rt);
        let _ = cache.state().unwrap();
        let _ = cache.refresh().unwrap();
    }
    let lkv = td.path().join(".tn").join("admin").join("admin.lkv.json");
    assert!(lkv.exists(), "lkv file should be written: {}", lkv.display());

    // New cache instance should load and reflect the same state.
    let mut cache2 = cache_for(&rt);
    let state2 = cache2.state().unwrap();
    assert!(!state2.get("recipients").unwrap().as_array().unwrap().is_empty());
}

#[test]
fn refresh_returns_zero_when_no_new_envelopes() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    let mut cache = cache_for(&rt);
    let _ = cache.refresh().unwrap();
    let delta = cache.refresh().unwrap();
    assert_eq!(delta, 0);
}

#[test]
fn refresh_picks_up_new_envelopes() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    let mut cache = cache_for(&rt);
    let before = cache.refresh().unwrap();
    let _ = before;
    let _ = cache.state().unwrap();
    let n0 = cache.at_offset();

    rt.admin_add_recipient(
        "default",
        &td.path().join("kB.btn.mykit"),
        Some("did:key:zRecipientB"),
    )
    .unwrap();
    let added = cache.refresh().unwrap();
    assert!(added >= 1, "expected refresh to pick up the new add");
    assert!(cache.at_offset() > n0);
}

#[test]
fn head_row_hash_advances_with_new_events() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Arc::new(Runtime::init(&cer.yaml_path).unwrap());
    let mut cache = cache_for(&rt);
    let _ = cache.refresh().unwrap();
    let h0 = cache.head_row_hash().map(str::to_string);

    rt.admin_add_recipient(
        "default",
        &td.path().join("kC.btn.mykit"),
        Some("did:key:zRecipientC"),
    )
    .unwrap();
    let _ = cache.refresh().unwrap();
    let h1 = cache.head_row_hash().map(str::to_string);
    assert_ne!(h0, h1, "head_row_hash must change after a new emit");
}
