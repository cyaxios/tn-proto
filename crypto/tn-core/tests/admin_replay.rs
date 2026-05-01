//! Replay-based admin verbs: `recipients`, `admin_state`, `vault_link`,
//! `vault_unlink`. Cover Python/TS parity contracts.

#![cfg(feature = "fs")]

mod common;

use serde_json::Value;
use tn_core::Runtime;

/// `recipients()` returns the active leaves only by default; passing
/// `include_revoked=true` appends revoked entries after the active ones.
#[test]
fn recipients_add_revoke_roundtrip_with_and_without_include_revoked() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let kit_a = td.path().join("a.btn.mykit");
    let kit_b = td.path().join("b.btn.mykit");
    let leaf_a = rt
        .admin_add_recipient("default", &kit_a, Some("did:key:zAlice"))
        .unwrap();
    let leaf_b = rt
        .admin_add_recipient("default", &kit_b, Some("did:key:zBob"))
        .unwrap();
    rt.admin_revoke_recipient("default", leaf_a).unwrap();

    // Default: only active recipients.
    let active = rt.recipients("default", false).unwrap();
    assert_eq!(active.len(), 1, "active should drop revoked leaf_a");
    assert_eq!(active[0].leaf_index, leaf_b);
    assert_eq!(active[0].recipient_did.as_deref(), Some("did:key:zBob"));
    assert!(!active[0].revoked);
    assert!(active[0].kit_sha256.is_some());
    assert!(active[0].minted_at.is_some());

    // include_revoked=true: active first (sorted), then revoked (sorted).
    let all = rt.recipients("default", true).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].leaf_index, leaf_b, "active comes first");
    assert!(!all[0].revoked);
    assert_eq!(all[1].leaf_index, leaf_a, "revoked comes after");
    assert!(all[1].revoked);
    assert!(all[1].revoked_at.is_some());
    // The revoked entry retains the recipient_did from its add event.
    assert_eq!(all[1].recipient_did.as_deref(), Some("did:key:zAlice"));
}

/// Filtering by group: a recipient in another group must not appear.
#[test]
fn recipients_filters_by_group() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let kit = td.path().join("r.btn.mykit");
    rt.admin_add_recipient("default", &kit, Some("did:key:zCarol"))
        .unwrap();

    // No "other" group exists — calling with a different name must be empty.
    let other = rt.recipients("not-a-group", true).unwrap();
    assert!(other.is_empty());

    let here = rt.recipients("default", false).unwrap();
    assert_eq!(here.len(), 1);
}

/// `admin_state.ceremony` is populated from the `tn.ceremony.init` event the
/// Rust runtime emits on first init. Fields match the active config and
/// `created_at` carries the envelope's timestamp.
#[test]
fn admin_state_ceremony_from_log_event() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let state = rt.admin_state(None).unwrap();
    let cer_rec = state.ceremony.as_ref().expect("ceremony must populate");
    assert_eq!(cer_rec.ceremony_id, "cer_test");
    assert_eq!(cer_rec.cipher, "btn");
    assert_eq!(cer_rec.device_did, cer.did);
    assert!(
        cer_rec.created_at.is_some(),
        "log-derived ceremony carries a created_at timestamp"
    );
}

/// When `tn.ceremony.init` is routed to a separate file via
/// `protocol_events_location`, the main-log replay produces no
/// `CeremonyInit` delta, so `admin_state` must fall back to deriving the
/// ceremony record from the active config (with `created_at == None`).
/// This is the normal Python fallback shape.
#[test]
fn admin_state_ceremony_fallback_when_init_routed_elsewhere() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    // Patch the yaml so tn.* events go to a separate file.
    let yaml_text = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let patched = yaml_text.replace(
        "protocol_events_location: main_log",
        // Route every tn.* event to a sibling file.
        "protocol_events_location: \"{yaml_dir}/tn_events.ndjson\"",
    );
    std::fs::write(&cer.yaml_path, patched).unwrap();

    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let state = rt.admin_state(None).unwrap();
    let cer_rec = state.ceremony.as_ref().expect("ceremony fallback");
    assert_eq!(cer_rec.ceremony_id, "cer_test");
    assert_eq!(cer_rec.cipher, "btn");
    assert_eq!(cer_rec.device_did, cer.did);
    assert!(
        cer_rec.created_at.is_none(),
        "fallback ceremony has no timestamp"
    );
}

/// `admin_state` reflects mint + revoke through the recipients list.
#[test]
fn admin_state_tracks_recipient_lifecycle() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let kit_a = td.path().join("a.btn.mykit");
    let kit_b = td.path().join("b.btn.mykit");
    let leaf_a = rt
        .admin_add_recipient("default", &kit_a, Some("did:key:zA"))
        .unwrap();
    let _leaf_b = rt
        .admin_add_recipient("default", &kit_b, Some("did:key:zB"))
        .unwrap();
    rt.admin_revoke_recipient("default", leaf_a).unwrap();

    let state = rt.admin_state(Some("default")).unwrap();
    assert_eq!(state.recipients.len(), 2);
    let revoked: Vec<_> = state
        .recipients
        .iter()
        .filter(|r| r.active_status == "revoked")
        .collect();
    let active: Vec<_> = state
        .recipients
        .iter()
        .filter(|r| r.active_status == "active")
        .collect();
    assert_eq!(revoked.len(), 1);
    assert_eq!(active.len(), 1);
    assert_eq!(revoked[0].leaf_index, leaf_a);
    assert!(revoked[0].revoked_at.is_some());
}

/// A `tn.rotation.completed` event retires every currently-active recipient
/// in the same group.
#[test]
fn admin_state_rotation_retires_active_recipients() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Mint two recipients.
    let kit_a = td.path().join("a.btn.mykit");
    let kit_b = td.path().join("b.btn.mykit");
    let leaf_a = rt.admin_add_recipient("default", &kit_a, None).unwrap();
    let _leaf_b = rt.admin_add_recipient("default", &kit_b, None).unwrap();
    // Revoke A so it's NOT in "active" any more.
    rt.admin_revoke_recipient("default", leaf_a).unwrap();

    // Synthesize a rotation.completed event. We hand-build the fields and
    // emit through the runtime's normal log surface, so the catalog
    // validator runs and the row hashes correctly.
    let mut fields = serde_json::Map::new();
    fields.insert("group".into(), Value::String("default".into()));
    fields.insert("cipher".into(), Value::String("btn".into()));
    fields.insert("generation".into(), Value::Number(2.into()));
    fields.insert(
        "previous_kit_sha256".into(),
        Value::String("sha256:".to_string() + &"0".repeat(64)),
    );
    fields.insert("old_pool_size".into(), Value::Null);
    fields.insert("new_pool_size".into(), Value::Null);
    fields.insert(
        "rotated_at".into(),
        Value::String("2026-04-24T12:00:00.000000Z".into()),
    );
    rt.emit("info", "tn.rotation.completed", fields).unwrap();

    let state = rt.admin_state(None).unwrap();
    assert_eq!(state.rotations.len(), 1);
    assert_eq!(state.rotations[0].group, "default");
    assert_eq!(state.rotations[0].generation, 2);

    // Recipient B (active before rotation) becomes "retired"; recipient A
    // stays "revoked" (rotation only touches still-active rows).
    let by_leaf: std::collections::BTreeMap<u64, &tn_core::AdminRecipientRecord> = state
        .recipients
        .iter()
        .map(|r| (r.leaf_index, r))
        .collect();
    let rec_a = by_leaf.get(&leaf_a).expect("A must be present");
    assert_eq!(
        rec_a.active_status, "revoked",
        "rotation does not change already-revoked rows"
    );
    let rec_b = by_leaf
        .values()
        .find(|r| r.leaf_index != leaf_a)
        .expect("B must be present");
    assert_eq!(rec_b.active_status, "retired");
    assert!(rec_b.retired_at.is_some());
}

/// `vault_link` emits a valid envelope; `vault_unlink` follows up; both
/// round-trip through `read()` and reduce cleanly.
#[test]
fn vault_link_and_unlink_round_trip() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Helper: count tn.vault.linked / unlinked envelopes by reading the
    // log. (vault_link returns Result<()> for Python parity, so we observe
    // emit / no-op via the log file rather than a return value.)
    fn count_events(rt: &Runtime, event_type: &str) -> usize {
        rt.read_raw()
            .unwrap()
            .iter()
            .filter(|e| e.envelope.get("event_type").and_then(Value::as_str) == Some(event_type))
            .count()
    }

    // First link: emits.
    rt.vault_link("did:key:zVault", "proj_1")
        .expect("vault_link must succeed");
    assert_eq!(count_events(&rt, "tn.vault.linked"), 1);

    // Idempotency: a second call with the same args must be a no-op
    // (no new tn.vault.linked envelope).
    rt.vault_link("did:key:zVault", "proj_1")
        .expect("idempotent re-link must succeed");
    assert_eq!(
        count_events(&rt, "tn.vault.linked"),
        1,
        "duplicate vault_link should short-circuit (no new envelope)"
    );

    // admin_state reflects the link as still-open.
    let state = rt.admin_state(None).unwrap();
    assert_eq!(state.vault_links.len(), 1);
    assert_eq!(state.vault_links[0].vault_did, "did:key:zVault");
    assert_eq!(state.vault_links[0].project_id, "proj_1");
    assert!(state.vault_links[0].unlinked_at.is_none());
    assert!(!state.vault_links[0].linked_at.is_empty());

    // Unlink with a reason.
    rt.vault_unlink("did:key:zVault", "proj_1", Some("rotated"))
        .expect("vault_unlink must succeed");

    let state2 = rt.admin_state(None).unwrap();
    assert_eq!(state2.vault_links.len(), 1);
    assert!(
        state2.vault_links[0].unlinked_at.is_some(),
        "unlinked_at must populate after vault_unlink"
    );

    // After unlink, vault_link to the SAME vault is no longer a no-op (the
    // existing link is closed). It must emit a fresh tn.vault.linked envelope.
    rt.vault_link("did:key:zVault", "proj_1").unwrap();
    assert_eq!(
        count_events(&rt, "tn.vault.linked"),
        2,
        "post-unlink vault_link must re-emit"
    );
}
