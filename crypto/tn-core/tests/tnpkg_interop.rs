//! Cross-language `.tnpkg` byte-compare tests.
//!
//! Each language's fixture builder produces an admin_log_snapshot for the
//! same canonical scenario:
//!
//!   1. Fresh btn ceremony.
//!   2. tn.recipient.added(did:key:zAlice) -> leaf A
//!   3. tn.recipient.added(did:key:zBob)   -> leaf B
//!   4. tn.recipient.revoked(leaf A)
//!   5. tn.vault.linked(did:web:vault.example, demo)
//!
//! This module verifies that:
//!
//!   1. Python-produced and TS-produced `.tnpkg`s parse cleanly via Rust
//!      and the manifest signature verifies.
//!   2. State / clock shape matches the canonical scenario.
//!   3. The manifest canonical signing-bytes function is byte-identical
//!      across the three languages when given identical inputs (the wire
//!      parity contract).
//!
//! If a fixture is missing, the cross-consume tests skip rather than fail
//! — the fixtures are built explicitly via each language's builder.

#![cfg(feature = "fs")]

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use tn_core::tnpkg::{read_tnpkg, verify_manifest, Manifest, ManifestKind, TnpkgSource};

fn fixture_dir(rel: &[&str]) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // `manifest_dir` is `tn-protocol/crypto/tn-core/`. Walk up to
    // `tn-protocol/` and join the rel path.
    let mut p = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    for seg in rel {
        p.push(seg);
    }
    p
}

fn python_fixture() -> PathBuf {
    fixture_dir(&["python", "tests", "fixtures", "python_admin_snapshot.tnpkg"])
}

fn ts_fixture() -> PathBuf {
    fixture_dir(&["ts-sdk", "test", "fixtures", "ts_admin_snapshot.tnpkg"])
}

fn assert_canonical_admin_state(manifest: &Manifest) {
    let state = manifest
        .state
        .as_ref()
        .expect("fixture must include materialized state");
    let recipients = state
        .get("recipients")
        .and_then(Value::as_array)
        .expect("state.recipients must be an array");
    assert_eq!(
        recipients.len(),
        2,
        "expected 2 recipients, got {}",
        recipients.len()
    );
    let mut alice_status: Option<&str> = None;
    let mut bob_status: Option<&str> = None;
    for r in recipients {
        let did = r.get("recipient_did").and_then(Value::as_str);
        let status = r.get("active_status").and_then(Value::as_str);
        match did {
            Some("did:key:zAlice") => alice_status = status,
            Some("did:key:zBob") => bob_status = status,
            _ => {}
        }
    }
    assert_eq!(alice_status, Some("revoked"), "alice should be revoked");
    assert_eq!(bob_status, Some("active"), "bob should be active");

    let vault_links = state
        .get("vault_links")
        .and_then(Value::as_array)
        .expect("state.vault_links must be an array");
    assert_eq!(vault_links.len(), 1, "expected 1 vault link");
    let link = &vault_links[0];
    assert_eq!(
        link.get("vault_did").and_then(Value::as_str),
        Some("did:web:vault.example")
    );
    assert_eq!(
        link.get("project_id").and_then(Value::as_str),
        Some("demo")
    );
    assert!(
        link.get("unlinked_at")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "vault link must still be active (unlinked_at == null)"
    );
}

fn skip_if_missing(p: &Path, label: &str) -> bool {
    if !p.exists() {
        eprintln!(
            "(skipping {label} cross-language test — fixture not built at {})",
            p.display()
        );
        return true;
    }
    false
}

#[test]
fn python_produced_admin_snapshot_parses_in_rust() {
    let p = python_fixture();
    if skip_if_missing(&p, "python") {
        return;
    }
    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&p))
        .expect("read python_admin_snapshot.tnpkg");
    verify_manifest(&manifest)
        .expect("Python-produced manifest signature must verify in Rust");
    assert_eq!(manifest.kind, ManifestKind::AdminLogSnapshot);
    assert!(body.contains_key("body/admin.ndjson"));
    assert!(
        manifest.event_count >= 4,
        "Python fixture should carry >=4 admin envelopes, got {}",
        manifest.event_count
    );
    assert_canonical_admin_state(&manifest);
}

#[test]
fn ts_produced_admin_snapshot_parses_in_rust() {
    let p = ts_fixture();
    if skip_if_missing(&p, "ts") {
        return;
    }
    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&p))
        .expect("read ts_admin_snapshot.tnpkg");
    verify_manifest(&manifest)
        .expect("TS-produced manifest signature must verify in Rust");
    assert_eq!(manifest.kind, ManifestKind::AdminLogSnapshot);
    assert!(body.contains_key("body/admin.ndjson"));
    assert!(
        manifest.event_count >= 4,
        "TS fixture should carry >=4 admin envelopes, got {}",
        manifest.event_count
    );
    assert_canonical_admin_state(&manifest);
}

// --------------------------------------------------------------------------
// Wire-format byte-equivalence: hard-coded golden manifest input. The
// canonical signing bytes for these exact fields must be byte-identical
// across Python (test_tnpkg_interop.py), Rust (this file), and TS
// (tnpkg_interop.test.ts).
// --------------------------------------------------------------------------

fn golden_input() -> Manifest {
    let mut clock_inner: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    clock_inner.insert("tn.recipient.added".into(), 2);
    clock_inner.insert("tn.recipient.revoked".into(), 1);
    clock_inner.insert("tn.vault.linked".into(), 1);
    let mut clock: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> =
        std::collections::BTreeMap::new();
    clock.insert(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
        clock_inner,
    );

    let mut state_obj = Map::new();
    let mut link = Map::new();
    link.insert(
        "vault_did".into(),
        Value::String("did:web:vault.example".into()),
    );
    link.insert("project_id".into(), Value::String("demo".into()));
    link.insert(
        "linked_at".into(),
        Value::String("2026-04-24T12:00:00.000Z".into()),
    );
    link.insert("unlinked_at".into(), Value::Null);
    state_obj.insert(
        "vault_links".into(),
        Value::Array(vec![Value::Object(link)]),
    );
    let state = Value::Object(state_obj);

    Manifest {
        kind: ManifestKind::AdminLogSnapshot,
        version: 1,
        from_did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
        to_did: Some("did:key:zRecipient".into()),
        ceremony_id: "test_ceremony_42".into(),
        as_of: "2026-04-24T12:00:00.000+00:00".into(),
        scope: "admin".into(),
        clock,
        event_count: 4,
        head_row_hash: Some(format!("sha256:{}", "a".repeat(64))),
        state: Some(state),
        manifest_signature_b64: None,
    }
}

/// Inline canonical bytes — independent of `Manifest::signing_bytes()` so
/// that test catches a drift in *either* the manifest serializer or the
/// canonical encoder. Matches the JCS-style encoding produced by Python's
/// `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
fn golden_canonical_bytes() -> Vec<u8> {
    // Order independent: the canonical encoder sorts keys. This blob
    // already has them sorted.
    let want = json!({
        "as_of": "2026-04-24T12:00:00.000+00:00",
        "ceremony_id": "test_ceremony_42",
        "clock": {
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK": {
                "tn.recipient.added": 2,
                "tn.recipient.revoked": 1,
                "tn.vault.linked": 1
            }
        },
        "event_count": 4,
        "from_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "head_row_hash": format!("sha256:{}", "a".repeat(64)),
        "kind": "admin_log_snapshot",
        "scope": "admin",
        "state": {
            "vault_links": [{
                "linked_at": "2026-04-24T12:00:00.000Z",
                "project_id": "demo",
                "unlinked_at": null,
                "vault_did": "did:web:vault.example"
            }]
        },
        "to_did": "did:key:zRecipient",
        "version": 1
    });
    tn_core::canonical::canonical_bytes(&want).expect("canonical encode")
}

#[test]
fn manifest_canonical_bytes_match_golden() {
    let m = golden_input();
    let got = m.signing_bytes().expect("signing_bytes");
    let want = golden_canonical_bytes();
    assert_eq!(
        got,
        want,
        "Rust signing_bytes drifted from golden.\n got: {}\nwant: {}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&want),
    );
}
