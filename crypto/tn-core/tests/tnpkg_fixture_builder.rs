//! Generate the Rust-produced ``rust_admin_snapshot.tnpkg`` fixture for
//! cross-language byte-compare tests.
//!
//! Canonical scenario (mirrored in the Python + TS builders):
//!
//!   1. Fresh btn ceremony.
//!   2. ``tn.recipient.added`` for did:key:zAlice  -> leaf A
//!   3. ``tn.recipient.added`` for did:key:zBob    -> leaf B
//!   4. ``tn.recipient.revoked`` for leaf A
//!   5. ``tn.vault.linked``     vault=did:web:vault.example  project_id=demo
//!
//! Run with:
//!
//!     cargo test -p tn-core --features fs --test tnpkg_fixture_builder \
//!         -- --ignored --nocapture
//!
//! The `#[ignore]` gate keeps fixture regeneration out of the default test
//! run; CI runs against the committed fixture, never re-builds it.

#![cfg(feature = "fs")]

mod common;

use std::path::PathBuf;

use tn_core::tnpkg::ManifestKind;
use tn_core::{ExportOptions, Runtime};

fn fixture_path() -> PathBuf {
    // Test is run from `crypto/tn-core`. Place fixture next to this file
    // (i.e. `crypto/tn-core/tests/fixtures/`).
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("rust_admin_snapshot.tnpkg")
}

#[test]
#[ignore = "fixture builder; run with `--ignored` to regenerate"]
fn build_rust_admin_snapshot_fixture() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let kit_a = td.path().join("alice.kit");
    let leaf_a = rt
        .admin_add_recipient("default", &kit_a, Some("did:key:zAlice"))
        .unwrap();
    let kit_b = td.path().join("bob.kit");
    let _leaf_b = rt
        .admin_add_recipient("default", &kit_b, Some("did:key:zBob"))
        .unwrap();
    rt.admin_revoke_recipient("default", leaf_a).unwrap();
    rt.vault_link("did:web:vault.example", "demo").unwrap();

    let out = fixture_path();
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    rt.export(
        &out,
        ExportOptions {
            kind: Some(ManifestKind::AdminLogSnapshot),
            ..Default::default()
        },
    )
    .unwrap();

    let bytes = std::fs::metadata(&out).unwrap().len();
    eprintln!("wrote {} ({} bytes)", out.display(), bytes);
}
