//! Cross-language byte-compare tests for `tn.secure_read()` flat output
//! and `tn.agents` pre-encryption canonical bytes.
//!
//! Spec: `docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md`
//! section 5.4.
//!
//! Each language commits two fixtures (`secure_read_canonical.json` +
//! `tn_agents_pre_encryption.json`). This module:
//!
//!   1. Builds the same two outputs locally from the canonical scenario
//!      (via the helpers in `secure_read_fixture_builder.rs`).
//!   2. Loads the OTHER two languages' fixtures.
//!   3. Asserts byte-identity for both.
//!
//! If a fixture is missing, the cross-consume tests skip rather than fail
//! — the fixtures are built explicitly via each language's builder.

#![cfg(feature = "fs")]

use std::path::{Path, PathBuf};

#[path = "common/secure_read_canonical_scenario.rs"]
mod scenario;

use scenario::{
    build_admin_events_canonical, build_secure_read_canonical, build_tn_agents_pre_encryption,
    canonical_json_bytes,
};

const SECURE_READ_NAME: &str = "secure_read_canonical.json";
const PRE_ENC_NAME: &str = "tn_agents_pre_encryption.json";
const ADMIN_NAME: &str = "admin_events_canonical.json";

fn fixture_path(rel: &[&str]) -> PathBuf {
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

fn rust_fixture(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn python_fixture(name: &str) -> PathBuf {
    fixture_path(&["python", "tests", "fixtures", name])
}

fn ts_fixture(name: &str) -> PathBuf {
    fixture_path(&["ts-sdk", "test", "fixtures", name])
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

// --------------------------------------------------------------------------
// Sentinel: fail loud if any cross-language fixture is missing or empty.
// The byte-compare tests above skip individually when a sibling-language
// fixture is absent. This sentinel ensures the full set exists on a
// healthy `main` so a rename, move, or zero-byte fixture surfaces as a
// hard failure rather than silent no-op.
// --------------------------------------------------------------------------

#[test]
fn required_byte_compare_fixtures_present() {
    let admin_py = fixture_path(&["python", "tests", "fixtures", "python_admin_snapshot.tnpkg"]);
    let admin_rs = rust_fixture("rust_admin_snapshot.tnpkg");
    let admin_ts = fixture_path(&["ts-sdk", "test", "fixtures", "ts_admin_snapshot.tnpkg"]);

    let expected: Vec<PathBuf> = vec![
        // Python.
        python_fixture(SECURE_READ_NAME),
        python_fixture(PRE_ENC_NAME),
        python_fixture(ADMIN_NAME),
        admin_py,
        // Rust.
        rust_fixture(SECURE_READ_NAME),
        rust_fixture(PRE_ENC_NAME),
        rust_fixture(ADMIN_NAME),
        admin_rs,
        // TS.
        ts_fixture(SECURE_READ_NAME),
        ts_fixture(PRE_ENC_NAME),
        ts_fixture(ADMIN_NAME),
        admin_ts,
    ];

    let mut missing: Vec<String> = Vec::new();
    let mut empty: Vec<String> = Vec::new();
    for p in &expected {
        match std::fs::metadata(p) {
            Ok(meta) => {
                if meta.len() == 0 {
                    empty.push(p.display().to_string());
                }
            }
            Err(_) => missing.push(p.display().to_string()),
        }
    }
    assert!(
        missing.is_empty(),
        "missing byte-compare fixtures: {missing:?}"
    );
    assert!(
        empty.is_empty(),
        "empty byte-compare fixtures (zero bytes): {empty:?}"
    );
}

// --------------------------------------------------------------------------
// Local sanity: building from the same scenario reproduces the committed
// Rust fixture byte-for-byte. Catches drift in the projection function.
// --------------------------------------------------------------------------

#[test]
fn rust_local_secure_read_matches_committed_fixture() {
    let on_disk_path = rust_fixture(SECURE_READ_NAME);
    if skip_if_missing(&on_disk_path, "rust local secure_read") {
        return;
    }
    let local = canonical_json_bytes(&build_secure_read_canonical());
    let on_disk = std::fs::read(&on_disk_path).expect("read rust fixture");
    assert_eq!(
        local,
        on_disk,
        "Rust's local secure_read output drifted from the committed fixture. \
         Re-run `cargo test -p tn-core --features fs --test secure_read_fixture_builder -- --ignored`."
    );
}

#[test]
fn rust_local_pre_encryption_matches_committed_fixture() {
    let on_disk_path = rust_fixture(PRE_ENC_NAME);
    if skip_if_missing(&on_disk_path, "rust local pre_encryption") {
        return;
    }
    let local = canonical_json_bytes(&build_tn_agents_pre_encryption());
    let on_disk = std::fs::read(&on_disk_path).expect("read rust fixture");
    assert_eq!(
        local, on_disk,
        "Rust's local tn.agents pre-encryption output drifted from the \
         committed fixture."
    );
}

// --------------------------------------------------------------------------
// Cross-language byte-compare: load the Python + TS fixtures and assert
// byte-identity against the Rust-produced output.
// --------------------------------------------------------------------------

#[test]
fn python_secure_read_byte_compare() {
    let p = python_fixture(SECURE_READ_NAME);
    if skip_if_missing(&p, "python secure_read") {
        return;
    }
    let py = std::fs::read(&p).expect("read python fixture");
    let rust = canonical_json_bytes(&build_secure_read_canonical());
    assert_eq!(
        rust, py,
        "Python-produced secure_read fixture differs from Rust output. \
         This is a cross-language wire drift; identify and fix the divergence."
    );
}

#[test]
fn ts_secure_read_byte_compare() {
    let p = ts_fixture(SECURE_READ_NAME);
    if skip_if_missing(&p, "ts secure_read") {
        return;
    }
    let ts = std::fs::read(&p).expect("read ts fixture");
    let rust = canonical_json_bytes(&build_secure_read_canonical());
    assert_eq!(
        rust, ts,
        "TS-produced secure_read fixture differs from Rust output. \
         This is a cross-language wire drift; identify and fix the divergence."
    );
}

#[test]
fn python_tn_agents_pre_encryption_byte_compare() {
    let p = python_fixture(PRE_ENC_NAME);
    if skip_if_missing(&p, "python tn.agents pre_encryption") {
        return;
    }
    let py = std::fs::read(&p).expect("read python fixture");
    let rust = canonical_json_bytes(&build_tn_agents_pre_encryption());
    assert_eq!(
        rust, py,
        "Python-produced tn.agents pre-encryption fixture differs from Rust \
         output. This is a cross-language wire drift; identify and fix the \
         divergence."
    );
}

#[test]
fn ts_tn_agents_pre_encryption_byte_compare() {
    let p = ts_fixture(PRE_ENC_NAME);
    if skip_if_missing(&p, "ts tn.agents pre_encryption") {
        return;
    }
    let ts = std::fs::read(&p).expect("read ts fixture");
    let rust = canonical_json_bytes(&build_tn_agents_pre_encryption());
    assert_eq!(
        rust, ts,
        "TS-produced tn.agents pre-encryption fixture differs from Rust \
         output. This is a cross-language wire drift; identify and fix the \
         divergence."
    );
}

// --------------------------------------------------------------------------
// Admin events canonical-bytes byte-compare. One entry per admin event_type
// in the catalog. Pins the canonical encoding for every admin event shape
// across Python / Rust / TS — this is the matrix that catches drift on
// list-valued fields, multiline strings, optional ints, etc., which the
// pre-2026-04-25 fixtures (covering only `payment.completed` +
// `order.created`) did not exercise.
// --------------------------------------------------------------------------

#[test]
fn rust_local_admin_events_matches_committed_fixture() {
    let on_disk_path = rust_fixture(ADMIN_NAME);
    if skip_if_missing(&on_disk_path, "rust local admin_events") {
        return;
    }
    let local = canonical_json_bytes(&build_admin_events_canonical());
    let on_disk = std::fs::read(&on_disk_path).expect("read rust fixture");
    assert_eq!(
        local, on_disk,
        "Rust's local admin_events canonical output drifted from the \
         committed fixture. Re-run `cargo test -p tn-core --features fs \
         --test secure_read_fixture_builder -- --ignored`."
    );
}

#[test]
fn python_admin_events_byte_compare() {
    let p = python_fixture(ADMIN_NAME);
    if skip_if_missing(&p, "python admin_events") {
        return;
    }
    let py = std::fs::read(&p).expect("read python fixture");
    let rust = canonical_json_bytes(&build_admin_events_canonical());
    assert_eq!(
        rust, py,
        "Python-produced admin_events canonical fixture differs from Rust \
         output. One of the catalog event types canonicalizes differently \
         between the two SDKs — diff the fixtures field by field to find \
         which event_type drifted."
    );
}

#[test]
fn ts_admin_events_byte_compare() {
    let p = ts_fixture(ADMIN_NAME);
    if skip_if_missing(&p, "ts admin_events") {
        return;
    }
    let ts = std::fs::read(&p).expect("read ts fixture");
    let rust = canonical_json_bytes(&build_admin_events_canonical());
    assert_eq!(
        rust, ts,
        "TS-produced admin_events canonical fixture differs from Rust \
         output. One of the catalog event types canonicalizes differently \
         between the two SDKs — diff the fixtures field by field to find \
         which event_type drifted."
    );
}
