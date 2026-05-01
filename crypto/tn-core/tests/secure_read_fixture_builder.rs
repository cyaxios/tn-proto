//! Generate the Rust-produced cross-language byte-compare fixtures for
//! the new `tn.read()` flat shape, `tn.secure_read()` output, and
//! `tn.agents` group pre-encryption canonical bytes.
//!
//! Spec: `docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md`
//! section 5.4 (cross-language byte-identity).
//!
//! Two fixtures are emitted (mirrored byte-for-byte by the Python + TS
//! builders):
//!
//!     secure_read_canonical.json
//!         Canonical JSON of `flatten_raw_entry(...) +
//!         attach_instructions(...)` applied to the canonical scenario
//!         raw entries — the dict shape `Runtime::secure_read()` hands to
//!         the LLM. Same envelope + plaintext input must produce
//!         byte-identical canonical-JSON output across Python / Rust / TS.
//!
//!     tn_agents_pre_encryption.json
//!         Canonical bytes of the six-field policy splice payload for
//!         `payment.completed`. This is the cipher's input; random AEAD
//!         nonces make the post-encryption ciphertext diverge per row,
//!         but the canonical PRE-encryption bytes (what gets passed to
//!         `cipher.encrypt(...)`) must agree across languages, byte for
//!         byte.
//!
//! Run with:
//!
//!     cargo test -p tn-core --features fs --test secure_read_fixture_builder \
//!         -- --ignored --nocapture
//!
//! `#[ignore]` keeps fixture regeneration out of the default test run.

#![cfg(feature = "fs")]

#[path = "common/secure_read_canonical_scenario.rs"]
mod scenario;

use std::path::PathBuf;

use scenario::{
    build_admin_events_canonical, build_secure_read_canonical, build_tn_agents_pre_encryption,
    canonical_json_bytes,
};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("tests").join("fixtures")
}

fn write_fixture(name: &str, value: &Value) -> std::io::Result<usize> {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir)?;
    let bytes = canonical_json_bytes(value);
    let path = dir.join(name);
    std::fs::write(&path, &bytes)?;
    Ok(bytes.len())
}

#[test]
#[ignore = "fixture builder; run with `--ignored` to regenerate"]
fn build_rust_secure_read_fixtures() {
    let secure = build_secure_read_canonical();
    let n = write_fixture("secure_read_canonical.json", &secure)
        .expect("write secure_read_canonical.json");
    eprintln!(
        "wrote {} ({} bytes)",
        fixtures_dir().join("secure_read_canonical.json").display(),
        n
    );

    let pre = build_tn_agents_pre_encryption();
    let n = write_fixture("tn_agents_pre_encryption.json", &pre)
        .expect("write tn_agents_pre_encryption.json");
    eprintln!(
        "wrote {} ({} bytes)",
        fixtures_dir()
            .join("tn_agents_pre_encryption.json")
            .display(),
        n
    );

    let admin = build_admin_events_canonical();
    let n = write_fixture("admin_events_canonical.json", &admin)
        .expect("write admin_events_canonical.json");
    eprintln!(
        "wrote {} ({} bytes)",
        fixtures_dir()
            .join("admin_events_canonical.json")
            .display(),
        n
    );
}
