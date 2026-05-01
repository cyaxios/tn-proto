//! Integration tests for `Runtime::ephemeral` — the "tempdir + auto-cleanup"
//! constructor that mirrors Python's `tn.session()` for tests and one-shot
//! scripts.

#![cfg(feature = "fs")]

use std::path::PathBuf;

#[test]
fn ephemeral_runtime_can_emit_and_read() {
    let log_path: PathBuf;
    {
        let rt = tn_core::Runtime::ephemeral().expect("ephemeral runtime");
        // Sanity: the runtime has a real DID and a log path under the tempdir.
        assert!(rt.did().starts_with("did:key:"));
        log_path = rt.log_path().to_path_buf();
        assert!(log_path.exists(), "log file should exist after init");

        // Emit a single user event — exercises the same codepath as a
        // non-ephemeral runtime.
        let mut fields = serde_json::Map::new();
        fields.insert("k".into(), serde_json::json!(1));
        rt.emit("info", "evt.ephemeral", fields).expect("emit ok");

        // Read it back.
        let entries = rt.read_raw().expect("read ok");
        let user: Vec<_> = entries
            .iter()
            .filter(|e| e.envelope["event_type"] == "evt.ephemeral")
            .collect();
        assert_eq!(user.len(), 1, "expected exactly one user event");
        assert!(user[0].envelope["sequence"].as_u64().unwrap() >= 1);
    }
    // After Drop the tempdir should be gone.
    assert!(
        !log_path.exists(),
        "tempdir should have been cleaned up on drop, but log_path still exists: {log_path:?}",
    );
}

#[test]
fn ephemeral_runtimes_are_isolated() {
    // Two ephemeral runtimes shouldn't share state — different DIDs,
    // different log paths.
    let a = tn_core::Runtime::ephemeral().unwrap();
    let b = tn_core::Runtime::ephemeral().unwrap();
    assert_ne!(a.did(), b.did());
    assert_ne!(a.log_path(), b.log_path());
}
