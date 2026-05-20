//! Tests for `ceremony.chain: false` — the unchained-emit profile
//! (telemetry, secure_log).
//!
//! When chain is disabled:
//!   - no `.emit.lock` artifact is created on disk;
//!   - every row carries `sequence: 1` and `prev_hash: ""`;
//!   - the per-emit tail-scan and chain.advance/commit are skipped.

#![cfg(feature = "fs")]

mod common;

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use common::setup_minimal_btn_ceremony;

fn fields(msg: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("message".to_string(), json!(msg));
    m
}

/// Helper: rewrite the yaml's `ceremony:` line to include the named flag.
fn add_ceremony_flag(yaml_path: &std::path::Path, flag_kv: &str) {
    let s = std::fs::read_to_string(yaml_path).unwrap();
    // common/mod.rs writes a flow-style mapping like:
    //   ceremony: {id: cer_test, mode: local, cipher: btn, protocol_events_location: main_log}
    // Inject the new k/v right before the closing brace.
    let needle = "protocol_events_location: main_log}";
    let replacement = format!("protocol_events_location: main_log, {flag_kv}}}");
    let patched = s.replace(needle, &replacement);
    assert_ne!(s, patched, "yaml patch did not match needle");
    std::fs::write(yaml_path, patched).unwrap();
}

fn main_log_path(yaml_path: &std::path::Path) -> PathBuf {
    // Default ceremony has no explicit logs.path; runtime resolves to
    // `<yaml_dir>/.tn/<stem>/logs/tn.ndjson`. Read it directly off
    // disk by globbing the conventional location.
    let yaml_dir = yaml_path.parent().unwrap();
    let candidate = yaml_dir
        .join(".tn")
        .join("tn")
        .join("logs")
        .join("tn.ndjson");
    if candidate.exists() {
        return candidate;
    }
    // Fallback: walk under .tn/ for any tn.ndjson.
    for entry in walkdir(yaml_dir) {
        if entry.file_name().and_then(|s| s.to_str()) == Some("tn.ndjson") {
            return entry;
        }
    }
    panic!("could not locate tn.ndjson under {}", yaml_dir.display());
}

fn walkdir(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(dir) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in dir.flatten() {
            let pth = e.path();
            if pth.is_dir() {
                stack.push(pth);
            } else {
                out.push(pth);
            }
        }
    }
    out
}

/// Read all rows from the main log as parsed JSON envelopes.
fn read_envelopes(log: &std::path::Path) -> Vec<Value> {
    let bytes = std::fs::read(log).unwrap();
    bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice::<Value>(l).ok())
        .collect()
}

#[test]
fn chain_true_default_creates_lock_file_and_advances_sequence() {
    unsafe { std::env::set_var("TN_NO_STDOUT", "1"); }
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    // No patching — chain defaults to true.
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    rt.emit("info", "test.event", fields("one")).unwrap();
    rt.emit("info", "test.event", fields("two")).unwrap();

    // Lock file artifact is created on first emit.
    let log = main_log_path(&cer.yaml_path);
    let lock = {
        let mut s = log.as_os_str().to_os_string();
        s.push(".emit.lock");
        PathBuf::from(s)
    };
    assert!(
        lock.exists(),
        "chain=true should leave the .emit.lock sentinel on disk: {}",
        lock.display()
    );

    // Chain advances: row 1 has sequence=1 prev_hash=ZERO, row 2
    // has sequence=2 prev_hash=row_1_hash.
    let envs: Vec<Value> = read_envelopes(&log)
        .into_iter()
        .filter(|e| e.get("event_type").and_then(Value::as_str) == Some("test.event"))
        .collect();
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0].get("sequence").and_then(Value::as_u64), Some(1));
    assert_eq!(envs[1].get("sequence").and_then(Value::as_u64), Some(2));
    let r1_hash = envs[0].get("row_hash").and_then(Value::as_str).unwrap();
    let r2_prev = envs[1].get("prev_hash").and_then(Value::as_str).unwrap();
    assert_eq!(r1_hash, r2_prev, "row 2's prev_hash must point at row 1");
}

#[test]
fn chain_false_skips_lock_file_and_writes_unchained_sentinels() {
    unsafe { std::env::set_var("TN_NO_STDOUT", "1"); }
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    add_ceremony_flag(&cer.yaml_path, "chain: false");

    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    rt.emit("info", "trace.span", fields("one")).unwrap();
    rt.emit("info", "trace.span", fields("two")).unwrap();
    rt.emit("info", "trace.span", fields("three")).unwrap();

    let log = main_log_path(&cer.yaml_path);
    let lock = {
        let mut s = log.as_os_str().to_os_string();
        s.push(".emit.lock");
        PathBuf::from(s)
    };
    assert!(
        !lock.exists(),
        "chain=false must not create the .emit.lock sentinel: {}",
        lock.display()
    );

    let envs: Vec<Value> = read_envelopes(&log)
        .into_iter()
        .filter(|e| e.get("event_type").and_then(Value::as_str) == Some("trace.span"))
        .collect();
    assert_eq!(envs.len(), 3);
    for (i, env) in envs.iter().enumerate() {
        assert_eq!(
            env.get("sequence").and_then(Value::as_u64),
            Some(1),
            "row {i} of chain=false must carry sequence: 1 (unchained sentinel)"
        );
        assert_eq!(
            env.get("prev_hash").and_then(Value::as_str),
            Some(""),
            "row {i} of chain=false must carry prev_hash: \"\" (unchained sentinel)"
        );
    }
}
