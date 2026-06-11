//! `{event_id}` templated `logs.path`: one ndjson file per event.
//!
//! A ceremony declaring `logs: {path: ./logs/{event_id}.ndjson}` must
//! route every emit to a file named after that event's unique
//! `event_id` (uuid7), with exactly one row per file. The writer layer
//! uses an open-write-close path (no pooling) so a long-running process
//! can't leak file handles. The init-time chain seed globs every
//! rendered file back so `prev_hash` linkage survives a restart.

#![cfg(feature = "fs")]

mod common;

use std::collections::BTreeSet;

use common::setup_minimal_btn_ceremony;

/// Rewrite the ceremony yaml's `logs.path` to `new_path`, inserting a
/// `logs:` block if absent. Mirrors the Python test helper
/// `_swap_logs_path` in `python/tests/test_log_path_template.py`.
fn set_logs_path(yaml_path: &std::path::Path, new_path: &str) {
    let text = std::fs::read_to_string(yaml_path).unwrap();
    let mut out = String::new();
    let mut replaced = false;
    for line in text.lines() {
        if line.starts_with("logs:") || line.starts_with("logs ") {
            out.push_str(&format!("logs: {{path: \"{new_path}\"}}\n"));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("logs: {{path: \"{new_path}\"}}\n"));
    }
    std::fs::write(yaml_path, out).unwrap();
}

/// Collect every `*.ndjson` file directly under `dir`.
fn ndjson_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("ndjson"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[test]
fn each_event_lands_in_its_own_file_with_one_row() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    set_logs_path(&cer.yaml_path, "./logs/{event_id}.ndjson");

    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    // Three business events with explicit, distinct event_ids.
    let ids = [
        "00000000-0000-7000-8000-00000000000a",
        "00000000-0000-7000-8000-00000000000b",
        "00000000-0000-7000-8000-00000000000c",
    ];
    for (i, id) in ids.iter().enumerate() {
        let mut f = serde_json::Map::new();
        f.insert("amount".into(), serde_json::json!(100 + i));
        rt.emit_with(
            "info",
            "order.created",
            f,
            Some("2026-04-21T12:00:00.000000Z"),
            Some(id),
        )
        .unwrap();
    }
    drop(rt);

    let logs_dir = td.path().join("logs");
    let files = ndjson_files(&logs_dir);

    // One file per business event id must exist, each holding exactly
    // one row whose event_id matches the file stem.
    for id in &ids {
        let p = logs_dir.join(format!("{id}.ndjson"));
        assert!(p.is_file(), "missing per-event file for {id}: {p:?}");
        let contents = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<_> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "{id}.ndjson must hold exactly one row");
        let env: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(env["event_id"], *id);
        assert_eq!(env["event_type"], "order.created");
    }

    // Every rendered file holds exactly one row (no pooling/leak that
    // would append a second event's row to a prior file).
    for f in &files {
        let contents = std::fs::read_to_string(f).unwrap();
        let n = contents.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(n, 1, "{f:?} should hold exactly one row, found {n}");
    }

    // The three business ids are distinct files (plus admin ceremony.init).
    let stems: BTreeSet<String> = files
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    for id in &ids {
        assert!(stems.contains(*id), "stem set missing {id}: {stems:?}");
    }
}

#[test]
fn chain_links_across_per_event_files() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    set_logs_path(&cer.yaml_path, "./logs/{event_id}.ndjson");

    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let ids = [
        "00000000-0000-7000-8000-0000000000a1",
        "00000000-0000-7000-8000-0000000000a2",
    ];
    for id in &ids {
        let mut f = serde_json::Map::new();
        f.insert("amount".into(), serde_json::json!(1));
        rt.emit_with("info", "order.created", f, None, Some(id))
            .unwrap();
    }
    drop(rt);

    let logs_dir = td.path().join("logs");
    let read_env = |id: &str| -> serde_json::Value {
        let p = logs_dir.join(format!("{id}.ndjson"));
        let contents = std::fs::read_to_string(&p).unwrap();
        let line = contents.lines().find(|l| !l.trim().is_empty()).unwrap();
        serde_json::from_str(line).unwrap()
    };

    let e1 = read_env(ids[0]);
    let e2 = read_env(ids[1]);
    // Same event_type → chain continues across the two files.
    assert_eq!(e1["sequence"], 1);
    assert_eq!(e2["sequence"], 2);
    assert_eq!(e2["prev_hash"], e1["row_hash"]);
}
