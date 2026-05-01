//! Integration tests for Runtime::init.

#![cfg(feature = "fs")]

mod common;

#[test]
fn init_minimal_btn_ceremony() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    assert_eq!(rt.did(), cer.did);
    // log_path ends with logs/tn.ndjson (forward or back slash depending on OS).
    let lp = rt.log_path().to_string_lossy();
    assert!(
        lp.ends_with(".tn/logs/tn.ndjson") || lp.ends_with("logs\\tn.ndjson"),
        "unexpected log_path: {lp}"
    );
}

#[test]
fn init_fails_when_did_mismatches() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    // Tamper yaml to point to a different DID.
    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let tampered = yaml.replace(&cer.did, "did:key:zDIFFERENTXXXXXXXXXXXXXXXXXXXXXX");
    std::fs::write(&cer.yaml_path, tampered).unwrap();

    let result = tn_core::Runtime::init(&cer.yaml_path);
    assert!(result.is_err(), "expected init to fail on DID mismatch");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("does not match") || msg.contains("DID"),
        "unexpected error: {msg}"
    );
}

#[test]
fn init_fails_when_no_btn_files() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    // Remove both btn keystore files.
    std::fs::remove_file(cer.keystore.join("default.btn.state")).unwrap();
    std::fs::remove_file(cer.keystore.join("default.btn.mykit")).unwrap();

    let result = tn_core::Runtime::init(&cer.yaml_path);
    assert!(
        result.is_err(),
        "expected init to fail when no btn files exist"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("no default.btn.state") || msg.contains("btn"),
        "unexpected error: {msg}"
    );
}

#[test]
fn fresh_init_emits_ceremony_init_as_first_entry() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());
    // Fresh init: log file does not exist yet.
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    // Read back and decrypt while the runtime is still live (we are the publisher).
    let entries = rt.read_raw().unwrap();
    assert!(
        !entries.is_empty(),
        "log must have at least one entry after fresh init"
    );

    let first = &entries[0];
    let env = &first.envelope;

    // Top-level envelope fields.
    assert_eq!(env["event_type"], "tn.ceremony.init");
    // Verify sequence is 1 (first event in the log).
    assert_eq!(env["sequence"], 1, "ceremony.init must be sequence 1");
    // did field carries the publisher DID at the top level.
    assert!(
        env["did"]
            .as_str()
            .is_some_and(|s| s.starts_with("did:key:")),
        "envelope did must start with did:key:"
    );
    // created_at equivalent: the envelope's timestamp field.
    assert!(
        env["timestamp"].as_str().is_some(),
        "timestamp must be present"
    );

    // Decrypted payload fields (the publisher can decrypt its own group).
    let pt = &first.plaintext_per_group["default"];
    assert!(
        pt["ceremony_id"].as_str().is_some(),
        "ceremony_id must be a string in decrypted payload"
    );
    assert!(
        pt["cipher"].as_str().is_some(),
        "cipher must be a string in decrypted payload"
    );
    assert!(
        pt["device_did"]
            .as_str()
            .is_some_and(|s| s.starts_with("did:key:")),
        "device_did must start with did:key: in decrypted payload"
    );
    assert!(
        pt["created_at"].as_str().is_some(),
        "created_at must be a string in decrypted payload"
    );

    drop(rt);

    // Also verify the raw log file has the entry as the first line.
    let log_path = td.path().join(".tn").join("logs").join("tn.ndjson");
    let content = std::fs::read_to_string(&log_path).expect("log file must exist after fresh init");
    let first_line = content
        .lines()
        .next()
        .expect("log must have at least one line");
    let raw: serde_json::Value =
        serde_json::from_str(first_line).expect("first line is valid JSON");
    assert_eq!(raw["event_type"], "tn.ceremony.init");
}

#[test]
fn reload_does_not_re_emit_ceremony_init() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    // First init: fresh creation emits exactly one tn.ceremony.init.
    {
        let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        drop(rt); // flush
    }

    // Reload from the same yaml: must NOT emit a second tn.ceremony.init.
    {
        let rt2 = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        drop(rt2); // flush
    }

    let log_path = td.path().join(".tn").join("logs").join("tn.ndjson");
    let content = std::fs::read_to_string(&log_path).expect("log file");
    let ceremony_inits: Vec<_> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event_type"] == "tn.ceremony.init")
        .collect();
    assert_eq!(
        ceremony_inits.len(),
        1,
        "reload must not re-emit tn.ceremony.init; got: {ceremony_inits:?}"
    );
}

#[test]
fn reload_does_not_re_emit_ceremony_init_with_protocol_routing() {
    // When protocol_events_location routes tn.* events to a separate file,
    // the main log never receives tn.ceremony.init. A naive !log_path.exists()
    // fresh-check would falsely detect fresh on reload and re-emit. This test
    // pins the bug fix.
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    // Rewrite the yaml to use a protocol_events_location template that routes
    // tn.* events to a separate file (mirrors runtime_emit.rs pattern).
    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let tampered = yaml.replace(
        "protocol_events_location: main_log",
        "protocol_events_location: \"{yaml_dir}/.tn/logs/protocol/{event_class}.ndjson\"",
    );
    std::fs::write(&cer.yaml_path, tampered).unwrap();

    // First init (fresh): emits tn.ceremony.init into logs/protocol/ceremony.ndjson.
    // The main log logs/tn.ndjson is NOT created.
    {
        let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        drop(rt);
    }

    // Sanity: main log exists (LogFileWriter creates it) but must be empty
    // because tn.ceremony.init was routed to the protocol file.
    let main_log = td.path().join(".tn").join("logs").join("tn.ndjson");
    if main_log.exists() {
        let content = std::fs::read_to_string(&main_log).unwrap();
        assert!(
            !content.lines().any(|l| l.contains("tn.ceremony.init")),
            "main log must not contain tn.ceremony.init when using protocol routing"
        );
    }

    // Second init (reload): must NOT re-emit ceremony.init.
    {
        let rt2 = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        drop(rt2);
    }

    // Count tn.ceremony.init across both known paths.
    let protocol_log = td
        .path()
        .join(".tn")
        .join("logs")
        .join("protocol")
        .join("ceremony.ndjson");
    let mut count = 0usize;

    // Main log: may still not exist (no non-tn events were emitted).
    if main_log.exists() {
        let content = std::fs::read_to_string(&main_log).unwrap();
        for line in content.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v["event_type"] == "tn.ceremony.init" {
                    count += 1;
                }
            }
        }
    }

    // Protocol-routed file.
    assert!(
        protocol_log.exists(),
        "protocol log must exist after fresh init"
    );
    let content = std::fs::read_to_string(&protocol_log).unwrap();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["event_type"] == "tn.ceremony.init" {
                count += 1;
            }
        }
    }

    assert_eq!(
        count, 1,
        "reload with protocol routing must not re-emit tn.ceremony.init; found {count}"
    );
}

#[test]
fn relative_protocol_events_location_anchors_at_yaml_dir() {
    // Regression: bug #3 from the e2e conftest workaround. Previously
    // ``Runtime::resolve_pel`` returned a ``PathBuf`` directly from the
    // template substitution, so a relative template like
    // ``./.tn/admin/admin.ndjson`` was resolved against the process cwd,
    // not the yaml's parent dir. With the fix in place, the admin event
    // lands in ``<yaml_dir>/.tn/admin/admin.ndjson`` regardless of where
    // the publisher subprocess was launched from.
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let tampered = yaml.replace(
        "protocol_events_location: main_log",
        // Plain relative path — no ``{yaml_dir}`` token. Must still anchor
        // at yaml_dir, not cwd.
        "protocol_events_location: \"./.tn/admin/admin.ndjson\"",
    );
    std::fs::write(&cer.yaml_path, tampered).unwrap();

    {
        let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        drop(rt);
    }

    let admin_log = td.path().join(".tn").join("admin").join("admin.ndjson");
    assert!(
        admin_log.exists(),
        "admin log must be anchored at yaml_dir/.tn/admin/admin.ndjson, got missing at {admin_log:?}"
    );
    let content = std::fs::read_to_string(&admin_log).unwrap();
    assert!(
        content.lines().any(|l| l.contains("tn.ceremony.init")),
        "admin log must contain tn.ceremony.init, got:\n{content}"
    );
}

#[test]
fn yaml_dir_template_keeps_rust_dispatch_active() {
    // Regression: bug #4 from the e2e conftest workaround. Previously a
    // template that used ``{yaml_dir}`` could silently kick the Rust path
    // back to the Python fallback in ``resolve_admin_log_path`` (the
    // condition ``!pel.contains('{')`` rejected any template). With the
    // fix, ``{yaml_dir}`` is substituted at config-load time, the
    // resolved path is treated as a normal absolute path, and the Rust
    // runtime keeps emitting through the configured admin file.
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let tampered = yaml.replace(
        "protocol_events_location: main_log",
        "protocol_events_location: \"{yaml_dir}/.tn/admin/admin.ndjson\"",
    );
    std::fs::write(&cer.yaml_path, tampered).unwrap();

    {
        let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        // Active btn ceremony — the runtime is fully usable.
        assert_eq!(rt.did(), cer.did);
        drop(rt);
    }

    let admin_log = td.path().join(".tn").join("admin").join("admin.ndjson");
    assert!(
        admin_log.exists(),
        "{{yaml_dir}}-templated admin log must resolve to <yaml_dir>/.tn/admin/admin.ndjson"
    );
    let content = std::fs::read_to_string(&admin_log).unwrap();
    assert!(
        content.lines().any(|l| l.contains("tn.ceremony.init")),
        "admin log must contain tn.ceremony.init"
    );

    // And reload doesn't re-emit ceremony.init — proves fresh-detection
    // (``resolve_pel_static``) also handles the {yaml_dir} template.
    {
        let rt2 = tn_core::Runtime::init(&cer.yaml_path).unwrap();
        drop(rt2);
    }
    let content2 = std::fs::read_to_string(&admin_log).unwrap();
    let count = content2
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event_type"] == "tn.ceremony.init")
        .count();
    assert_eq!(
        count, 1,
        "reload must not re-emit tn.ceremony.init under {{yaml_dir}} template; got {count}"
    );
}

#[test]
fn init_seeds_chain_from_existing_log() {
    let td = tempfile::tempdir().unwrap();
    let cer = common::setup_minimal_btn_ceremony(td.path());

    // Pre-write a fake ndjson log with one entry so chain seeding is exercised.
    let logs_dir = td.path().join(".tn").join("logs");
    std::fs::create_dir_all(&logs_dir).unwrap();
    let fake_entry = serde_json::json!({
        "event_type": "order.created",
        "sequence": 3,
        "row_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    });
    std::fs::write(logs_dir.join("tn.ndjson"), format!("{}\n", fake_entry)).unwrap();

    // init should succeed and read the pre-existing log without error.
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    assert_eq!(rt.did(), cer.did);
}
