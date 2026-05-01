#![cfg(feature = "fs")]

mod common;

use common::setup_minimal_btn_ceremony;

#[test]
fn emit_writes_one_envelope_line() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    let mut fields = serde_json::Map::new();
    fields.insert("amount".into(), serde_json::json!(100));
    fields.insert("note".into(), serde_json::json!("first"));

    rt.emit_with(
        "info",
        "order.created",
        fields,
        Some("2026-04-21T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-00000000000a"),
    )
    .unwrap();

    // Verify log file contains two parseable lines:
    // line 0 = tn.ceremony.init (emitted on fresh creation), line 1 = the business event.
    // Per-row metadata that used to surface via the EmitReceipt is now read
    // straight off the envelope — emit*() returns Result<()> for cross-language
    // parity (Python tn.log -> None, TS tn.log -> void).
    let log = rt.log_path().to_path_buf();
    drop(rt);
    let contents = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = contents.lines().collect();
    assert_eq!(lines.len(), 2); // ceremony.init + order.created
    let ceremony_env: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(ceremony_env["event_type"], "tn.ceremony.init");
    let env: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert!(env["row_hash"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(env["sequence"], 1);
    assert_eq!(env["event_type"], "order.created");
    assert_eq!(env["event_id"], "00000000-0000-0000-0000-00000000000a");
    // Group sub-object present.
    assert!(env.get("default").is_some());
    assert!(env["default"]["ciphertext"].is_string());
    assert!(env["default"]["field_hashes"]["amount"]
        .as_str()
        .unwrap()
        .starts_with("hmac-sha256:v1:"));
}

#[test]
fn emit_two_events_chains_prev_hash() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    let mut f1 = serde_json::Map::new();
    f1.insert("amount".into(), serde_json::json!(100));
    rt.emit_with(
        "info",
        "order.created",
        f1,
        Some("2026-04-21T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-00000000000a"),
    )
    .unwrap();

    let mut f2 = serde_json::Map::new();
    f2.insert("amount".into(), serde_json::json!(200));
    rt.emit_with(
        "info",
        "order.created",
        f2,
        Some("2026-04-21T12:00:01.000000Z"),
        Some("00000000-0000-0000-0000-00000000000b"),
    )
    .unwrap();

    let log = rt.log_path().to_path_buf();
    drop(rt);
    let lines: Vec<_> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    // ceremony.init (line 0) + first order.created (line 1) + second order.created (line 2).
    assert_eq!(lines.len(), 3);
    let e1: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    let e2: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
    assert_eq!(e1["sequence"], 1);
    assert_eq!(e2["sequence"], 2);
    assert_eq!(e2["prev_hash"], e1["row_hash"]);
}

#[test]
fn protocol_events_route_to_separate_file() {
    // Set up a btn ceremony, then modify its yaml to point protocol_events_location
    // at a template path. Emit one `tn.*` event and one non-tn event;
    // assert the tn.* event lands in the template file, the other in main log.
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());

    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let tampered = yaml.replace(
        "protocol_events_location: main_log",
        "protocol_events_location: \"{yaml_dir}/.tn/logs/protocol/{event_class}.ndjson\"",
    );
    std::fs::write(&cer.yaml_path, tampered).unwrap();

    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    // Emit a tn.* event
    rt.emit_with(
        "info",
        "tn.key.rotate",
        serde_json::Map::new(),
        Some("2026-04-21T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-00000000000a"),
    )
    .unwrap();

    // Emit a non-tn event
    let mut f = serde_json::Map::new();
    f.insert("amount".into(), serde_json::json!(100));
    rt.emit_with(
        "info",
        "order.created",
        f,
        Some("2026-04-21T12:00:01.000000Z"),
        Some("00000000-0000-0000-0000-00000000000b"),
    )
    .unwrap();

    let main_log = rt.log_path().to_path_buf();
    let protocol_log = td.path().join(".tn").join("logs").join("protocol").join("key.ndjson");
    drop(rt);

    let main = std::fs::read_to_string(&main_log).unwrap();
    let proto = std::fs::read_to_string(&protocol_log).unwrap();
    // Main log should have only the order.created event
    assert_eq!(main.lines().count(), 1, "main log should have 1 line");
    assert!(main.contains("order.created"));
    assert!(!main.contains("tn.key.rotate"));
    // Protocol log should have only the tn.key.rotate event
    assert_eq!(proto.lines().count(), 1);
    assert!(proto.contains("tn.key.rotate"));
}

#[test]
fn close_is_idempotent_with_drop() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();
    let mut f = serde_json::Map::new();
    f.insert("x".into(), serde_json::json!(1));
    rt.emit_with(
        "info",
        "test.close",
        f,
        Some("2026-04-21T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-0000000000cc"),
    )
    .unwrap();
    let log = rt.log_path().to_path_buf();
    rt.close().unwrap();
    // File contents survive close: ceremony.init (line 0) + test.close (line 1).
    let contents = std::fs::read_to_string(&log).unwrap();
    assert_eq!(contents.lines().count(), 2);
}

#[test]
fn log_level_wrappers_emit_with_expected_level() {
    // Parity with Python tn.log / tn.debug / tn.info / tn.warning / tn.error.
    // log() is severity-less (level=""), the others set their namesake.
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    type WrapperFn = fn(
        &tn_core::Runtime,
        &str,
        serde_json::Map<String, serde_json::Value>,
    ) -> tn_core::Result<()>;
    let cases: &[(&str, &str, WrapperFn)] = &[
        ("", "evt.bare", |r, t, f| r.log(t, f)),
        ("debug", "evt.debug", |r, t, f| r.debug(t, f)),
        ("info", "evt.info", |r, t, f| r.info(t, f)),
        ("warning", "evt.warning", |r, t, f| r.warning(t, f)),
        ("error", "evt.error", |r, t, f| r.error(t, f)),
    ];

    for (expected_level, event_type, wrapper) in cases {
        let mut fields = serde_json::Map::new();
        fields.insert("n".into(), serde_json::json!(1));
        wrapper(&rt, event_type, fields).unwrap();

        let contents = std::fs::read_to_string(rt.log_path()).unwrap();
        let line = contents
            .lines()
            .rfind(|l| l.contains(&format!("\"event_type\":\"{event_type}\"")))
            .expect("emitted line present");
        let env: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            env["level"].as_str().unwrap(),
            *expected_level,
            "wrapper for {event_type} set wrong level",
        );
    }
}

#[test]
fn emit_rejects_catalogued_admin_event_with_bad_shape() {
    // tn.recipient.added requires group, leaf_index, recipient_did,
    // kit_sha256, cipher. Emitting it without kit_sha256 must fail before
    // signing so the bad envelope never hits the log.
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    let mut fields = serde_json::Map::new();
    fields.insert("group".into(), serde_json::json!("default"));
    fields.insert("leaf_index".into(), serde_json::json!(1));
    fields.insert("recipient_did".into(), serde_json::Value::Null);
    fields.insert("cipher".into(), serde_json::json!("btn"));
    // Intentionally omit kit_sha256.

    let result = rt.emit("info", "tn.recipient.added", fields);
    assert!(
        result.is_err(),
        "emit must reject missing required field kit_sha256"
    );
    let msg = match result {
        Err(e) => format!("{e}"),
        Ok(_) => unreachable!(),
    };
    assert!(
        msg.contains("schema") || msg.contains("missing required field"),
        "error should mention schema or missing required field; got: {msg}",
    );
}
