//! Tests for `Runtime::secure_read` (per 2026-04-25 read-ergonomics spec §3).

#![cfg(feature = "fs")]

mod common;

use serde_json::{json, Value};
use std::path::Path;
use tn_core::{Error, OnInvalid, Runtime, SecureReadOptions};

const POLICY: &str = "# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## payment.completed

### instruction
Recorded payment row.

### use_for
Aggregate reporting.

### do_not_use_for
Risk scoring.

### consequences
PII exposure.

### on_violation_or_error
POST escalate

";

#[test]
fn secure_read_skip_default_emits_tampered_event() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(1));
    rt.info("evt.test", f).unwrap();

    // Corrupt the log: rewrite the last entry's row_hash.
    let log_path = rt.log_path().to_path_buf();
    let txt = std::fs::read_to_string(&log_path).unwrap();
    let mut lines: Vec<String> = txt.lines().map(str::to_string).collect();
    let last = lines.last_mut().unwrap();
    let mut env: serde_json::Value = serde_json::from_str(last).unwrap();
    let obj = env.as_object_mut().unwrap();
    obj.insert(
        "row_hash".into(),
        Value::String("sha256:0000000000000000000000000000000000000000000000000000000000000000".into()),
    );
    *last = serde_json::to_string(&env).unwrap();
    std::fs::write(&log_path, lines.join("\n") + "\n").unwrap();
    drop(rt);

    let rt2 = Runtime::init(&cer.yaml_path).unwrap();
    let entries = rt2
        .secure_read(SecureReadOptions {
            on_invalid: OnInvalid::Skip,
            log_path: None,
        })
        .unwrap();
    // The corrupted row was dropped.
    assert!(entries
        .iter()
        .all(|e| e.fields.get("event_type").and_then(Value::as_str) != Some("evt.test")));
    drop(rt2);

    // A tampered_row_skipped event should now exist.
    let rt3 = Runtime::init(&cer.yaml_path).unwrap();
    let raw = rt3.read_raw().unwrap();
    let count = raw
        .iter()
        .filter(|e| {
            e.envelope.get("event_type").and_then(Value::as_str)
                == Some("tn.read.tampered_row_skipped")
        })
        .count();
    assert!(count >= 1);
}

#[test]
fn secure_read_raise_returns_err_on_first_failure() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(1));
    rt.info("evt.test", f).unwrap();
    let log_path = rt.log_path().to_path_buf();
    let txt = std::fs::read_to_string(&log_path).unwrap();
    let mut lines: Vec<String> = txt.lines().map(str::to_string).collect();
    let last = lines.last_mut().unwrap();
    let mut env: serde_json::Value = serde_json::from_str(last).unwrap();
    env.as_object_mut().unwrap().insert(
        "row_hash".into(),
        Value::String("sha256:1111111111111111111111111111111111111111111111111111111111111111".into()),
    );
    *last = serde_json::to_string(&env).unwrap();
    std::fs::write(&log_path, lines.join("\n") + "\n").unwrap();
    drop(rt);

    let rt2 = Runtime::init(&cer.yaml_path).unwrap();
    let res = rt2.secure_read(SecureReadOptions {
        on_invalid: OnInvalid::Raise,
        log_path: None,
    });
    assert!(matches!(res, Err(Error::Malformed { .. })));
}

#[test]
fn secure_read_forensic_surfaces_invalid_reasons() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(2));
    rt.info("evt.test", f).unwrap();
    let log_path = rt.log_path().to_path_buf();
    let txt = std::fs::read_to_string(&log_path).unwrap();
    let mut lines: Vec<String> = txt.lines().map(str::to_string).collect();
    let last = lines.last_mut().unwrap();
    let mut env: serde_json::Value = serde_json::from_str(last).unwrap();
    env.as_object_mut().unwrap().insert(
        "row_hash".into(),
        Value::String("sha256:2222222222222222222222222222222222222222222222222222222222222222".into()),
    );
    *last = serde_json::to_string(&env).unwrap();
    std::fs::write(&log_path, lines.join("\n") + "\n").unwrap();
    drop(rt);

    let rt2 = Runtime::init(&cer.yaml_path).unwrap();
    let entries = rt2
        .secure_read(SecureReadOptions {
            on_invalid: OnInvalid::Forensic,
            log_path: None,
        })
        .unwrap();
    let bad = entries
        .iter()
        .find(|e| e.fields.get("event_type").and_then(Value::as_str) == Some("evt.test"))
        .expect("forensic surfaces tampered row");
    let reasons = bad.fields.get("_invalid_reasons").unwrap().as_array().unwrap();
    let s: Vec<&str> = reasons.iter().filter_map(Value::as_str).collect();
    assert!(s.contains(&"row_hash") || s.contains(&"signature"));
}

#[test]
fn secure_read_attaches_instructions_when_kit_held() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    std::fs::create_dir_all(td.path().join(".tn").join("config")).unwrap();
    std::fs::write(td.path().join(".tn").join("config").join("agents.md"), POLICY).unwrap();
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(7));
    rt.info("payment.completed", f).unwrap();

    let entries = rt.secure_read(SecureReadOptions::default()).unwrap();
    let payment = entries
        .iter()
        .find(|e| e.fields.get("event_type").and_then(Value::as_str) == Some("payment.completed"))
        .expect("payment");
    let instr = payment.instructions.as_ref().expect("instructions");
    assert_eq!(instr.instruction, "Recorded payment row.");
    // The six tn.agents fields are NOT in fields (carved out).
    assert!(!payment.fields.contains_key("instruction"));
    assert!(!payment.fields.contains_key("policy"));
}

// --- Helpers ---------------------------------------------------------

fn setup_btn_with_agents(root: &Path) -> common::BtnCeremony {
    use std::path::PathBuf;
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();
    let dk = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();

    let mut pub_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x22u8; 32]).unwrap();
    let kit = pub_state.mint().unwrap();
    std::fs::write(keystore.join("default.btn.state"), pub_state.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.btn.mykit"), kit.to_bytes()).unwrap();

    let mut agents_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x33u8; 32]).unwrap();
    let agents_kit = agents_state.mint().unwrap();
    std::fs::write(
        keystore.join("tn.agents.btn.state"),
        agents_state.to_bytes(),
    )
    .unwrap();
    std::fs::write(keystore.join("tn.agents.btn.mykit"), agents_kit.to_bytes()).unwrap();

    let did = dk.did().to_string();
    let yaml = format!(
        "ceremony: {{id: cer_test, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         me: {{did: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 \"tn.agents\":\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20   fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    let yaml_path = root.join("tn.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    common::BtnCeremony {
        yaml_path,
        keystore: PathBuf::from(&keystore),
        did,
    }
}
