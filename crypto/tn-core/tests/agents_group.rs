//! Tests for the reserved `tn.agents` group + policy splice (per
//! 2026-04-25 read-ergonomics spec §2).

#![cfg(feature = "fs")]

mod common;

use serde_json::Value;
use tn_core::{config::parse, Error, Runtime};

const POLICY: &str = "# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting on amount and currency.

### do_not_use_for
Credit decisions, fraud model training.

### consequences
customer_id is PII; exposure violates GDPR.

### on_violation_or_error
POST https://merchant.example.com/controls/escalate

";

#[test]
fn reserved_namespace_rejects_user_tn_groups() {
    let yaml = r#"
ceremony: {id: c1, mode: local, cipher: btn}
keystore: {path: ./.tn/keys}
me: {did: "did:key:zXYZ"}
public_fields: []
default_policy: private
groups:
  default: {policy: private, cipher: btn}
  "tn.foo": {policy: private, cipher: btn}
fields: {}
llm_classifier: {enabled: false, provider: "", model: ""}
"#;
    let err = parse(yaml).unwrap_err();
    assert!(matches!(err, Error::ReservedGroupName { .. }));
}

#[test]
fn reserved_namespace_allows_tn_agents() {
    let yaml = r#"
ceremony: {id: c1, mode: local, cipher: btn}
keystore: {path: ./.tn/keys}
me: {did: "did:key:zXYZ"}
public_fields: []
default_policy: private
groups:
  default: {policy: private, cipher: btn}
  "tn.agents":
    policy: private
    cipher: btn
    fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]
fields: {}
llm_classifier: {enabled: false, provider: "", model: ""}
"#;
    let cfg = parse(yaml).unwrap();
    assert!(cfg.groups.contains_key("tn.agents"));
}

#[test]
fn ephemeral_runtime_auto_injects_tn_agents() {
    let rt = Runtime::ephemeral().unwrap();
    assert!(rt.group_names().contains(&"tn.agents".to_string()));
}

#[test]
fn policy_file_splice_populates_tn_agents_fields() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony_with_agents(td.path());

    // Drop the policy file BEFORE init.
    let cfg_dir = td.path().join(".tn").join("config");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("agents.md"), POLICY).unwrap();

    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Emit a `payment.completed` event WITHOUT specifying the six agent
    // fields. The splice should fill them.
    let mut f = serde_json::Map::new();
    f.insert("amount".into(), serde_json::json!(4999));
    rt.info("payment.completed", f).unwrap();

    let raw = rt.read_raw().unwrap();
    let payment = raw
        .iter()
        .find(|e| {
            e.envelope.get("event_type").and_then(Value::as_str)
                == Some("payment.completed")
        })
        .expect("payment.completed entry");
    let agents_pt = &payment.plaintext_per_group["tn.agents"];
    assert_eq!(
        agents_pt["instruction"].as_str().unwrap(),
        "This row records a completed payment."
    );
    assert!(agents_pt["policy"]
        .as_str()
        .unwrap()
        .starts_with(".tn/config/agents.md#payment.completed@1#sha256:"));
}

#[test]
fn admin_events_splice_tn_agents_when_policy_covers_them() {
    // Regression for the 2026-04-25 e2e gap: when an admin verb (e.g.
    // ``admin_add_recipient``) emits a ``tn.recipient.added`` event whose
    // public_fields already carry the structural data (group, leaf_index,
    // recipient_did, kit_sha256, cipher), the policy splice MUST still
    // populate the ``tn.agents`` group block. An LLM runtime watching the
    // admin log would otherwise see an admin event with no instructions.
    let policy = "# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## tn.recipient.added

### instruction
This row records a newly-issued recipient kit.

### use_for
Replication of recipient roster across mirrors.

### do_not_use_for
Direct merging into any external CRM or marketing list.

### consequences
Reveals the recipient's DID; do not publish broadly.

### on_violation_or_error
POST https://merchant.example.com/controls/escalate

";
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony_with_agents(td.path());

    let cfg_dir = td.path().join(".tn").join("config");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("agents.md"), policy).unwrap();

    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let kit_path = td.path().join("peer.btn.mykit");
    rt.admin_add_recipient("default", &kit_path, Some("did:key:zPeerForSplice"))
        .unwrap();

    let raw = rt.read_raw().unwrap();
    let added = raw
        .iter()
        .find(|e| {
            e.envelope.get("event_type").and_then(Value::as_str)
                == Some("tn.recipient.added")
        })
        .expect("tn.recipient.added entry");

    let agents_pt = added
        .plaintext_per_group
        .get("tn.agents")
        .expect("admin events must carry a populated tn.agents block");
    assert_eq!(
        agents_pt["instruction"].as_str().unwrap(),
        "This row records a newly-issued recipient kit."
    );
    assert_eq!(
        agents_pt["use_for"].as_str().unwrap(),
        "Replication of recipient roster across mirrors."
    );
    assert!(agents_pt["policy"]
        .as_str()
        .unwrap()
        .starts_with(".tn/config/agents.md#tn.recipient.added@1#sha256:"));
}

#[test]
fn no_policy_file_means_tn_agents_stays_empty() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony_with_agents(td.path());

    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let mut f = serde_json::Map::new();
    f.insert("amount".into(), serde_json::json!(1));
    rt.info("payment.completed", f).unwrap();

    let raw = rt.read_raw().unwrap();
    let payment = raw
        .iter()
        .find(|e| {
            e.envelope.get("event_type").and_then(Value::as_str)
                == Some("payment.completed")
        })
        .expect("payment.completed entry");
    // No splice: tn.agents has no fields routed into it for this event,
    // so the envelope has no tn.agents group payload (no plaintext entry).
    assert!(!payment.plaintext_per_group.contains_key("tn.agents"));
}

#[test]
fn policy_published_event_emitted_on_init_when_policy_present() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony_with_agents(td.path());
    std::fs::create_dir_all(td.path().join(".tn").join("config")).unwrap();
    std::fs::write(td.path().join(".tn").join("config").join("agents.md"), POLICY).unwrap();

    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let raw = rt.read_raw().unwrap();
    let count = raw
        .iter()
        .filter(|e| {
            e.envelope.get("event_type").and_then(Value::as_str)
                == Some("tn.agents.policy_published")
        })
        .count();
    assert_eq!(count, 1, "exactly one policy_published on first init");
    drop(rt);

    // Re-init without changing the policy: no new event.
    let rt2 = Runtime::init(&cer.yaml_path).unwrap();
    let raw2 = rt2.read_raw().unwrap();
    let count2 = raw2
        .iter()
        .filter(|e| {
            e.envelope.get("event_type").and_then(Value::as_str)
                == Some("tn.agents.policy_published")
        })
        .count();
    assert_eq!(count2, 1, "idempotent on unchanged policy");
}

// --- Test helpers ---------------------------------------------------------

/// Like `setup_minimal_btn_ceremony` but mints a tn.agents group too so
/// the runtime can route policy text into it.
fn setup_minimal_btn_ceremony_with_agents(root: &std::path::Path) -> common::BtnCeremony {
    use std::path::PathBuf;
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();

    let dk = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();

    // default group.
    let mut pub_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x22u8; 32]).unwrap();
    let kit = pub_state.mint().unwrap();
    std::fs::write(keystore.join("default.btn.state"), pub_state.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.btn.mykit"), kit.to_bytes()).unwrap();

    // tn.agents group.
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

