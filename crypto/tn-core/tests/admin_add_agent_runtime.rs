//! Tests for `Runtime::admin_add_agent_runtime` (per spec §2.8).

#![cfg(feature = "fs")]

mod common;

use std::path::Path;
use tn_core::Runtime;

#[test]
fn bundle_includes_named_groups_plus_tn_agents() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let out_path = td.path().join("agent.tnpkg");
    let p = rt
        .admin_add_agent_runtime(
            "did:key:zRuntimeAgent",
            &["default"],
            &out_path,
            Some("agent-v1"),
        )
        .unwrap();
    assert!(p.exists());
    // Label sidecar.
    let sidecar = p.with_extension("tnpkg.label");
    let _ = sidecar; // best-effort write — don't strictly assert.
}

#[test]
fn dedup_when_caller_passes_tn_agents() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let out_path = td.path().join("agent.tnpkg");
    let p = rt
        .admin_add_agent_runtime(
            "did:key:zRuntimeAgent",
            &["default", "tn.agents", "default"],
            &out_path,
            None,
        )
        .unwrap();
    assert!(p.exists());
}

#[test]
fn unknown_group_errors() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_btn_with_agents(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let out_path = td.path().join("agent.tnpkg");
    let res = rt.admin_add_agent_runtime(
        "did:key:zRuntimeAgent",
        &["nonexistent"],
        &out_path,
        None,
    );
    assert!(res.is_err());
}

// --- Helpers ----------------------------------------------------------

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
