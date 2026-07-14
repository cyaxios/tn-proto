//! Group planning for public-only recipient preparation.

use std::fs;
use std::path::Path;

use tn_core::runtime::Runtime;

fn mixed_runtime(root: &Path) -> Runtime {
    let keystore = root.join(".tn").join("keys");
    fs::create_dir_all(&keystore).expect("keystore");
    let device = tn_core::DeviceKey::generate();
    fs::write(keystore.join("local.private"), device.private_bytes()).expect("device key");
    fs::write(keystore.join("index_master.key"), [0x31_u8; 32]).expect("index key");

    let mut state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x32_u8; 32]).expect("btn");
    let kit = state.mint().expect("self kit");
    fs::write(keystore.join("broadcast.btn.state"), state.to_bytes()).expect("btn state");
    fs::write(keystore.join("broadcast.btn.mykit"), kit.to_bytes()).expect("btn kit");

    let did = device.did();
    let yaml = format!(
        "ceremony: {{id: cer_prepare, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 broadcast:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 partners:\n\
         \x20   policy: private\n\
         \x20   cipher: jwe\n\
         \x20   recipients: []\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n"
    );
    let yaml_path = root.join("tn.yaml");
    fs::write(&yaml_path, yaml).expect("yaml");
    Runtime::init(&yaml_path).expect("mixed runtime")
}

#[test]
fn plan_partitions_kit_groups_from_public_only_jwe_groups() {
    let temp = tempfile::tempdir().expect("tempdir");
    let runtime = mixed_runtime(temp.path());

    let plan = runtime
        .plan_recipient_preparation(Some(&["partners", "broadcast", "partners"]))
        .expect("plan");

    assert_eq!(plan.requested_groups, vec!["partners", "broadcast"]);
    assert_eq!(plan.kit_groups, vec!["broadcast"]);
    assert_eq!(plan.jwe_groups, vec!["partners"]);
    assert!(!temp.path().join(".tn/keys/partners.jwe.mykey").exists());
}

#[test]
fn legacy_mixed_bundle_rejects_jwe_before_consuming_btn_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let runtime = mixed_runtime(temp.path());
    let state_path = temp.path().join(".tn/keys/broadcast.btn.state");
    let before = fs::read(&state_path).expect("state before");
    let out = temp.path().join("legacy-mixed.tnpkg");

    let error = runtime
        .bundle_for_recipient("did:key:zReader", &out, Some(&["broadcast", "partners"]))
        .expect_err("legacy bundler must reject JWE");

    assert!(error.to_string().contains("cipher=jwe"));
    assert_eq!(fs::read(state_path).expect("state after"), before);
    assert!(!out.exists());
}
