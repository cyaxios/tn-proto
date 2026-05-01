//! Multi-group field routing — Rust mirror of the Python and TS test
//! suites in `python/tests/test_multi_group_routing.py` and
//! `ts-sdk/test/multi_group_routing.test.ts`.
//!
//! Verifies:
//!   * `groups[<g>].fields` lists invert into a sorted multi-group map.
//!   * A field declared under N groups is encrypted into all N groups'
//!     payloads; each group's reader sees the same value independently.
//!   * Routing to an unknown group is a load-time error.
//!   * A field listed in both `public_fields` and a group is rejected.
//!   * Legacy flat `fields:` block still loads (back-compat path).

#![cfg(feature = "fs")]

use std::path::{Path, PathBuf};

use tn_core::config::{load as load_config, Config};
use tn_core::Runtime;

/// Build a btn ceremony at `root` with N groups (each a publisher +
/// self-reader). Fills in tn.yaml from `yaml_body` so individual tests
/// can declare arbitrary `groups[<g>].fields` shapes.
fn make_ceremony(root: &Path, group_names: &[&str], yaml_body: &dyn Fn(&str) -> String) -> PathBuf {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();

    // Device key + master index key.
    let dk = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();

    for (i, name) in group_names.iter().enumerate() {
        let seed: [u8; 32] = std::array::from_fn(|j| ((j as u8).wrapping_mul(5)).wrapping_add(7).wrapping_add(i as u8 * 13));
        let mut pub_state =
            tn_btn::PublisherState::setup_with_seed(tn_btn::Config, seed).unwrap();
        let kit = pub_state.mint().unwrap();
        std::fs::write(keystore.join(format!("{name}.btn.state")), pub_state.to_bytes()).unwrap();
        std::fs::write(keystore.join(format!("{name}.btn.mykit")), kit.to_bytes()).unwrap();
    }

    let yaml = yaml_body(dk.did());
    let yaml_path = root.join("tn.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    yaml_path
}

fn yaml_body_two_groups_share_field(did: &str) -> String {
    format!(
        "ceremony: {{id: cer_mg, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         me: {{did: \"{did}\"}}\n\
         public_fields: [timestamp, event_id, event_type, level]\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20 a:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   fields: [email]\n\
         \x20 b:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   fields: [email]\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    )
}

#[test]
fn config_inverts_groups_fields_into_sorted_map() {
    let td = tempfile::tempdir().unwrap();
    let yaml = make_ceremony(
        td.path(),
        &["default", "a", "b"],
        &yaml_body_two_groups_share_field,
    );
    let cfg: Config = load_config(&yaml).unwrap();
    let map = cfg.field_to_groups().unwrap();
    assert_eq!(map.get("email").unwrap(), &vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn emit_encrypts_a_field_into_every_listed_group() {
    let td = tempfile::tempdir().unwrap();
    let yaml = make_ceremony(
        td.path(),
        &["default", "a", "b"],
        &yaml_body_two_groups_share_field,
    );
    let rt = Runtime::init(&yaml).unwrap();

    let mut fields = serde_json::Map::new();
    fields.insert("email".into(), serde_json::json!("alice@example.com"));
    rt.emit_with(
        "info",
        "evt.multi",
        fields,
        Some("2026-04-25T00:00:00.000000Z"),
        Some("00000000-0000-0000-0000-00000000000a"),
    )
    .unwrap();

    let log = rt.log_path().to_path_buf();
    drop(rt);
    let contents = std::fs::read_to_string(&log).unwrap();
    let mut user_lines = Vec::new();
    for line in contents.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        if !v["event_type"].as_str().unwrap_or("").starts_with("tn.") {
            user_lines.push(v);
        }
    }
    assert_eq!(user_lines.len(), 1);
    let env = &user_lines[0];
    assert!(env.get("a").is_some(), "group a payload missing");
    assert!(env.get("b").is_some(), "group b payload missing");
    // Each group's index token is independent (different group index key).
    let a_hash = env["a"]["field_hashes"]["email"].as_str().unwrap();
    let b_hash = env["b"]["field_hashes"]["email"].as_str().unwrap();
    assert_ne!(a_hash, b_hash);

    // And the runtime's own read path returns plaintext for both groups.
    let rt2 = Runtime::init(&yaml).unwrap();
    let entries: Vec<_> = rt2
        .read_raw()
        .unwrap()
        .into_iter()
        .filter(|e| {
            e.envelope["event_type"].as_str().unwrap_or("") == "evt.multi"
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let pt = &entries[0].plaintext_per_group;
    assert_eq!(pt["a"]["email"].as_str(), Some("alice@example.com"));
    assert_eq!(pt["b"]["email"].as_str(), Some("alice@example.com"));
}

#[test]
fn field_to_groups_list_is_sorted_alphabetically() {
    let td = tempfile::tempdir().unwrap();
    let yaml = make_ceremony(
        td.path(),
        &["default", "zeta", "alpha"],
        &|did| {
            format!(
                "ceremony: {{id: cer_sort, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
                 keystore: {{path: ./.tn/keys}}\n\
                 me: {{did: \"{did}\"}}\n\
                 public_fields: [timestamp, event_id, event_type, level]\n\
                 default_policy: private\n\
                 groups:\n\
                 \x20 default:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 \x20 zeta:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 \x20   fields: [x]\n\
                 \x20 alpha:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 \x20   fields: [x]\n\
                 fields: {{}}\n\
                 llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
            )
        },
    );
    let cfg: Config = load_config(&yaml).unwrap();
    let map = cfg.field_to_groups().unwrap();
    assert_eq!(
        map.get("x").unwrap(),
        &vec!["alpha".to_string(), "zeta".to_string()]
    );
}

#[test]
fn field_routed_to_unknown_group_is_a_load_error() {
    // Use the legacy flat `fields:` block to point at a non-existent group;
    // canonical `groups[<g>].fields` can't reference other groups.
    let td = tempfile::tempdir().unwrap();
    let yaml = make_ceremony(
        td.path(),
        &["default"],
        &|did| {
            format!(
                "ceremony: {{id: cer_unknown, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
                 keystore: {{path: ./.tn/keys}}\n\
                 me: {{did: \"{did}\"}}\n\
                 public_fields: [timestamp]\n\
                 default_policy: private\n\
                 groups:\n\
                 \x20 default:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 fields:\n\
                 \x20 x: {{group: ghost_group}}\n\
                 llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
            )
        },
    );
    let cfg: Config = load_config(&yaml).unwrap();
    let err = cfg.field_to_groups().expect_err("expected unknown-group error");
    let msg = format!("{err}");
    assert!(msg.contains("unknown group"), "unexpected error: {msg}");
}

#[test]
fn field_in_public_and_group_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    let yaml = make_ceremony(
        td.path(),
        &["default", "a"],
        &|did| {
            format!(
                "ceremony: {{id: cer_amb, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
                 keystore: {{path: ./.tn/keys}}\n\
                 me: {{did: \"{did}\"}}\n\
                 public_fields: [timestamp, event_id, event_type, level, email]\n\
                 default_policy: private\n\
                 groups:\n\
                 \x20 default:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 \x20 a:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 \x20   fields: [email]\n\
                 fields: {{}}\n\
                 llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
            )
        },
    );
    let cfg: Config = load_config(&yaml).unwrap();
    let err = cfg.field_to_groups().expect_err("expected ambiguity error");
    let msg = format!("{err}");
    assert!(msg.contains("public_fields"), "unexpected error: {msg}");
}

#[test]
fn legacy_flat_fields_block_still_loads() {
    let td = tempfile::tempdir().unwrap();
    let yaml = make_ceremony(
        td.path(),
        &["default", "secrets"],
        &|did| {
            format!(
                "ceremony: {{id: cer_legacy, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
                 keystore: {{path: ./.tn/keys}}\n\
                 me: {{did: \"{did}\"}}\n\
                 public_fields: [timestamp]\n\
                 default_policy: private\n\
                 groups:\n\
                 \x20 default:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 \x20 secrets:\n\
                 \x20   policy: private\n\
                 \x20   cipher: btn\n\
                 \x20   recipients:\n\
                 \x20     - {{did: \"{did}\"}}\n\
                 fields:\n\
                 \x20 password: {{group: secrets}}\n\
                 llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
            )
        },
    );
    let cfg: Config = load_config(&yaml).unwrap();
    let map = cfg.field_to_groups().unwrap();
    assert_eq!(map.get("password").unwrap(), &vec!["secrets".to_string()]);
}
