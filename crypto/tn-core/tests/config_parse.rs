//! Parsing a minimal tn.yaml.

#[test]
fn parse_example_yaml() {
    let yaml = r#"
ceremony:
  id: cer_test
  mode: local
  cipher: btn
  protocol_events_location: main_log
keystore:
  path: ./keys
device:
  device_identity: "did:key:zABC"
public_fields: [timestamp, event_id, event_type, level]
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - recipient_identity: "did:key:zABC"
    index_epoch: 0
fields: {}
llm_classifier:
  enabled: false
  provider: ""
  model: ""
"#;
    let cfg = tn_core::config::parse(yaml).unwrap();
    assert_eq!(cfg.ceremony.id, "cer_test");
    assert_eq!(cfg.ceremony.cipher, "btn");
    assert_eq!(cfg.device.device_identity, "did:key:zABC");
    assert!(cfg.groups.contains_key("default"));
    assert_eq!(cfg.groups["default"].cipher, "btn");
    assert_eq!(cfg.groups["default"].index_epoch, 0);
    assert_eq!(cfg.public_fields.len(), 4);
}

#[test]
fn parse_handles_missing_optionals() {
    // Minimal yaml — ensure defaults kick in for optional fields.
    let yaml = r#"
ceremony:
  id: cer_min
  cipher: btn
keystore:
  path: ./keys
device:
  device_identity: "did:key:zXYZ"
groups:
  default:
    cipher: btn
"#;
    let cfg = tn_core::config::parse(yaml).unwrap();
    assert_eq!(cfg.ceremony.mode, "local"); // default
                                            // Default flipped from the legacy "main_log" sentinel to a dedicated
                                            // admin-log path (matches Python's LoadedConfig.admin_log_location
                                            // default at python/tn/config.py and aligns with #26).
    assert_eq!(
        cfg.ceremony.protocol_events_location,
        "./.tn/admin/admin.ndjson"
    );
    assert_eq!(cfg.default_policy, "private"); // default
    assert_eq!(cfg.groups["default"].index_epoch, 0); // default
    assert_eq!(cfg.groups["default"].policy, "private"); // default
    assert!(!cfg.vault.enabled);
    assert_eq!(cfg.vault.sync_interval_seconds, 600);
}

#[test]
fn parse_vault_block_defaults_sync_interval_to_600() {
    let yaml = r#"
ceremony:
  id: cer_vault
  cipher: btn
keystore:
  path: ./keys
device:
  device_identity: "did:key:zXYZ"
groups:
  default:
    cipher: btn
vault:
  enabled: true
  url: https://vault.example
  linked_project_id: ""
  autosync: true
"#;
    let cfg = tn_core::config::parse(yaml).unwrap();
    assert!(cfg.vault.enabled);
    assert_eq!(cfg.vault.url.as_deref(), Some("https://vault.example"));
    assert_eq!(cfg.vault.linked_project_id, None);
    assert!(cfg.vault.autosync);
    assert_eq!(cfg.vault.sync_interval_seconds, 600);
    let normalized = cfg.normalized_vault();
    assert!(normalized.enabled);
    assert_eq!(normalized.url.as_deref(), Some("https://vault.example"));
}

#[test]
fn legacy_ceremony_link_fields_populate_normalized_vault_view() {
    let yaml = r#"
ceremony:
  id: cer_vault
  mode: linked
  cipher: btn
  linked_vault: https://legacy-vault.example
  linked_project_id: proj_legacy
keystore:
  path: ./keys
device:
  device_identity: "did:key:zXYZ"
groups:
  default:
    cipher: btn
"#;
    let cfg = tn_core::config::parse(yaml).unwrap();
    assert!(!cfg.vault.enabled);
    assert!(!cfg.vault_declared);
    let normalized = cfg.normalized_vault();
    assert!(normalized.enabled);
    assert_eq!(
        normalized.url.as_deref(),
        Some("https://legacy-vault.example")
    );
    assert_eq!(normalized.linked_project_id.as_deref(), Some("proj_legacy"));
    assert!(normalized.autosync);
    assert_eq!(normalized.sync_interval_seconds, 600);
}

#[test]
fn disabled_vault_block_suppresses_legacy_ceremony_link_fields() {
    let yaml = r#"
ceremony:
  id: cer_vault
  mode: local
  cipher: btn
  linked_vault: https://legacy-vault.example
  linked_project_id: proj_legacy
keystore:
  path: ./keys
device:
  device_identity: "did:key:zXYZ"
groups:
  default:
    cipher: btn
vault:
  enabled: false
  url: ""
  linked_project_id: ""
  autosync: false
  sync_interval_seconds: 600
"#;
    let cfg = tn_core::config::parse(yaml).unwrap();
    assert!(cfg.vault_declared);
    let normalized = cfg.normalized_vault();
    assert!(!normalized.enabled);
    assert_eq!(normalized.url, None);
    assert_eq!(normalized.linked_project_id, None);
    assert!(!normalized.autosync);
    assert_eq!(normalized.sync_interval_seconds, 600);
}
