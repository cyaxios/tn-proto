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
me:
  did: "did:key:zABC"
public_fields: [timestamp, event_id, event_type, level]
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - did: "did:key:zABC"
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
    assert_eq!(cfg.me.did, "did:key:zABC");
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
me:
  did: "did:key:zXYZ"
groups:
  default:
    cipher: btn
"#;
    let cfg = tn_core::config::parse(yaml).unwrap();
    assert_eq!(cfg.ceremony.mode, "local"); // default
    assert_eq!(cfg.ceremony.protocol_events_location, "main_log"); // default
    assert_eq!(cfg.default_policy, "private"); // default
    assert_eq!(cfg.groups["default"].index_epoch, 0); // default
    assert_eq!(cfg.groups["default"].policy, "private"); // default
}
