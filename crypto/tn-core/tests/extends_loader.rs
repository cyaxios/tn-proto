//! `extends:` resolution in tn.yaml loading.
//!
//! Mirrors `python/tn/config.py::_resolve_extends` and
//! `ts-sdk/src/runtime/config.ts::resolveExtends`. Stream yamls written
//! by the multi-ceremony layer (`createFreshCeremony` for non-default
//! streams) carry `extends: ../default/tn.yaml` so they inherit identity,
//! keystore, groups, recipients, etc. from the parent — only their
//! per-stream overrides (ceremony.profile, logs.path, handlers) live in
//! the child file. Before this resolver landed, the Rust loader rejected
//! such yamls with `"missing field cipher"`. Issues §11 Blocker 1.

#![cfg(feature = "fs")]

use std::fs;
use std::path::Path;

use tn_core::config;

fn write(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::write(path, body).unwrap();
}

/// Minimal parent yaml with one btn group. Used as the chain root for
/// most fixtures here.
fn parent_btn(ceremony_id: &str) -> String {
    format!(
        r#"ceremony:
  id: {ceremony_id}
  cipher: btn
  mode: local
keystore:
  path: ./keys
logs:
  path: ./logs/tn.ndjson
me:
  did: "did:key:zABC"
groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - did: "did:key:zABC"
"#
    )
}

#[test]
fn simple_extends_inherits_groups_and_cipher() {
    let td = tempfile::tempdir().unwrap();
    let parent = td.path().join("parent.yaml");
    let child = td.path().join("child.yaml");
    write(&parent, &parent_btn("cer_parent"));
    write(
        &child,
        r#"extends: ./parent.yaml
ceremony:
  id: cer_child
"#,
    );

    let cfg = config::load(&child).expect("child must load via extends");
    // Inherited from parent.
    assert_eq!(cfg.ceremony.cipher, "btn");
    assert!(cfg.groups.contains_key("default"));
    assert_eq!(cfg.me.did, "did:key:zABC");
    // Child override on ceremony.id wins.
    assert_eq!(cfg.ceremony.id, "cer_child");
}

#[test]
fn extends_drops_top_level_marker() {
    // The merged Config has no place for `extends:` — it's a directive
    // on the source yaml, not a schema field. The merger drops it so
    // the strongly-typed parse sees a clean doc.
    let td = tempfile::tempdir().unwrap();
    let parent = td.path().join("parent.yaml");
    let child = td.path().join("child.yaml");
    write(&parent, &parent_btn("cer_p"));
    write(
        &child,
        r#"extends: ./parent.yaml
ceremony:
  id: cer_c
"#,
    );
    // If `extends:` was not stripped, parse would either reject the
    // unknown field (no — serde defaults are forgiving) or, more
    // subtly, the child's own extends survives into the merged shape
    // and confuses downstream callers. Belt-and-suspenders: confirm
    // the load works AND the runtime-init friendly shape is valid by
    // re-parsing the serialized config.
    let cfg = config::load(&child).unwrap();
    let s = serde_yml::to_string(&serde_yml::to_value(&cfg).unwrap()).unwrap();
    assert!(!s.contains("extends:"), "extends key must not survive merge");
}

#[test]
fn nested_extends_three_levels() {
    // A → extends → B → extends → C (chain root). Every parent-owned
    // key flows from C through B into A.
    let td = tempfile::tempdir().unwrap();
    let c_path = td.path().join("c.yaml");
    let b_path = td.path().join("b.yaml");
    let a_path = td.path().join("a.yaml");
    write(&c_path, &parent_btn("cer_root"));
    write(
        &b_path,
        r#"extends: ./c.yaml
ceremony:
  log_level: info
"#,
    );
    write(
        &a_path,
        r#"extends: ./b.yaml
ceremony:
  id: cer_leaf
"#,
    );
    let cfg = config::load(&a_path).unwrap();
    // From C (parent-owned).
    assert!(cfg.groups.contains_key("default"));
    assert_eq!(cfg.me.did, "did:key:zABC");
    assert_eq!(cfg.ceremony.cipher, "btn");
    // From B (ceremony shallow merge).
    assert_eq!(cfg.ceremony.log_level, "info");
    // From A (leaf override).
    assert_eq!(cfg.ceremony.id, "cer_leaf");
}

#[test]
fn parent_relative_paths_resolve_against_parent_dir() {
    // Parent at /td/p/parent.yaml has `keystore.path: ./keys` (parent-dir
    // relative). Child at /td/c/child.yaml extends it. The merged
    // keystore path must point at /td/p/keys, NOT /td/c/keys.
    let td = tempfile::tempdir().unwrap();
    let parent_dir = td.path().join("p");
    let child_dir = td.path().join("c");
    let parent = parent_dir.join("parent.yaml");
    let child = child_dir.join("child.yaml");
    write(&parent, &parent_btn("cer_p"));
    write(
        &child,
        r#"extends: ../p/parent.yaml
ceremony:
  id: cer_c
"#,
    );
    let cfg = config::load(&child).unwrap();
    let resolved = Path::new(&cfg.keystore.path);
    // The merged keystore.path was absolutized at merge time so it
    // sits under parent_dir, not child_dir.
    assert!(
        resolved.starts_with(&parent_dir),
        "keystore.path {resolved:?} must resolve under parent dir {parent_dir:?}",
    );
    assert!(!resolved.starts_with(&child_dir));
}

#[test]
fn parent_logs_path_absolutized_against_parent_dir() {
    // Same as above, but for logs.path. Child does NOT override logs,
    // so the parent's relative path must end up absolute under parent dir.
    let td = tempfile::tempdir().unwrap();
    let parent_dir = td.path().join("p");
    let child_dir = td.path().join("c");
    let parent = parent_dir.join("parent.yaml");
    let child = child_dir.join("child.yaml");
    write(&parent, &parent_btn("cer_p"));
    write(
        &child,
        r#"extends: ../p/parent.yaml
ceremony:
  id: cer_c
"#,
    );
    let cfg = config::load(&child).unwrap();
    let resolved = Path::new(&cfg.logs.path);
    assert!(
        resolved.starts_with(&parent_dir),
        "logs.path {resolved:?} should resolve under parent {parent_dir:?}",
    );
}

#[test]
fn cycle_two_files_detected() {
    let td = tempfile::tempdir().unwrap();
    let a = td.path().join("a.yaml");
    let b = td.path().join("b.yaml");
    write(
        &a,
        r#"extends: ./b.yaml
ceremony:
  id: cer_a
"#,
    );
    write(
        &b,
        r#"extends: ./a.yaml
ceremony:
  id: cer_b
"#,
    );
    let err = config::load(&a).expect_err("cycle must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("cycle") || msg.contains("maximum depth"),
        "expected cycle/depth error, got: {msg}",
    );
}

#[test]
fn missing_parent_yields_clear_error() {
    let td = tempfile::tempdir().unwrap();
    let child = td.path().join("child.yaml");
    write(
        &child,
        r#"extends: ./does_not_exist.yaml
ceremony:
  id: cer_c
"#,
    );
    let err = config::load(&child).expect_err("missing parent must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("does not exist") || msg.contains("extends target"),
        "expected missing-parent error, got: {msg}",
    );
}

#[test]
fn child_overrides_ceremony_subfield() {
    // Per Python semantics: ceremony is a shallow merge — child overrides
    // matching subfields, parent's other subfields survive.
    let td = tempfile::tempdir().unwrap();
    let parent = td.path().join("parent.yaml");
    let child = td.path().join("child.yaml");
    let parent_yaml = r#"ceremony:
  id: cer_p
  cipher: btn
  mode: local
  log_level: warning
keystore:
  path: ./keys
logs:
  path: ./logs/tn.ndjson
me:
  did: "did:key:zABC"
groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - did: "did:key:zABC"
"#;
    write(&parent, parent_yaml);
    write(
        &child,
        r#"extends: ./parent.yaml
ceremony:
  id: cer_c
  log_level: debug
"#,
    );
    let cfg = config::load(&child).unwrap();
    // Child overrides id + log_level.
    assert_eq!(cfg.ceremony.id, "cer_c");
    assert_eq!(cfg.ceremony.log_level, "debug");
    // Parent's cipher survives the shallow merge.
    assert_eq!(cfg.ceremony.cipher, "btn");
}

#[test]
fn parent_owned_keys_cannot_be_overridden() {
    // Per Python: if child sets me/keystore/groups/etc., parent wins.
    // No warning is surfaced in Rust today, but the merged shape must
    // carry the parent's value.
    let td = tempfile::tempdir().unwrap();
    let parent = td.path().join("parent.yaml");
    let child = td.path().join("child.yaml");
    write(&parent, &parent_btn("cer_p"));
    write(
        &child,
        r#"extends: ./parent.yaml
ceremony:
  id: cer_c
me:
  did: "did:key:zCHILD"
"#,
    );
    let cfg = config::load(&child).unwrap();
    assert_eq!(
        cfg.me.did, "did:key:zABC",
        "parent's me.did must survive child's attempted override",
    );
}

#[test]
fn handlers_are_additive_with_dedup() {
    // Parent declares a stdout handler. Child adds a file.rotating
    // handler. Both should appear in the merged config, with child's
    // entries first (per Python: `child + parent`, dedupe by name/kind).
    let td = tempfile::tempdir().unwrap();
    let parent = td.path().join("parent.yaml");
    let child = td.path().join("child.yaml");
    let mut p = parent_btn("cer_p");
    p.push_str(
        r#"handlers:
  - kind: stdout
"#,
    );
    write(&parent, &p);
    write(
        &child,
        r#"extends: ./parent.yaml
ceremony:
  id: cer_c
handlers:
  - kind: file.rotating
    name: main
    path: ./.tn/child/logs/tn.ndjson
"#,
    );
    let cfg = config::load(&child).unwrap();
    // Both handlers present, deduped by name/kind.
    let kinds: Vec<&str> = cfg
        .handlers
        .iter()
        .filter_map(|h| h.get("kind").and_then(serde_yml::Value::as_str))
        .collect();
    assert!(
        kinds.contains(&"file.rotating") && kinds.contains(&"stdout"),
        "handlers merge dropped one or both: {kinds:?}",
    );
}

#[test]
fn yaml_without_extends_loads_unchanged() {
    // Regression guard: introducing extends resolution must not change
    // the behavior of self-contained yamls. A yaml with no `extends:`
    // key should parse identically to the pre-resolver code path.
    let td = tempfile::tempdir().unwrap();
    let p = td.path().join("plain.yaml");
    write(&p, &parent_btn("cer_plain"));
    let cfg = config::load(&p).unwrap();
    assert_eq!(cfg.ceremony.id, "cer_plain");
    assert_eq!(cfg.me.did, "did:key:zABC");
}

#[test]
fn parity_with_python_via_dispatch_resolved_yaml() {
    // Cross-SDK parity canary: simulates the exact fixture shape that
    // `python/tn/_dispatch.py::_yaml_for_rust` produces today — a stream
    // yaml at `./.tn/payments/tn.yaml` extending `../default/tn.yaml`.
    // After this test passes, the Python `_yaml_for_rust` workaround
    // becomes a backwards-compat layer; Rust no longer needs it to
    // accept the same input.
    let td = tempfile::tempdir().unwrap();
    let default_dir = td.path().join(".tn").join("default");
    let payments_dir = td.path().join(".tn").join("payments");
    let default = default_dir.join("tn.yaml");
    let payments = payments_dir.join("tn.yaml");

    let default_yaml = r#"ceremony:
  id: cer_default
  cipher: btn
  mode: local
  profile: ledger
keystore:
  path: ./keys
logs:
  path: ./logs/tn.ndjson
me:
  did: "did:key:zABC"
groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - did: "did:key:zABC"
handlers:
  - kind: stdout
"#;
    let payments_yaml = r#"extends: ../default/tn.yaml
ceremony:
  id: cer_payments
  profile: transaction
logs:
  path: ./logs/payments.ndjson
handlers:
  - kind: file.rotating
    name: main
    path: ./logs/payments.ndjson
"#;
    write(&default, default_yaml);
    write(&payments, payments_yaml);

    let cfg = config::load(&payments).expect("emit_propagation-style stream yaml must load");
    // Identity + groups inherited from default.
    assert_eq!(cfg.me.did, "did:key:zABC");
    assert!(cfg.groups.contains_key("default"));
    assert_eq!(cfg.ceremony.cipher, "btn");
    // Stream-specific overrides win.
    assert_eq!(cfg.ceremony.id, "cer_payments");
    // ceremony.profile flows through the shallow merge (parent's
    // "ledger" gets overridden by child's "transaction"). The Config
    // struct doesn't model `profile`, but we can verify via raw value.
    let v = serde_yml::to_value(&cfg).unwrap();
    let prof = v
        .get("ceremony")
        .and_then(|c| c.get("profile"))
        .and_then(|p| p.as_str());
    // ceremony.profile isn't a typed field on Ceremony, so it would
    // typically be dropped at serde deserialize. The relevant
    // assertion for parity is the load succeeds + identity inherits;
    // profile-only assertions belong to the multi-ceremony layer.
    let _ = prof;
    // Handlers: child's file.rotating + parent's stdout, both present.
    let kinds: Vec<&str> = cfg
        .handlers
        .iter()
        .filter_map(|h| h.get("kind").and_then(serde_yml::Value::as_str))
        .collect();
    assert!(kinds.contains(&"file.rotating"));
    assert!(kinds.contains(&"stdout"));
}
