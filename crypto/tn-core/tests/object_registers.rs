#![cfg(feature = "fs")]

#[cfg(feature = "fs-locking")]
use std::collections::BTreeMap;
use std::fs;
#[cfg(feature = "fs-locking")]
use std::path::Path;

use serde_json::json;
#[cfg(feature = "fs-locking")]
use serde_json::Value;
#[cfg(feature = "fs-locking")]
use tn_core::chain::{compute_row_hash, RowHashInput, ZERO_HASH};
use tn_core::governed::GovernedObject;
use tn_core::runtime::{ObjectRegisters, Objects};
#[cfg(feature = "fs-locking")]
use tn_core::sealed_object::{extract_group_blocks, verify_sealed, ENVELOPE_RESERVED};
#[cfg(feature = "fs-locking")]
use tn_core::signing::signature_b64;
use tn_core::DeviceKey;

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCreate an aggregate.\n### use_for\nResearch.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";
const SECRET: &str = "business-plaintext-must-never-appear-in-registers";

fn object() -> GovernedObject {
    let context = Objects::ephemeral(POLICY, "agents.md", &["data"]).unwrap();
    context
        .seal(
            context
                .draft("research.sample")
                .unwrap()
                .group("data", json!({"private_note": SECRET}))
                .unwrap(),
        )
        .unwrap()
}

#[cfg(feature = "fs-locking")]
fn rows(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[cfg(feature = "fs-locking")]
fn assert_verified(row: &Value) {
    let envelope = row.as_object().unwrap();
    let groups = extract_group_blocks(envelope).unwrap();
    assert!(groups.is_empty());
    let valid = verify_sealed(envelope, &groups);
    assert!(valid.signature, "signature must verify");
    assert!(valid.row_hash, "row hash must recompute");
    assert_eq!(envelope.len(), 14, "only headers and approved metadata");
    assert!(!serde_json::to_string(row).unwrap().contains(SECRET));
    assert!(uuid::Uuid::parse_str(row["event_id"].as_str().unwrap()).is_ok());
    assert!(time::OffsetDateTime::parse(
        row["timestamp"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339
    )
    .is_ok());
}

#[test]
#[cfg(feature = "fs-locking")]
fn separate_registers_sign_metadata_and_resume_their_own_chains() {
    let dir = tempfile::tempdir().unwrap();
    let creation = dir.path().join("service-a/creation.ndjson");
    let release = dir.path().join("service-a/release.ndjson");
    let service_b = dir.path().join("service-b/release.ndjson");
    let device = DeviceKey::generate();
    let object = object();
    let policies = vec!["policy:one".to_owned(), "policy:two".to_owned()];
    let registers = ObjectRegisters::new(Some(creation.clone()), Some(release.clone()));
    assert!(registers
        .record(
            &device,
            "create",
            &object,
            "research",
            "service-a",
            &policies
        )
        .unwrap());
    assert!(registers
        .record(&device, "release", &object, "analysis", "reports", &policies)
        .unwrap());
    let reopened = ObjectRegisters::new(Some(creation.clone()), Some(release.clone()));
    assert!(reopened
        .record(
            &device,
            "create",
            &object,
            "research",
            "service-a",
            &policies
        )
        .unwrap());
    assert!(reopened
        .record(&device, "release", &object, "analysis", "reports", &policies)
        .unwrap());
    assert!(ObjectRegisters::new(None, Some(service_b.clone()))
        .record(&device, "release", &object, "analysis", "reports", &policies)
        .unwrap());

    for (path, action, event_type, purpose, destination) in [
        (
            &creation,
            "create",
            "tn.object.created",
            "research",
            "service-a",
        ),
        (
            &release,
            "release",
            "tn.object.released",
            "analysis",
            "reports",
        ),
    ] {
        let rows = rows(path);
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_verified(row);
            assert_eq!(row["device_identity"], device.did());
            assert_eq!(row["event_type"], event_type);
            assert_eq!(row["level"], "info");
            assert_eq!(row["object_id"], object.id());
            assert_eq!(row["action"], action);
            assert_eq!(row["purpose"], purpose);
            assert_eq!(row["destination"], destination);
            assert_eq!(row["policy_refs"], json!(policies));
        }
        assert_eq!(rows[0]["sequence"], 1);
        assert_eq!(rows[0]["prev_hash"], ZERO_HASH);
        assert_eq!(rows[1]["sequence"], 2);
        assert_eq!(rows[1]["prev_hash"], rows[0]["row_hash"]);
        assert_ne!(rows[1]["event_id"], rows[0]["event_id"]);
    }
    let independent = rows(&service_b);
    assert_eq!(independent.len(), 1);
    assert_eq!(independent[0]["sequence"], 1);
    assert_eq!(independent[0]["prev_hash"], ZERO_HASH);
}

#[test]
fn disabled_actions_do_not_create_the_other_register_or_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let unused = dir.path().join("untouched/register.ndjson");
    let device = DeviceKey::generate();
    let object = object();
    for (registers, action) in [
        (ObjectRegisters::default(), "create"),
        (ObjectRegisters::default(), "release"),
        (ObjectRegisters::new(Some(unused.clone()), None), "release"),
        (ObjectRegisters::new(None, Some(unused.clone())), "create"),
        (ObjectRegisters::new(Some("".into()), None), "create"),
    ] {
        assert!(!registers
            .record(&device, action, &object, "", "", &[])
            .unwrap());
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn unsupported_actions_fail_before_creating_any_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("untouched/register.ndjson");
    assert!(ObjectRegisters::new(Some(path.clone()), Some(path))
        .record(&DeviceKey::generate(), "delete", &object(), "", "", &[])
        .is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
#[cfg(feature = "fs-locking")]
fn one_file_preserves_independent_per_event_type_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("register.ndjson");
    let device = DeviceKey::generate();
    let object = object();
    let registers = ObjectRegisters::new(Some(path.clone()), Some(path.clone()));
    for action in ["create", "release", "create", "release"] {
        registers
            .record(&device, action, &object, "", "", &[])
            .unwrap();
    }
    let rows = rows(&path);
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["sequence"], 1);
    assert_eq!(rows[1]["sequence"], 1);
    assert_eq!(rows[2]["sequence"], 2);
    assert_eq!(rows[3]["sequence"], 2);
    assert_eq!(rows[0]["prev_hash"], ZERO_HASH);
    assert_eq!(rows[1]["prev_hash"], ZERO_HASH);
    assert_eq!(rows[2]["prev_hash"], rows[0]["row_hash"]);
    assert_eq!(rows[3]["prev_hash"], rows[1]["row_hash"]);
}

#[cfg(feature = "fs-locking")]
fn resign(row: &mut Value, device: &DeviceKey) {
    let public_fields: BTreeMap<_, _> = row
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| !ENVELOPE_RESERVED.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let hash = compute_row_hash(&RowHashInput {
        device_identity: device.did(),
        timestamp: row["timestamp"].as_str().unwrap(),
        event_id: row["event_id"].as_str().unwrap(),
        event_type: row["event_type"].as_str().unwrap(),
        level: row["level"].as_str().unwrap(),
        prev_hash: row["prev_hash"].as_str().unwrap(),
        public_fields: &public_fields,
        groups: &BTreeMap::new(),
    });
    row["signature"] = json!(signature_b64(&device.sign(hash.as_bytes())));
    row["row_hash"] = json!(hash);
}

#[test]
#[cfg(feature = "fs-locking")]
fn malformed_or_corrupted_history_is_refused_without_appending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("register.ndjson");
    let device = DeviceKey::generate();
    let object = object();
    let registers = ObjectRegisters::new(Some(path.clone()), None);
    registers
        .record(&device, "create", &object, "research", "reports", &[])
        .unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let row = rows(&path).remove(0);
    let mut changed_metadata = row.clone();
    changed_metadata["purpose"] = json!("tampered");
    let mut changed_signature = row.clone();
    changed_signature["signature"] = json!("AA");
    let mut changed_sequence = row.clone();
    changed_sequence["sequence"] = json!(99);
    let mut changed_previous = row.clone();
    changed_previous["prev_hash"] = json!(object.id());
    resign(&mut changed_previous, &device);
    let mut added_plaintext = row.clone();
    added_plaintext["private_note"] = json!(SECRET);
    resign(&mut added_plaintext, &device);
    let mut wrong_action = row.clone();
    wrong_action["action"] = json!("release");
    resign(&mut wrong_action, &device);
    let corruptions = [
        "not-json\n".to_owned(),
        format!("{original}{{\"event_type\":"),
        original.trim_end().to_owned(),
        format!("{}\n", serde_json::to_string(&changed_metadata).unwrap()),
        format!("{}\n", serde_json::to_string(&changed_signature).unwrap()),
        format!("{}\n", serde_json::to_string(&changed_sequence).unwrap()),
        format!("{}\n", serde_json::to_string(&changed_previous).unwrap()),
        format!("{}\n", serde_json::to_string(&added_plaintext).unwrap()),
        format!("{}\n", serde_json::to_string(&wrong_action).unwrap()),
        original.replacen('{', "{\"sequence\":1,", 1),
        format!("{original}{original}"),
        format!("{original}\n"),
    ];
    for corrupted in corruptions {
        fs::write(&path, &corrupted).unwrap();
        assert!(registers
            .record(&device, "create", &object, "", "", &[])
            .is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), corrupted);
    }
}

#[test]
#[cfg(not(feature = "fs-locking"))]
fn enabled_register_refuses_to_write_without_cross_process_lock_support() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("untouched/register.ndjson");
    assert!(ObjectRegisters::new(Some(path), None)
        .record(&DeviceKey::generate(), "create", &object(), "", "", &[])
        .is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

// Execute environment mutation and competing writers in separate processes so
// other tests cannot observe environment changes or substitute a thread mutex
// for the operating-system file lock being exercised.
#[test]
#[cfg(feature = "fs-locking")]
fn object_register_subprocess_writer() {
    let Ok(mode) = std::env::var("TN_OBJECT_REGISTER_TEST_MODE") else {
        return;
    };
    let path = std::env::var_os("TN_OBJECT_CREATION_REGISTER").unwrap();
    let registers = ObjectRegisters::from_env().unwrap();
    let object = object();
    let device = DeviceKey::generate();
    if mode == "capture_env" {
        std::env::set_var("TN_OBJECT_CREATION_REGISTER", "");
        std::env::remove_var("TN_OBJECT_RELEASE_REGISTER");
        let disabled = ObjectRegisters::from_env().unwrap();
        assert!(!disabled
            .record(&device, "create", &object, "", "", &[])
            .unwrap());
        assert!(!disabled
            .record(&device, "release", &object, "", "", &[])
            .unwrap());
        assert!(!Path::new(&path).exists());
        assert!(registers
            .record(&device, "create", &object, "", "", &[])
            .unwrap());
        assert!(!registers
            .record(&device, "release", &object, "", "", &[])
            .unwrap());
    } else {
        assert_eq!(mode, "concurrent");
        for _ in 0..4 {
            assert!(registers
                .record(&device, "create", &object, "", "", &[])
                .unwrap());
        }
    }
}

#[cfg(feature = "fs-locking")]
fn child_command(path: &Path, mode: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "object_register_subprocess_writer",
            "--nocapture",
        ])
        .env("TN_OBJECT_CREATION_REGISTER", path)
        .env("TN_OBJECT_RELEASE_REGISTER", "")
        .env("TN_OBJECT_REGISTER_TEST_MODE", mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

#[test]
#[cfg(feature = "fs-locking")]
fn environment_paths_are_captured_per_service_without_initializing_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("register.ndjson");
    let output = child_command(&path, "capture_env").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(rows(&path).len(), 1);
}

#[test]
#[cfg(feature = "fs-locking")]
fn concurrent_processes_append_one_unbroken_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("register.ndjson");
    let children: Vec<_> = (0..4)
        .map(|_| child_command(&path, "concurrent").spawn().unwrap())
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    let rows = rows(&path);
    assert_eq!(rows.len(), 16);
    let mut previous = ZERO_HASH;
    for (index, row) in rows.iter().enumerate() {
        assert_verified(row);
        assert_eq!(row["sequence"], (index + 1) as u64);
        assert_eq!(row["prev_hash"], previous);
        previous = row["row_hash"].as_str().unwrap();
    }
}
