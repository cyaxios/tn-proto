mod common;

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use tempfile::TempDir;
use tn_proto::{
    AbsorbReceiptExt, BundleForRecipientOptions, MintInvitationOptions, ReadOptions,
    SecretExportConsent, Tn,
};

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn python_emits_rust_reads() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let yaml_path = run_python(
        tmp.path(),
        r#"
import json
import pathlib
import sys

import tn

tn.init("interop_py")
tn.info("py.created", marker="python-to-rust")
print(tn.current_config().yaml_path)
tn.flush_and_close()
"#,
        &[],
    );

    let tn = Tn::init(yaml_path.trim())?;
    let entries = tn.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    let entry = common::find_event(&entries, "py.created");
    assert_eq!(
        entry.get("marker").and_then(Value::as_str),
        Some("python-to-rust")
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn rust_emits_python_reads() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let yaml_path = run_python(
        tmp.path(),
        r#"
import tn

tn.init("interop_py")
print(tn.current_config().yaml_path)
tn.flush_and_close()
"#,
        &[],
    );
    let yaml_path = yaml_path.trim().to_string();

    let tn = Tn::init(&yaml_path)?;
    tn.info("rust.created", json!({ "marker": "rust-to-python" }))?;
    tn.close()?;

    let output = run_python(
        tmp.path(),
        r#"
import json
import sys

import tn

tn.init(sys.argv[1])
rows = []
for entry in tn.read(all_runs=True):
    rows.append({
        "event_type": getattr(entry, "event_type", None),
        "fields": getattr(entry, "fields", {}),
    })
print(json.dumps(rows, sort_keys=True))
tn.flush_and_close()
"#,
        &[&yaml_path],
    );
    assert!(
        output.contains("rust.created") && output.contains("rust-to-python"),
        "Python read did not see Rust event: {output}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn rust_admin_snapshot_python_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-admin-snapshot.tnpkg");

    let mut producer = Tn::ephemeral()?;
    producer
        .admin()
        .ensure_group("payments", ["order_id", "amount"])?;
    producer.info(
        "payment.created",
        json!({ "order_id": "ord-rust-export", "amount": 42 }),
    )?;
    producer.pkg().export_admin_snapshot(&pkg_path)?;

    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let output = run_python(
        tmp.path(),
        r#"
import json
import sys

import tn

tn.init("py_consumer")
receipt = tn.pkg.absorb(sys.argv[1])
print(json.dumps({
    "kind": getattr(receipt, "kind", None),
    "legacy_status": getattr(receipt, "legacy_status", None),
    "accepted_count": getattr(receipt, "accepted_count", None),
    "deduped_count": getattr(receipt, "deduped_count", None),
    "noop": getattr(receipt, "noop", None),
}, sort_keys=True))
tn.flush_and_close()
"#,
        &[&pkg_arg],
    );
    let receipt = last_json_object(&output);
    assert_eq!(
        receipt.get("kind").and_then(Value::as_str),
        Some("admin_log_snapshot")
    );
    assert_ne!(
        receipt.get("legacy_status").and_then(Value::as_str),
        Some("rejected"),
        "Python rejected Rust admin snapshot: {receipt}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn python_admin_snapshot_rust_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("python-admin-snapshot.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();

    run_python(
        tmp.path(),
        r#"
import sys

import tn

tn.init("py_producer")
tn.info("py.package.created", marker="python-package-to-rust")
tn.pkg.export(sys.argv[1], kind="admin_log_snapshot")
print(sys.argv[1])
tn.flush_and_close()
"#,
        &[&pkg_arg],
    );

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "admin_log_snapshot");
    assert_ne!(
        receipt.legacy_status, "rejected",
        "Rust rejected Python admin snapshot: {receipt:?}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn rust_project_seed_python_bootstrap_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-project-seed.tnpkg");
    let restore_dir = tmp.path().join("py-restore");

    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let producer_did = producer.did().to_string();
    producer
        .pkg()
        .export_project_seed(&pkg_path, None, SecretExportConsent::acknowledge())?;

    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let restore_arg = restore_dir.to_string_lossy().to_string();
    let output = run_python(
        tmp.path(),
        r#"
import json
import os
import sys
from pathlib import Path

import tn
from tn.signing import DeviceKey

pkg_path = sys.argv[1]
restore_dir = Path(sys.argv[2])
restore_dir.mkdir(parents=True, exist_ok=True)

previous = os.getcwd()
os.chdir(restore_dir)
try:
    receipt = tn.pkg.absorb(pkg_path)
    cfg = tn.current_config()
    did = str(cfg.device.did)
    derived_did = str(DeviceKey.from_private_bytes((cfg.keystore / "local.private").read_bytes()).did)
    groups = sorted(cfg.groups.keys())
    tn.info("py.restored.project_seed", marker="rust-project-seed-to-python")
    rows = [entry for entry in tn.read() if not entry.event_type.startswith("tn.")]
    last = rows[-1] if rows else None
    print(json.dumps({
        "kind": getattr(receipt, "kind", None),
        "legacy_status": getattr(receipt, "legacy_status", None),
        "did": did,
        "derived_did": derived_did,
        "groups": groups,
        "event_type": getattr(last, "event_type", None),
        "fields": getattr(last, "fields", None),
    }, sort_keys=True))
    tn.flush_and_close()
finally:
    os.chdir(previous)
"#,
        &[&pkg_arg, &restore_arg],
    );

    let restored = last_json_object(&output);
    assert_eq!(
        restored.get("kind").and_then(Value::as_str),
        Some("project_seed")
    );
    assert_ne!(
        restored.get("legacy_status").and_then(Value::as_str),
        Some("rejected"),
        "Python rejected Rust project_seed: {restored}"
    );
    assert_eq!(
        restored.get("did").and_then(Value::as_str),
        Some(producer_did.as_str())
    );
    assert_eq!(
        restored.get("derived_did").and_then(Value::as_str),
        Some(producer_did.as_str())
    );
    assert_eq!(
        restored.get("event_type").and_then(Value::as_str),
        Some("py.restored.project_seed")
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn python_project_seed_rust_verifies_and_stashes() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("python-project-seed.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();

    run_python(
        tmp.path(),
        r#"
import sys

import tn

tn.init("py_project_seed_producer")
tn.pkg.export(sys.argv[1], kind="project_seed", confirm_includes_secrets=True)
print(sys.argv[1])
tn.flush_and_close()
"#,
        &[&pkg_arg],
    );

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "project_seed");
    assert_eq!(receipt.legacy_status, "stashed");
    assert!(
        receipt.legacy_reason.contains("no bootstrap handler yet"),
        "unexpected Rust project_seed receipt: {receipt:?}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn rust_kit_bundle_python_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-kit-bundle.tnpkg");

    let producer = Tn::ephemeral()?;
    producer.pkg().export_kit_bundle(
        &pkg_path,
        Some(vec!["default".to_string()]),
        Some("did:key:zPythonInteropRecipient".to_string()),
    )?;

    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let output = run_python(
        tmp.path(),
        r#"
import json
import sys

import tn

tn.init("py_kit_consumer")
receipt = tn.pkg.absorb(sys.argv[1])
duplicate = tn.pkg.absorb(sys.argv[1])
print(json.dumps({
    "kind": getattr(receipt, "kind", None),
    "legacy_status": getattr(receipt, "legacy_status", None),
    "accepted_count": getattr(receipt, "accepted_count", None),
    "deduped_count": getattr(receipt, "deduped_count", None),
    "replaced_kit_paths": [str(path) for path in getattr(receipt, "replaced_kit_paths", [])],
    "duplicate_status": getattr(duplicate, "legacy_status", None),
    "duplicate_deduped_count": getattr(duplicate, "deduped_count", None),
}, sort_keys=True))
tn.flush_and_close()
"#,
        &[&pkg_arg],
    );

    let receipt = last_json_object(&output);
    assert_eq!(
        receipt.get("kind").and_then(Value::as_str),
        Some("kit_bundle")
    );
    assert_ne!(
        receipt.get("legacy_status").and_then(Value::as_str),
        Some("rejected"),
        "Python rejected Rust kit_bundle: {receipt}"
    );
    assert!(
        receipt
            .get("accepted_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "Python should install at least one Rust kit: {receipt}"
    );
    assert!(
        receipt
            .get("duplicate_deduped_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "Python duplicate absorb should dedupe the Rust kit: {receipt}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn rust_sealed_kit_bundle_python_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-sealed-kit-bundle.tnpkg");

    let consumer_info = run_python(
        tmp.path(),
        r#"
import json

import tn

tn.init("py_sealed_kit_consumer")
cfg = tn.current_config()
print(json.dumps({
    "did": str(cfg.device.did),
    "yaml": str(cfg.yaml_path),
}, sort_keys=True))
tn.flush_and_close()
"#,
        &[],
    );
    let consumer_info = last_json_object(&consumer_info);
    let consumer_did = consumer_info
        .get("did")
        .and_then(Value::as_str)
        .expect("Python should print consumer did")
        .to_string();
    let consumer_yaml = consumer_info
        .get("yaml")
        .and_then(Value::as_str)
        .expect("Python should print consumer yaml")
        .to_string();

    let producer = Tn::ephemeral()?;
    producer.pkg().bundle_for_recipient(
        &consumer_did,
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: true,
        },
    )?;

    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let output = run_python(
        tmp.path(),
        r#"
import json
import sys
from pathlib import Path

import tn

tn.init(sys.argv[1])
receipt = tn.pkg.absorb(sys.argv[2])
duplicate = tn.pkg.absorb(sys.argv[2])
cfg = tn.current_config()
print(json.dumps({
    "kind": getattr(receipt, "kind", None),
    "legacy_status": getattr(receipt, "legacy_status", None),
    "accepted_count": getattr(receipt, "accepted_count", None),
    "deduped_count": getattr(receipt, "deduped_count", None),
    "duplicate_status": getattr(duplicate, "legacy_status", None),
    "duplicate_deduped_count": getattr(duplicate, "deduped_count", None),
    "kit_exists": (Path(cfg.keystore) / "default.btn.mykit").exists(),
}, sort_keys=True))
tn.flush_and_close()
"#,
        &[&consumer_yaml, &pkg_arg],
    );

    let receipt = last_json_object(&output);
    assert_eq!(
        receipt.get("kind").and_then(Value::as_str),
        Some("kit_bundle")
    );
    assert_ne!(
        receipt.get("legacy_status").and_then(Value::as_str),
        Some("rejected"),
        "Python rejected Rust sealed kit_bundle: {receipt}"
    );
    assert!(
        receipt
            .get("accepted_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "Python should install the Rust sealed kit: {receipt}"
    );
    assert_eq!(
        receipt.get("kit_exists").and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        receipt
            .get("duplicate_deduped_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "Python duplicate absorb should dedupe the Rust sealed kit: {receipt}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn python_kit_bundle_rust_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("python-kit-bundle.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();

    run_python(
        tmp.path(),
        r#"
import sys

import tn

tn.init("py_kit_producer")
tn.pkg.export(sys.argv[1], kind="kit_bundle")
print(sys.argv[1])
tn.flush_and_close()
"#,
        &[&pkg_arg],
    );

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_ne!(receipt.legacy_status, "rejected");
    assert!(
        receipt.accepted_count > 0,
        "Rust should install at least one Python kit: {receipt:?}"
    );

    let duplicate = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(duplicate.kind, "kit_bundle");
    assert_eq!(duplicate.legacy_status, "no_op");
    assert!(duplicate.deduped_count > 0);

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn python_sealed_kit_bundle_rust_absorbs() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("python-sealed-kit-bundle.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let consumer = Tn::ephemeral()?;
    let recipient_did = consumer.did().to_string();

    run_python(
        tmp.path(),
        r#"
import sys

import tn

tn.init("py_sealed_kit_producer")
tn.pkg.bundle_for_recipient(
    sys.argv[1],
    sys.argv[2],
    groups=["default"],
    seal_for_recipient=True,
)
print(sys.argv[2])
tn.flush_and_close()
"#,
        &[&recipient_did, &pkg_arg],
    );

    let info = consumer.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), tn_proto::ManifestKind::KitBundle);
    assert!(info.verified());
    assert!(info.has_body_entry("body/encrypted.bin"));
    assert!(!info.has_body_entry("body/default.btn.mykit"));

    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.status(), tn_proto::AbsorbStatus::Accepted);
    assert!(
        receipt.accepted_count > 0,
        "Rust should install the Python sealed kit: {receipt:?}"
    );

    let duplicate = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(duplicate.kind, "kit_bundle");
    assert_eq!(duplicate.legacy_status, "no_op");
    assert!(duplicate.deduped_count > 0);

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn rust_invite_python_accepts() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let invite_path = tmp.path().join("tn-invite-rust-python.zip");
    let producer = Tn::ephemeral()?;
    producer.inbox().mint_invite_path(
        "did:key:zPythonInviteRecipient",
        &invite_path,
        MintInvitationOptions {
            from_email: Some("rust@example.test".to_string()),
            invitation_id: Some("rust-python".to_string()),
            ..MintInvitationOptions::default()
        },
    )?;

    let invite_arg = invite_path.to_string_lossy().to_string();
    let output = run_python(
        tmp.path(),
        r#"
import json
import sys
from pathlib import Path

import tn
import yaml
from tn import inbox

tn.init("py_invite_consumer")
yaml_path = tn.current_config().yaml_path
tn.flush_and_close()

result = inbox.accept(Path(sys.argv[1]), yaml_path=yaml_path)

doc = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8")) or {}
loc = (doc.get("ceremony") or {}).get("admin_log_location")
if not loc or loc == "main_log":
    loc = f"./.tn/{Path(yaml_path).stem}/admin/default.ndjson"
admin_log = Path(loc)
if not admin_log.is_absolute():
    admin_log = (Path(yaml_path).parent / admin_log).resolve()
rows = []
if admin_log.exists():
    for line in admin_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        env = json.loads(line)
        if env.get("event_type") == "tn.enrolment.absorbed":
            rows.append(env)

print(json.dumps({
    "group_name": result["group_name"],
    "from_email": result["from_email"],
    "kit_path": result["kit_path"],
    "kit_exists": __import__("pathlib").Path(result["kit_path"]).exists(),
    "absorbed": rows,
}, sort_keys=True))
"#,
        &[&invite_arg],
    );

    let result = last_json_object(&output);
    assert_eq!(
        result.get("group_name").and_then(Value::as_str),
        Some("default")
    );
    assert_eq!(
        result.get("from_email").and_then(Value::as_str),
        Some("rust@example.test")
    );
    assert_eq!(
        result.get("kit_exists").and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        result
            .get("absorbed")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty()),
        "Python accept should record tn.enrolment.absorbed: {result}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local Python SDK/native extension setup; run with cargo test -p tn-proto --test interop_python -- --ignored"]
fn python_invite_rust_accepts() -> tn_proto::Result<()> {
    if !python_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let consumer = Tn::ephemeral()?;
    let invite_path = tmp.path().join("tn-invite-python-rust.zip");
    let invite_arg = invite_path.to_string_lossy().to_string();
    let recipient_did = consumer.did().to_string();

    run_python(
        tmp.path(),
        r#"
import sys

import tn
from tn.cli import main as cli_main

tn.init("py_invite_producer")
yaml_path = tn.current_config().yaml_path
tn.flush_and_close()

rc = cli_main([
    "invite",
    sys.argv[1],
    sys.argv[2],
    "--group",
    "default",
    "--yaml",
    str(yaml_path),
    "--from-email",
    "python@example.test",
])
if rc != 0:
    raise SystemExit(rc)
print(sys.argv[2])
"#,
        &[&recipient_did, &invite_arg],
    );

    let accepted = consumer.inbox().accept_path(&invite_path)?;
    assert_eq!(accepted.group_name(), "default");
    assert_eq!(accepted.from_email(), "python@example.test");
    assert!(accepted.info.kit_hash_verified());
    assert!(accepted.kit_path.exists());

    let entries = consumer.read(ReadOptions::default())?;
    let absorbed = common::find_event(&entries, "tn.enrolment.absorbed");
    assert_eq!(
        absorbed.get("publisher_identity").and_then(Value::as_str),
        accepted.info.manifest.from_account_did.as_deref()
    );

    Ok(())
}

fn python_ready() -> bool {
    let repo = common::repo_root();
    let mut command = python_command();
    command
        .current_dir(&repo)
        .env("PYTHONPATH", repo.join("python"))
        .env("TN_NO_STDOUT", "1")
        .arg("-c")
        .arg("import tn; print('ok')");

    match command.output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            eprintln!(
                "skipping Python interop: Python SDK is not importable in this environment\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
        Err(err) => {
            eprintln!("skipping Python interop: failed to start Python: {err}");
            false
        }
    }
}

fn python_command() -> Command {
    Command::new(std::env::var_os("TN_INTEROP_PYTHON").unwrap_or_else(|| OsString::from("python")))
}

fn run_python(cwd: &Path, code: &str, args: &[&str]) -> String {
    let repo = common::repo_root();
    let python_path = repo.join("python");
    let mut command = python_command();
    command
        .current_dir(cwd)
        .env("PYTHONPATH", python_path)
        .env("TN_NO_STDOUT", "1")
        .arg("-c")
        .arg(code);
    for arg in args {
        command.arg(arg);
    }
    let output = command.output().expect("failed to run python");
    assert!(
        output.status.success(),
        "python failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("python stdout should be UTF-8")
}

fn last_json_object(output: &str) -> Value {
    output
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .unwrap_or_else(|| panic!("expected a JSON object in stdout: {output}"))
}
