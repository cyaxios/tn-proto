#![cfg(feature = "cli")]

use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[cfg(feature = "watch")]
use std::process::Stdio;

use tn_core::tnpkg::{read_tnpkg, TnpkgSource};
use tn_proto::{AbsorbReceiptExt, MintInvitationOptions, Tn, TnProjectOptions};

#[test]
fn cli_help_lists_main_command_groups() -> tn_proto::Result<()> {
    assert_help_contains(
        &["--help"],
        &[
            "init",
            "claim-link",
            "read",
            "verify",
            "show",
            "watch",
            "inbox",
            "pkg",
            "group",
            "auth",
            "wallet",
            "vault",
        ],
    )?;
    assert_help_contains(
        &["read", "--help"],
        &["--yaml", "--all-runs", "--verify", "--pretty"],
    )?;
    assert_help_contains(&["verify", "--help"], &["--yaml"])?;
    assert_help_contains(&["show", "--help"], &["--yaml"])?;
    assert_help_contains(
        &["watch", "--help"],
        &[
            "--yaml",
            "--from-beginning",
            "--native",
            "--event-type",
            "--event-type-prefix",
            "--limit",
            "--timeout-ms",
        ],
    )?;
    assert_help_contains(
        &["auth", "--help"],
        &["connect-code", "logout", "status", "whoami"],
    )?;
    assert_help_contains(&["inbox", "--help"], &["list", "inspect", "accept", "mint"])?;
    assert_help_contains(&["inbox", "inspect", "--help"], &["ZIP"])?;
    assert_help_contains(
        &["pkg", "--help"],
        &["inspect", "absorb", "compile-enrolment", "offer", "export"],
    )?;
    assert_help_contains(
        &["pkg", "compile-enrolment", "--help"],
        &["--yaml", "--recipient", "--group", "--out"],
    )?;
    assert_help_contains(
        &["pkg", "offer", "--help"],
        &["--yaml", "--peer", "--group", "--out"],
    )?;
    assert_help_contains(
        &["pkg", "export", "--help"],
        &[
            "admin-snapshot",
            "bundle-for-recipient",
            "recipient-handoff",
        ],
    )?;
    assert_help_contains(
        &["pkg", "export", "recipient-handoff", "--help"],
        &["--yaml", "--recipient", "--out-dir", "--group"],
    )?;
    assert_help_contains(
        &["group", "--help"],
        &[
            "list",
            "recipients",
            "add",
            "add-recipient",
            "revoke-recipient",
        ],
    )?;
    assert_help_contains(&["group", "list", "--help"], &["--yaml"])?;
    assert_help_contains(
        &["group", "recipients", "--help"],
        &["--yaml", "--include-revoked"],
    )?;
    assert_help_contains(&["group", "add", "--help"], &["--yaml", "--fields"])?;
    assert_help_contains(&["group", "add-recipient", "--help"], &["--yaml", "--out"])?;
    assert_help_contains(
        &["group", "revoke-recipient", "--help"],
        &["--yaml", "LEAF_INDEX"],
    )?;
    assert_help_contains(
        &["wallet", "--help"],
        &["status", "sync", "restore", "unlink"],
    )?;
    assert_help_contains(&["vault", "--help"], &["connect", "unlink"])?;

    Ok(())
}

#[test]
fn cli_read_prints_entries_all_runs_and_verify_flags() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-read-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info(
        "read.cli",
        serde_json::json!({
            "order_id": "READ-1",
            "amount": 99
        }),
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let current_run = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("read")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;
    assert!(
        current_run.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&current_run.stdout),
        String::from_utf8_lossy(&current_run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&current_run.stdout)
            .trim()
            .is_empty(),
        "default read should show only this CLI process run"
    );

    let all_runs = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("read")
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--all-runs")
        .output()?;
    assert!(
        all_runs.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&all_runs.stdout),
        String::from_utf8_lossy(&all_runs.stderr)
    );
    let stdout = String::from_utf8_lossy(&all_runs.stdout);
    assert!(stdout.contains("\"event_type\":\"read.cli\""));
    assert!(stdout.contains("\"order_id\":\"READ-1\""));
    assert!(stdout.contains("\"amount\":99"));

    let verified = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("read")
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--verify")
        .arg("--pretty")
        .output()?;
    assert!(
        verified.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    let stdout = String::from_utf8_lossy(&verified.stdout);
    assert!(stdout.contains("\"event_type\": \"read.cli\""));
    assert!(stdout.contains("\"_valid\""));
    assert!(stdout.contains("\"signature\": true"));
    assert!(stdout.contains("\"row_hash\": true"));
    assert!(stdout.contains("\"chain\": true"));

    Ok(())
}

#[test]
fn cli_verify_reports_valid_log() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-verify-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info(
        "verify.cli",
        serde_json::json!({
            "order_id": "VERIFY-1",
            "amount": 42
        }),
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("verify")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;
    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("entries: 1"));
    assert!(stdout.contains("invalid: 0"));
    assert!(stdout.contains("valid: true"));

    Ok(())
}

#[test]
fn cli_show_prints_project_status_summary() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-show-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info(
        "show.cli",
        serde_json::json!({
            "order_id": "SHOW-1",
            "amount": 7
        }),
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    let did = tn.did().to_string();
    tn.close()?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("show")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;
    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("yaml: {}", yaml_path.display())));
    assert!(stdout.contains(&format!("did: {did}")));
    assert!(stdout.contains("entries: 1"));
    assert!(stdout.contains("groups: default"));
    assert!(stdout.contains("account: (not bound)"));
    assert!(stdout.contains("vault state: Local"));
    assert!(stdout.contains("wallet inbox: "));

    Ok(())
}

#[test]
fn cli_watch_prints_existing_entries_from_beginning() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-watch-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info(
        "watch.cli",
        serde_json::json!({
            "order_id": "WATCH-1",
            "amount": 12
        }),
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("watch")
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--from-beginning")
        .arg("--event-type-prefix")
        .arg("watch.")
        .arg("--limit")
        .arg("1")
        .arg("--timeout-ms")
        .arg("1000")
        .output()?;
    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"event_type\":\"watch.cli\""));
    assert!(stdout.contains("\"order_id\":\"WATCH-1\""));
    assert!(stdout.contains("\"amount\":12"));

    Ok(())
}

#[cfg(feature = "watch")]
#[test]
fn cli_watch_native_prints_new_entries() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-watch-native-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let child = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("watch")
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--native")
        .arg("--event-type")
        .arg("watch.native.cli")
        .arg("--limit")
        .arg("1")
        .arg("--timeout-ms")
        .arg("5000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    thread::sleep(Duration::from_millis(300));
    let tn = Tn::init(&yaml_path)?;
    tn.info(
        "watch.native.cli",
        serde_json::json!({
            "order_id": "NATIVE-WATCH-1",
            "amount": 34
        }),
    )?;
    tn.close()?;

    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"event_type\":\"watch.native.cli\""));
    assert!(stdout.contains("\"order_id\":\"NATIVE-WATCH-1\""));
    assert!(stdout.contains("\"amount\":34"));

    Ok(())
}

#[cfg(not(feature = "watch"))]
#[test]
fn cli_watch_native_explains_missing_feature() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-watch-native-error",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("watch")
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--native")
        .arg("--timeout-ms")
        .arg("1")
        .output()?;
    assert!(
        !output.status.success(),
        "cli unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires building tn-proto with `--features cli,watch`"));

    Ok(())
}

#[test]
fn cli_inbox_accept_installs_real_invite() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let invite_path = tmp.path().join("tn-invite-cli.zip");
    let producer = Tn::ephemeral()?;
    let consumer = Tn::ephemeral()?;

    producer.inbox().mint_invite_path(
        consumer.did(),
        &invite_path,
        MintInvitationOptions {
            from_email: Some("cli@example.test".to_string()),
            invitation_id: Some("cli-test".to_string()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("accept")
        .arg(&invite_path)
        .arg("--yaml")
        .arg(consumer.yaml_path())
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("accepted invite:"));
    assert!(stdout.contains("group: default"));
    assert!(stdout.contains("from: cli@example.test"));
    assert!(stdout.contains("kit:"));
    assert!(stdout.contains("absorbed_at:"));

    Ok(())
}

#[test]
fn cli_inbox_list_prints_invites() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    std::fs::write(tmp.path().join("tn-invite-a.zip"), [])?;
    std::fs::write(tmp.path().join("not-an-invite.zip"), [])?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("list")
        .arg("--dir")
        .arg(tmp.path())
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tn-invite-a.zip"));
    assert!(!stdout.contains("not-an-invite.zip"));

    Ok(())
}

#[test]
fn cli_inbox_inspect_prints_invite_manifest() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let invite_path = tmp.path().join("tn-invite-cli-inspect.zip");
    let producer = Tn::ephemeral()?;
    let consumer = Tn::ephemeral()?;

    producer.inbox().mint_invite_path(
        consumer.did(),
        &invite_path,
        MintInvitationOptions {
            from_email: Some("producer@example.test".to_string()),
            project_id: Some("proj_cli_inspect".to_string()),
            project_name: Some("CLI Inspect".to_string()),
            note: Some("preview first".to_string()),
            invitation_id: Some("cli-inspect-1".to_string()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("inspect")
        .arg(&invite_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("invite:"));
    assert!(stdout.contains("group: default"));
    assert!(stdout.contains("sender: producer@example.test"));
    assert!(stdout.contains("from did: did:key:"));
    assert!(stdout.contains("project id: proj_cli_inspect"));
    assert!(stdout.contains("project name: CLI Inspect"));
    assert!(stdout.contains("leaf: 1"));
    assert!(stdout.contains("kit entry: default.btn.mykit"));
    assert!(stdout.contains("kit bytes:"));
    assert!(stdout.contains("kit sha256:"));
    assert!(stdout.contains("kit hash verified: true"));
    assert!(stdout.contains("created at:"));
    assert!(stdout.contains("provenance: rust-sdk"));
    assert!(stdout.contains("note: preview first"));

    Ok(())
}

#[test]
fn cli_inbox_mint_writes_invite_that_can_be_accepted() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let producer = Tn::init_project_with_options(
        "cli-invite-producer",
        TnProjectOptions {
            project_dir: Some(tmp.path().join("producer")),
            ..Default::default()
        },
    )?;
    producer.vault().connect(tn_proto::VaultConnectOptions {
        vault: "https://vault.example".to_string(),
        project_id: "proj_cli_invite".to_string(),
        project_name: Some("CLI Invite".to_string()),
        record_audit_event: false,
    })?;
    let consumer = Tn::init_project_with_options(
        "cli-invite-consumer",
        TnProjectOptions {
            project_dir: Some(tmp.path().join("consumer")),
            ..Default::default()
        },
    )?;
    let invite_path = tmp.path().join("tn-invite-cli-minted.zip");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("mint")
        .arg(consumer.did())
        .arg(&invite_path)
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--group")
        .arg("default")
        .arg("--from-email")
        .arg("producer@example.test")
        .arg("--project-name")
        .arg("CLI Invite")
        .arg("--note")
        .arg("welcome")
        .arg("--invitation-id")
        .arg("cli-invite-1")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("invite:"));
    assert!(stdout.contains("recipient:"));
    assert!(stdout.contains("group: default"));
    assert!(stdout.contains("from: producer@example.test"));
    assert!(stdout.contains("leaf: 1"));
    assert!(stdout.contains("kit_sha256: sha256:"));
    assert!(stdout.contains("inner kit: default.btn.mykit"));

    let info = producer.inbox().inspect_path(&invite_path)?;
    assert_eq!(info.manifest.invitation_id.as_deref(), Some("cli-invite-1"));
    assert_eq!(
        info.manifest.from_email.as_deref(),
        Some("producer@example.test")
    );
    assert_eq!(info.manifest.project_id.as_deref(), Some("proj_cli_invite"));
    assert_eq!(info.manifest.project_name.as_deref(), Some("CLI Invite"));
    assert_eq!(info.manifest.note.as_deref(), Some("welcome"));
    assert!(info.kit_hash_verified());

    let accepted = consumer.inbox().accept_path(&invite_path)?;
    assert_eq!(accepted.group_name(), "default");
    assert_eq!(accepted.from_email(), "producer@example.test");

    Ok(())
}

#[test]
fn cli_inbox_mint_list_inspect_accept_workflow() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let producer = Tn::init_project_with_options(
        "cli-invite-workflow-producer",
        TnProjectOptions {
            project_dir: Some(tmp.path().join("producer")),
            ..Default::default()
        },
    )?;
    let consumer = Tn::init_project_with_options(
        "cli-invite-workflow-consumer",
        TnProjectOptions {
            project_dir: Some(tmp.path().join("consumer")),
            ..Default::default()
        },
    )?;
    let invite_path = tmp.path().join("tn-invite-workflow.zip");

    let mint = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("mint")
        .arg(consumer.did())
        .arg(&invite_path)
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--from-email")
        .arg("workflow@example.test")
        .arg("--project-name")
        .arg("Workflow Invite")
        .arg("--note")
        .arg("all cli")
        .arg("--invitation-id")
        .arg("workflow-invite-1")
        .output()?;

    assert!(
        mint.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mint.stdout),
        String::from_utf8_lossy(&mint.stderr)
    );
    let mint_stdout = String::from_utf8_lossy(&mint.stdout);
    assert!(mint_stdout.contains("invite:"));
    assert!(mint_stdout.contains("from: workflow@example.test"));
    assert!(mint_stdout.contains("inner kit: default.btn.mykit"));
    assert!(invite_path.exists());

    let list = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("list")
        .arg("--dir")
        .arg(tmp.path())
        .output()?;

    assert!(
        list.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(String::from_utf8_lossy(&list.stdout).contains("tn-invite-workflow.zip"));

    let inspect = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("inspect")
        .arg(&invite_path)
        .output()?;

    assert!(
        inspect.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_stdout = String::from_utf8_lossy(&inspect.stdout);
    assert!(inspect_stdout.contains("sender: workflow@example.test"));
    assert!(inspect_stdout.contains("project name: Workflow Invite"));
    assert!(inspect_stdout.contains("kit hash verified: true"));
    assert!(inspect_stdout.contains("note: all cli"));

    let accept = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("inbox")
        .arg("accept")
        .arg(&invite_path)
        .arg("--yaml")
        .arg(consumer.yaml_path())
        .output()?;

    assert!(
        accept.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );
    let accept_stdout = String::from_utf8_lossy(&accept.stdout);
    assert!(accept_stdout.contains("accepted invite:"));
    assert!(accept_stdout.contains("from: workflow@example.test"));
    assert!(accept_stdout.contains("kit:"));

    Ok(())
}

#[test]
fn cli_pkg_inspect_prints_package_summary() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    let pkg_path = tn
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("admin-snapshot.tnpkg");
    tn.pkg().export_admin_snapshot(&pkg_path)?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("inspect")
        .arg(&pkg_path)
        .arg("--entries")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("package:"));
    assert!(stdout.contains("kind: admin_log_snapshot"));
    assert!(stdout.contains("category: AdminSnapshot"));
    assert!(stdout.contains("verified: true"));
    assert!(stdout.contains("signature: Verified"));
    assert!(stdout.contains("publisher:"));
    assert!(stdout.contains("recipient: (none)"));
    assert!(stdout.contains("body entries:"));
    assert!(stdout.contains("contains reader keys: false"));
    assert!(stdout.contains("contains secrets: false"));
    assert!(stdout.contains("entry: body/admin.ndjson"));

    Ok(())
}

#[test]
fn cli_pkg_absorb_applies_package_and_reports_noop_on_duplicate() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    producer.info(
        "payment.created",
        serde_json::json!({ "order_id": "PKG-CLI-1" }),
    )?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("admin-snapshot.tnpkg");
    producer.pkg().export_admin_snapshot(&pkg_path)?;

    let consumer = Tn::ephemeral()?;
    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("absorb")
        .arg(&pkg_path)
        .arg("--yaml")
        .arg(consumer.yaml_path())
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("package:"));
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("kind: admin_log_snapshot"));
    assert!(stdout.contains("status: Accepted"));
    assert!(stdout.contains("accepted:"));
    assert!(stdout.contains("deduped:"));
    assert!(stdout.contains("noop: false"));

    let duplicate = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("absorb")
        .arg(&pkg_path)
        .arg("--yaml")
        .arg(consumer.yaml_path())
        .output()?;

    assert!(
        duplicate.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&duplicate.stdout),
        String::from_utf8_lossy(&duplicate.stderr)
    );
    let duplicate_stdout = String::from_utf8_lossy(&duplicate.stdout);
    assert!(duplicate_stdout.contains("kind: admin_log_snapshot"));
    assert!(duplicate_stdout.contains("status: NoOp"));

    Ok(())
}

#[test]
fn cli_pkg_export_admin_snapshot_writes_inspectable_package() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    tn.info(
        "payment.created",
        serde_json::json!({ "order_id": "PKG-CLI-EXPORT" }),
    )?;
    let pkg_path = tn
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("cli-export-admin-snapshot.tnpkg");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("export")
        .arg("admin-snapshot")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--out")
        .arg(&pkg_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("package:"));
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("kind: admin_log_snapshot"));
    assert!(stdout.contains("verified: true"));
    assert!(stdout.contains("body entries:"));
    assert!(stdout.contains("contains secrets: false"));
    assert!(pkg_path.exists());

    let info = tn.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), tn_proto::ManifestKind::AdminLogSnapshot);
    assert!(info.verified());
    assert!(!info.contains_secret_material());
    assert!(info.has_body_entry("body/admin.ndjson"));

    Ok(())
}

#[test]
fn cli_pkg_export_bundle_for_recipient_writes_absorbable_kit_bundle() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("cli-reader-bundle.tnpkg");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("export")
        .arg("bundle-for-recipient")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--recipient")
        .arg(consumer.did())
        .arg("--out")
        .arg(&pkg_path)
        .arg("--group")
        .arg("payments")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("package:"));
    assert!(stdout.contains("recipient:"));
    assert!(stdout.contains("groups: payments"));
    assert!(stdout.contains("kind: kit_bundle"));
    assert!(stdout.contains("verified: true"));
    assert!(stdout.contains("contains reader keys: true"));
    assert!(stdout.contains("contains secrets: false"));
    assert!(pkg_path.exists());

    let info = producer.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), tn_proto::ManifestKind::KitBundle);
    assert!(info.verified());
    assert!(info.contains_reader_keys());
    assert!(!info.contains_secret_material());

    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert!(receipt.accepted_count > 0);

    Ok(())
}

#[test]
fn cli_pkg_export_bundle_for_recipient_can_seal_bundle() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("cli-reader-bundle-sealed.tnpkg");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("export")
        .arg("bundle-for-recipient")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--recipient")
        .arg(consumer.did())
        .arg("--out")
        .arg(&pkg_path)
        .arg("--group")
        .arg("payments")
        .arg("--seal-for-recipient")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kind: kit_bundle"));
    assert!(stdout.contains("verified: true"));
    assert!(stdout.contains("sealed: true"));
    assert!(pkg_path.exists());

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    assert_eq!(manifest.kind, tn_proto::ManifestKind::KitBundle);
    assert!(body.contains_key("body/encrypted.bin"));
    assert!(!body.contains_key("body/payments.btn.mykit"));
    let body_encryption = manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .and_then(serde_json::Value::as_object)
        .expect("sealed bundle should carry body_encryption");
    assert!(body_encryption
        .get("recipient_wraps")
        .and_then(serde_json::Value::as_array)
        .is_some());

    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.status(), tn_proto::AbsorbStatus::Accepted);
    assert!(receipt.accepted_count > 0);

    Ok(())
}

#[test]
fn cli_pkg_compile_enrolment_writes_absorbable_handoff() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("cli-compiled-enrolment.tnpkg");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("compile-enrolment")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--recipient")
        .arg(consumer.did())
        .arg("--group")
        .arg("payments")
        .arg("--out")
        .arg(&pkg_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("package:"));
    assert!(stdout.contains("recipient:"));
    assert!(stdout.contains("groups: payments"));
    assert!(stdout.contains("kind: kit_bundle"));
    assert!(stdout.contains("verified: true"));
    assert!(stdout.contains("sealed: false"));
    assert!(stdout.contains("manifest sha256:"));
    assert!(stdout.contains("package sha256:"));
    assert!(stdout.contains("contains reader keys: true"));
    assert!(stdout.contains("contains secrets: false"));

    let info = producer.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), tn_proto::ManifestKind::KitBundle);
    assert!(info.verified());
    assert!(info.contains_reader_keys());

    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.status(), tn_proto::AbsorbStatus::Accepted);

    Ok(())
}

#[test]
fn cli_pkg_compile_enrolment_roundtrips_through_cli_absorb() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("cli-compiled-enrolment-roundtrip.tnpkg");

    let compile = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("compile-enrolment")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--recipient")
        .arg(consumer.did())
        .arg("--group")
        .arg("payments")
        .arg("--out")
        .arg(&pkg_path)
        .output()?;

    assert!(
        compile.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );

    let absorb = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("absorb")
        .arg(&pkg_path)
        .arg("--yaml")
        .arg(consumer.yaml_path())
        .output()?;

    assert!(
        absorb.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&absorb.stdout),
        String::from_utf8_lossy(&absorb.stderr)
    );
    let absorb_stdout = String::from_utf8_lossy(&absorb.stdout);
    assert!(absorb_stdout.contains("kind: kit_bundle"));
    assert!(absorb_stdout.contains("status: Accepted"));
    assert!(absorb_stdout.contains("legacy status: enrolment_applied"));
    assert!(absorb_stdout.contains("noop: false"));

    let duplicate = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("absorb")
        .arg(&pkg_path)
        .arg("--yaml")
        .arg(consumer.yaml_path())
        .output()?;

    assert!(
        duplicate.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&duplicate.stdout),
        String::from_utf8_lossy(&duplicate.stderr)
    );
    let duplicate_stdout = String::from_utf8_lossy(&duplicate.stdout);
    assert!(duplicate_stdout.contains("kind: kit_bundle"));
    assert!(duplicate_stdout.contains("status: NoOp"));
    assert!(duplicate_stdout.contains("legacy status: no_op"));

    Ok(())
}

#[test]
fn cli_pkg_offer_compiles_handoff_and_attests_event() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log parent")
        .join("cli-offer.tnpkg");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("offer")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--peer")
        .arg(consumer.did())
        .arg("--group")
        .arg("payments")
        .arg("--out")
        .arg(&pkg_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("package:"));
    assert!(stdout.contains("peer:"));
    assert!(stdout.contains("group: payments"));
    assert!(stdout.contains("status: offered"));
    assert!(stdout.contains("kind: kit_bundle"));
    assert!(stdout.contains("verified: true"));
    assert!(stdout.contains("package sha256:"));
    assert!(stdout.contains("contains reader keys: true"));
    assert!(stdout.contains("contains secrets: false"));

    let info = producer.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), tn_proto::ManifestKind::KitBundle);
    assert!(info.verified());
    assert!(info.contains_reader_keys());

    let entries = producer.read(tn_proto::ReadOptions {
        all_runs: true,
        ..tn_proto::ReadOptions::default()
    })?;
    let event = entries
        .iter()
        .find(|entry| entry.event_type() == Some("tn.offer.compiled"))
        .expect("offer CLI should emit tn.offer.compiled");
    assert_eq!(
        event
            .get("peer_identity")
            .and_then(serde_json::Value::as_str),
        Some(consumer.did())
    );

    Ok(())
}

#[test]
fn cli_pkg_export_recipient_handoff_writes_snapshot_and_bundle() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let out_dir = tmp.path().join("handoff");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("export")
        .arg("recipient-handoff")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--recipient")
        .arg(consumer.did())
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--group")
        .arg("payments")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("recipient:"));
    assert!(stdout.contains("groups: payments"));
    assert!(stdout.contains("admin package:"));
    assert!(stdout.contains("admin verified: true"));
    assert!(stdout.contains("admin contains secrets: false"));
    assert!(stdout.contains("bundle package:"));
    assert!(stdout.contains("bundle verified: true"));
    assert!(stdout.contains("bundle contains reader keys: true"));
    assert!(stdout.contains("bundle contains secrets: false"));
    assert!(stdout.contains("send: admin-snapshot.tnpkg, reader-bundle.tnpkg"));

    let admin_path = out_dir.join("admin-snapshot.tnpkg");
    let bundle_path = out_dir.join("reader-bundle.tnpkg");
    assert!(admin_path.exists());
    assert!(bundle_path.exists());

    let admin_info = producer.pkg().inspect_path(&admin_path)?;
    assert_eq!(admin_info.kind(), tn_proto::ManifestKind::AdminLogSnapshot);
    assert!(admin_info.verified());
    assert!(!admin_info.contains_secret_material());

    let bundle_info = producer.pkg().inspect_path(&bundle_path)?;
    assert_eq!(bundle_info.kind(), tn_proto::ManifestKind::KitBundle);
    assert!(bundle_info.verified());
    assert!(bundle_info.contains_reader_keys());
    assert!(!bundle_info.contains_secret_material());

    let admin_receipt = consumer.pkg().absorb_path(&admin_path)?;
    let bundle_receipt = consumer.pkg().absorb_path(&bundle_path)?;
    assert!(admin_receipt.accepted() || admin_receipt.no_op());
    assert_eq!(bundle_receipt.kind, "kit_bundle");
    assert!(bundle_receipt.accepted_count > 0);

    Ok(())
}

#[test]
fn cli_pkg_export_recipient_handoff_can_seal_reader_bundle() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let consumer = Tn::ephemeral()?;
    let out_dir = tmp.path().join("sealed-handoff");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("pkg")
        .arg("export")
        .arg("recipient-handoff")
        .arg("--yaml")
        .arg(producer.yaml_path())
        .arg("--recipient")
        .arg(consumer.did())
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--group")
        .arg("payments")
        .arg("--seal-for-recipient")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("admin verified: true"));
    assert!(stdout.contains("bundle verified: true"));
    assert!(stdout.contains("bundle sealed: true"));
    assert!(stdout.contains("bundle contains secrets: false"));
    assert!(stdout.contains("send: admin-snapshot.tnpkg, reader-bundle.tnpkg"));

    let admin_path = out_dir.join("admin-snapshot.tnpkg");
    let bundle_path = out_dir.join("reader-bundle.tnpkg");
    assert!(admin_path.exists());
    assert!(bundle_path.exists());

    let admin_info = producer.pkg().inspect_path(&admin_path)?;
    assert_eq!(admin_info.kind(), tn_proto::ManifestKind::AdminLogSnapshot);
    assert!(admin_info.verified());
    assert!(admin_info.has_body_entry("body/admin.ndjson"));

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&bundle_path))?;
    assert_eq!(manifest.kind, tn_proto::ManifestKind::KitBundle);
    assert!(body.contains_key("body/encrypted.bin"));
    assert!(!body.contains_key("body/payments.btn.mykit"));
    let body_encryption = manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .and_then(serde_json::Value::as_object)
        .expect("sealed bundle should carry body_encryption");
    assert!(body_encryption
        .get("recipient_wraps")
        .and_then(serde_json::Value::as_array)
        .is_some());

    let admin_receipt = consumer.pkg().absorb_path(&admin_path)?;
    let bundle_receipt = consumer.pkg().absorb_path(&bundle_path)?;
    assert!(admin_receipt.accepted() || admin_receipt.no_op());
    assert_eq!(bundle_receipt.kind, "kit_bundle");
    assert_eq!(bundle_receipt.status(), tn_proto::AbsorbStatus::Accepted);
    assert!(bundle_receipt.accepted_count > 0);

    Ok(())
}

#[test]
fn cli_group_add_creates_group_and_routes_fields() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-group-add-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("add")
        .arg("payments")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--fields")
        .arg("order_id,amount")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("group: payments"));
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("created: true"));
    assert!(stdout.contains("changed: true"));
    assert!(stdout.contains("fields: order_id,amount"));
    assert!(stdout.contains("cipher: btn"));

    let yaml_path = tn.yaml_path().to_path_buf();
    let tn = Tn::init(&yaml_path)?;
    assert!(tn.group_names().iter().any(|name| name == "payments"));
    tn.info(
        "payment.created",
        serde_json::json!({
            "order_id": "CLI-GROUP-1",
            "amount": 42,
            "note": "private"
        }),
    )?;
    let entries = tn.read(tn_proto::ReadOptions::default())?;
    let payment = entries
        .iter()
        .find(|entry| entry.event_type() == Some("payment.created"))
        .expect("payment.created should be readable");
    assert_eq!(
        payment.get("order_id").and_then(serde_json::Value::as_str),
        Some("CLI-GROUP-1")
    );
    assert_eq!(
        payment.get("amount").and_then(serde_json::Value::as_i64),
        Some(42)
    );
    let raw_log = std::fs::read_to_string(tn.log_path())?;
    assert!(!raw_log.contains("CLI-GROUP-1"));

    Ok(())
}

#[test]
fn cli_group_list_prints_configured_groups() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut tn = Tn::init_project_with_options(
        "cli-group-list-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("list")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("groups: 3"));
    assert!(stdout.contains("group: default"));
    assert!(stdout.contains("group: tn.agents"));
    assert!(stdout.contains("group: payments"));

    Ok(())
}

#[test]
fn cli_group_add_recipient_mints_reader_kit() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut tn = Tn::init_project_with_options(
        "cli-group-recipient-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let kit_path = tmp.path().join("recipient.btn.mykit");
    let recipient_did = "did:key:zCliGroupRecipient";

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("add-recipient")
        .arg("payments")
        .arg(recipient_did)
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--out")
        .arg(&kit_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("group: payments"));
    assert!(stdout.contains("recipient: did:key:zCliGroupRecipient"));
    assert!(stdout.contains("leaf index: 1"));
    assert!(stdout.contains("kit:"));
    assert!(stdout.contains("yaml:"));
    assert!(kit_path.exists());

    let mut tn = Tn::init(&yaml_path)?;
    let state = tn.admin().state(Some("payments"))?;
    let recipient = state
        .recipients
        .iter()
        .find(|row| row.leaf_index == 1)
        .expect("admin state should include minted recipient");
    assert_eq!(recipient.group, "payments");
    assert_eq!(recipient.recipient_identity.as_deref(), Some(recipient_did));
    assert_eq!(recipient.active_status, "active");

    Ok(())
}

#[test]
fn cli_group_recipients_lists_active_and_revoked_leaves() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut tn = Tn::init_project_with_options(
        "cli-group-recipients-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    let kit_path = tmp.path().join("recipient.btn.mykit");
    tn.admin().add_recipient(
        "payments",
        Some("did:key:zCliListRecipient".to_string()),
        &kit_path,
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let active = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("recipients")
        .arg("payments")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;
    assert!(
        active.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&active.stdout),
        String::from_utf8_lossy(&active.stderr)
    );
    let stdout = String::from_utf8_lossy(&active.stdout);
    assert!(stdout.contains("group: payments"));
    assert!(stdout.contains("recipients: 1"));
    assert!(stdout.contains("leaf: 1 recipient: did:key:zCliListRecipient revoked: false"));

    let revoke = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("revoke-recipient")
        .arg("payments")
        .arg("1")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;
    assert!(
        revoke.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );

    let active_after_revoke = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("recipients")
        .arg("payments")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;
    assert!(
        active_after_revoke.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&active_after_revoke.stdout),
        String::from_utf8_lossy(&active_after_revoke.stderr)
    );
    let stdout = String::from_utf8_lossy(&active_after_revoke.stdout);
    assert!(stdout.contains("recipients: 0"));

    let all = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("recipients")
        .arg("payments")
        .arg("--yaml")
        .arg(&yaml_path)
        .arg("--include-revoked")
        .output()?;
    assert!(
        all.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&all.stdout),
        String::from_utf8_lossy(&all.stderr)
    );
    let stdout = String::from_utf8_lossy(&all.stdout);
    assert!(stdout.contains("recipients: 1"));
    assert!(stdout.contains("leaf: 1 recipient: did:key:zCliListRecipient revoked: true"));

    Ok(())
}

#[test]
fn cli_group_revoke_recipient_updates_publisher_state() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut tn = Tn::init_project_with_options(
        "cli-group-revoke-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    let kit_path = tmp.path().join("recipient.btn.mykit");
    let added = tn.admin().add_recipient(
        "payments",
        Some("did:key:zCliRevokeRecipient".to_string()),
        &kit_path,
    )?;
    assert_eq!(added.leaf_index, 1);
    assert_eq!(tn.admin().revoked_count("payments")?, 0);
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("group")
        .arg("revoke-recipient")
        .arg("payments")
        .arg("1")
        .arg("--yaml")
        .arg(&yaml_path)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("group: payments"));
    assert!(stdout.contains("leaf index: 1"));
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("revoked: true"));

    let mut tn = Tn::init(&yaml_path)?;
    assert_eq!(tn.admin().revoked_count("payments")?, 1);

    Ok(())
}

#[test]
fn cli_auth_connect_code_marks_project_bound() -> tn_proto::Result<()> {
    let server =
        LocalHttpServer::start_json(r#"{"account_id":"acct_cli","project_id":"proj_cli"}"#)?;
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-auth-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("auth")
        .arg("connect-code")
        .arg("tn_connect_cli")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--machine-identity-path")
        .arg(tmp.path().join("missing-identity.json"))
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("account: acct_cli"));
    assert!(stdout.contains("did:"));
    assert!(stdout.contains("signing tier: Ceremony"));
    assert!(stdout.contains("project id: proj_cli"));

    let request = server.request();
    assert!(request.starts_with("POST /api/v1/account/connect-codes/redeem "));
    assert!(request.contains("\"code\":\"tn_connect_cli\""));
    assert!(request.contains("\"did\":\""));
    assert!(request.contains("\"signature_b64\":\""));

    let state = tn.account().state();
    assert_eq!(state.account_id.as_deref(), Some("acct_cli"));
    assert!(state.account_bound);

    Ok(())
}

#[test]
fn cli_auth_connect_code_rejects_malformed_success_response() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start_json(r#"{"project_id":"proj_without_account"}"#)?;
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-auth-malformed-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("auth")
        .arg("connect-code")
        .arg("tn_connect_bad")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--machine-identity-path")
        .arg(tmp.path().join("missing-identity.json"))
        .output()?;

    assert!(
        !output.status.success(),
        "cli unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("connect-code response"));
    assert!(stderr.contains("account_id"));
    assert_eq!(tn.account().account_id(), None);
    assert!(!tn.account().is_bound());

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/v1/account/connect-codes/redeem "));

    Ok(())
}

#[test]
fn cli_auth_status_reports_unbound_project() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-status-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("auth")
        .arg("status")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("did:"));
    assert!(stdout.contains("account: (not bound)"));
    assert!(stdout.contains("account bound: false"));
    assert!(stdout.contains("key cached: false"));
    assert!(stdout.contains("verdict: NotLoggedIn"));
    assert!(stdout.contains("vault state: Local"));

    Ok(())
}

#[test]
fn cli_auth_logout_clears_binding_and_cached_key() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-logout-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let state_path = tn
        .yaml_path()
        .parent()
        .expect("yaml parent")
        .join(".tn")
        .join("sync")
        .join("state.json");
    std::fs::create_dir_all(state_path.parent().expect("state parent"))?;
    std::fs::write(
        &state_path,
        serde_json::json!({
            "account_bound": true,
            "account_id": "acct_logout_cli",
            "pending_claim": { "claim_url": "secret" },
            "other": "kept"
        })
        .to_string(),
    )?;
    let identity_dir = tmp.path().join("identity");
    let store = tn_proto::FileCredentialStore::new(identity_dir.join("credentials.json"));
    store.set_account_awk("acct_logout_cli", &tn_proto::VaultAwk::new([71_u8; 32]))?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("auth")
        .arg("logout")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .env("TN_IDENTITY_DIR", &identity_dir)
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("previous account: acct_logout_cli"));
    assert!(stdout.contains("deleted cached key: true"));
    assert!(stdout.contains("account bound: false"));
    assert!(stdout.contains("verdict: NotLoggedIn"));

    let state: serde_json::Value = serde_json::from_slice(&std::fs::read(state_path)?)?;
    assert!(state.get("account_id").is_none());
    assert_eq!(state["account_bound"].as_bool(), Some(false));
    assert!(state.get("pending_claim").is_none());
    assert_eq!(state["other"].as_str(), Some("kept"));
    assert!(store.get_account_awk("acct_logout_cli")?.is_none());

    Ok(())
}

#[test]
fn cli_auth_whoami_reports_bound_project() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start_json(r#"{"account_id":"acct_whoami"}"#)?;
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-whoami-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let connect = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("auth")
        .arg("connect-code")
        .arg("tn_connect_whoami")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--machine-identity-path")
        .arg(tmp.path().join("missing-identity.json"))
        .output()?;
    assert!(
        connect.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("auth")
        .arg("whoami")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("account: acct_whoami"));
    assert!(stdout.contains("account bound: true"));
    assert!(stdout.contains("key cached: false"));
    assert!(stdout.contains("verdict: LinkedNoKey"));

    Ok(())
}

#[test]
fn cli_vault_connect_links_existing_project() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-vault-connect-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("vault")
        .arg("connect")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg("https://vault.example")
        .arg("--project-id")
        .arg("proj_cli_vault")
        .arg("--project-name")
        .arg("CLI Vault")
        .arg("--no-audit-event")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vault: https://vault.example"));
    assert!(stdout.contains("project id: proj_cli_vault"));
    assert!(stdout.contains("project name: CLI Vault"));
    assert!(stdout.contains("newly linked: true"));
    assert!(stdout.contains("audit event recorded: false"));
    assert!(stdout.contains("state: Linked"));

    let reopened = Tn::init(tn.yaml_path())?;
    let state = reopened.vault().link_state()?;
    assert_eq!(state.state, tn_proto::VaultLinkState::Linked);
    assert_eq!(state.linked_vault.as_deref(), Some("https://vault.example"));
    assert_eq!(state.linked_project_id.as_deref(), Some("proj_cli_vault"));

    Ok(())
}

#[test]
fn cli_vault_unlink_clears_existing_project_link() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-vault-unlink-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(tn_proto::VaultConnectOptions {
        vault: "https://vault.example".to_string(),
        project_id: "proj_cli_unlink".to_string(),
        project_name: Some("CLI Unlink".to_string()),
        record_audit_event: true,
    })?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("vault")
        .arg("unlink")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--reason")
        .arg("operator_requested")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vault: https://vault.example"));
    assert!(stdout.contains("project id: proj_cli_unlink"));
    assert!(stdout.contains("reason: operator_requested"));
    assert!(stdout.contains("audit event recorded: true"));
    assert!(stdout.contains("state: Local"));

    let reopened = Tn::init(tn.yaml_path())?;
    let state = reopened.vault().link_state()?;
    assert_eq!(state.state, tn_proto::VaultLinkState::Local);
    assert_eq!(state.linked_vault, None);
    assert_eq!(state.linked_project_id, None);

    Ok(())
}

#[test]
fn cli_wallet_unlink_alias_clears_existing_project_link() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-unlink-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(tn_proto::VaultConnectOptions {
        vault: "https://vault.example".to_string(),
        project_id: "proj_cli_wallet_unlink".to_string(),
        project_name: Some("CLI Wallet Unlink".to_string()),
        record_audit_event: false,
    })?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("unlink")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--no-audit-event")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vault: https://vault.example"));
    assert!(stdout.contains("project id: proj_cli_wallet_unlink"));
    assert!(stdout.contains("audit event recorded: false"));
    assert!(stdout.contains("state: Local"));

    let reopened = Tn::init(tn.yaml_path())?;
    let state = reopened.vault().link_state()?;
    assert_eq!(state.state, tn_proto::VaultLinkState::Local);
    assert_eq!(state.linked_vault, None);
    assert_eq!(state.linked_project_id, None);

    Ok(())
}

#[test]
fn cli_wallet_sync_pull_only_reports_unbound_project() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("sync")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg("http://127.0.0.1:9")
        .arg("--pull-only")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("staged: 0"));
    assert!(stdout.contains("skipped: 0"));
    assert!(stdout.contains("absorbed: 0"));
    assert!(stdout.contains("pushed: false"));
    assert!(stdout.contains("account: (not bound)"));
    assert!(stdout.contains("account bound: false"));
    assert!(stdout.contains("published groups: (none)"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("account inbox pull skipped because wallet is not account-bound"));

    Ok(())
}

#[test]
fn cli_wallet_status_prints_paths_and_binding_state() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-status-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(tn_proto::VaultConnectOptions {
        vault: "https://vault.example".to_string(),
        project_id: "proj_wallet_status".to_string(),
        project_name: Some("wallet-status-demo".to_string()),
        record_audit_event: false,
    })?;
    let account_state_path = tn
        .yaml_path()
        .parent()
        .expect("yaml parent")
        .join(".tn")
        .join("sync")
        .join("state.json");
    std::fs::create_dir_all(account_state_path.parent().expect("state parent"))?;
    std::fs::write(
        &account_state_path,
        serde_json::json!({
            "account_bound": true,
            "account_id": "acct_wallet_status"
        })
        .to_string(),
    )?;
    let wallet_state_path = tn_proto::wallet_sync_state_path(tn.yaml_path());
    std::fs::create_dir_all(wallet_state_path.parent().expect("wallet state parent"))?;
    std::fs::write(
        &wallet_state_path,
        serde_json::json!({
            "account_bound": true,
            "account_id": "acct_wallet_status"
        })
        .to_string(),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("status")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("yaml:"));
    assert!(stdout.contains("wallet root:"));
    assert!(stdout.contains("wallet inbox:"));
    assert!(stdout.contains("wallet state:"));
    assert!(stdout.contains("account: acct_wallet_status"));
    assert!(stdout.contains("account bound: true"));
    assert!(stdout.contains("wallet account bound: true"));
    assert!(stdout.contains("vault state: Linked"));
    assert!(stdout.contains("vault: https://vault.example"));
    assert!(stdout.contains("project id: proj_wallet_status"));

    Ok(())
}

#[test]
fn cli_wallet_sync_pull_only_stages_bound_inbox_package() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-bound-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let state_path = tn_proto::wallet_sync_state_path(tn.yaml_path());
    std::fs::create_dir_all(state_path.parent().expect("state parent"))?;
    std::fs::write(
        &state_path,
        serde_json::json!({
            "account_bound": true,
            "account_id": "acct_wallet_cli"
        })
        .to_string(),
    )?;
    let server = LocalHttpServer::start_many(vec![
        HttpResponse::json(
            200,
            r#"{"items":[{"publisher_identity":"did:key:zPublisher","ceremony_id":"sync","ts":"2026-06-26T12:00:00Z"}]}"#,
        ),
        HttpResponse::binary(200, b"fake tnpkg bytes"),
    ])?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("sync")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--pull-only")
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("staged: 1"));
    assert!(stdout.contains("account: acct_wallet_cli"));
    assert!(stdout.contains("account bound: true"));
    assert!(stdout.contains("pushed: false"));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/account/inbox "));
    assert!(requests[1].starts_with("GET /api/v1/account/inbox/"));
    assert!(requests[1].contains("did%3Akey%3AzPublisher"));
    assert!(requests[1].contains("2026-06-26T12%3A00%3A00Z.tnpkg"));

    let staged = tn_proto::inbox_dir(tn.yaml_path())
        .join("did_key_zPublisher")
        .join("sync")
        .join("2026-06-26T12_00_00Z.tnpkg");
    assert_eq!(std::fs::read(staged)?, b"fake tnpkg bytes");

    Ok(())
}

#[test]
fn cli_wallet_sync_push_only_uses_passphrase_fallback() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-push-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info(
        "wallet.push.cli",
        serde_json::json!({ "order_id": "CLI-PUSH-1" }),
    )?;

    let passphrase = "correct horse battery staple";
    let awk = tn_proto::VaultAwk::new([42_u8; 32]);
    let salt = [43_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[44_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let server = LocalHttpServer::start_many(vec![
        HttpResponse::json(200, &credential_wrap_list_json(&salt, &wrapped_awk)),
        HttpResponse::json(404, r#"{"error":"missing wrapped key"}"#),
        HttpResponse::json(404, r#"{"error":"missing blob"}"#),
        HttpResponse::json(
            200,
            r#"{"wrapped_bek_b64":"stored","wrap_nonce_b64":"stored_nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        HttpResponse::json(200, r#"{"generation":2}"#),
    ])?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("sync")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--push-only")
        .arg("--account-id")
        .arg("acct_cli_push")
        .arg("--project-id")
        .arg("proj_cli_push")
        .arg("--passphrase")
        .arg(passphrase)
        .env("TN_IDENTITY_DIR", tmp.path().join("identity"))
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("staged: 0"));
    assert!(stdout.contains("absorbed: 0"));
    assert!(stdout.contains("pushed: true"));
    assert!(stdout.contains("account: (not bound)"));

    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_cli_push/wrapped-key "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj_cli_push/encrypted-blob "));
    assert!(requests[3].starts_with("PUT /api/v1/projects/proj_cli_push/wrapped-key "));
    assert!(requests[4].starts_with("PUT /api/v1/projects/proj_cli_push/encrypted-blob-account "));
    assert!(!requests
        .iter()
        .any(|request| request.contains("/api/v1/account/inbox")));

    Ok(())
}

#[test]
fn cli_wallet_sync_push_only_requires_account_id() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-push-missing-account",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let server = LocalHttpServer::start_many(Vec::new())?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("sync")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--push-only")
        .arg("--project-id")
        .arg("proj_missing_account")
        .env("TN_IDENTITY_DIR", tmp.path().join("identity"))
        .output()?;

    assert!(
        !output.status.success(),
        "cli unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("wallet sync requires account_id"));
    assert!(server.requests().is_empty());

    Ok(())
}

#[test]
fn cli_wallet_sync_default_pulls_publishes_and_pushes() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cli-wallet-full-demo",
        TnProjectOptions {
            project_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info(
        "wallet.full.cli",
        serde_json::json!({ "order_id": "CLI-FULL-1" }),
    )?;
    let state_path = tn_proto::wallet_sync_state_path(tn.yaml_path());
    std::fs::create_dir_all(state_path.parent().expect("state parent"))?;
    std::fs::write(
        &state_path,
        serde_json::json!({
            "account_bound": true,
            "account_id": "acct_cli_full"
        })
        .to_string(),
    )?;

    let passphrase = "full sync passphrase";
    let awk = tn_proto::VaultAwk::new([52_u8; 32]);
    let salt = [53_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[54_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let server = LocalHttpServer::start_many(vec![
        HttpResponse::json(
            200,
            r#"{"items":[{"publisher_identity":"did:key:zPublisher","ceremony_id":"sync","ts":"2026-06-26T12:00:00Z"}]}"#,
        ),
        HttpResponse::binary(200, b"not a valid tnpkg archive"),
        HttpResponse::json(
            201,
            r#"{"stored_path":"/stored/group-keys.tnpkg","byte_size":123,"manifest_signature_b64":"sig-group-keys","head_row_hash":null}"#,
        ),
        HttpResponse::json(200, &credential_wrap_list_json(&salt, &wrapped_awk)),
        HttpResponse::json(404, r#"{"error":"missing wrapped key"}"#),
        HttpResponse::json(404, r#"{"error":"missing blob"}"#),
        HttpResponse::json(
            200,
            r#"{"wrapped_bek_b64":"stored","wrap_nonce_b64":"stored_nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        HttpResponse::json(200, r#"{"generation":7}"#),
    ])?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("sync")
        .arg("--yaml")
        .arg(tn.yaml_path())
        .arg("--vault")
        .arg(server.base_url())
        .arg("--project-id")
        .arg("proj_cli_full")
        .arg("--account-id")
        .arg("acct_cli_full")
        .arg("--passphrase")
        .arg(passphrase)
        .env("TN_IDENTITY_DIR", tmp.path().join("identity"))
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("staged: 1"));
    assert!(stdout.contains("absorbed: 0"));
    assert!(stdout.contains("rejected: 1"));
    assert!(stdout.contains("pushed: true"));
    assert!(stdout.contains("account: acct_cli_full"));
    assert!(stdout.contains("account bound: true"));
    assert!(stdout.contains("published groups: default"));

    let requests = server.requests();
    assert_eq!(requests.len(), 8);
    assert!(requests[0].starts_with("GET /api/v1/account/inbox "));
    assert!(requests[1].starts_with("GET /api/v1/account/inbox/"));
    assert!(requests[2].starts_with("POST /api/v1/inbox/"));
    assert!(requests[2].contains("/snapshots/local_"));
    assert!(requests[3].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[4].starts_with("GET /api/v1/projects/proj_cli_full/wrapped-key "));
    assert!(requests[5].starts_with("GET /api/v1/projects/proj_cli_full/encrypted-blob "));
    assert!(requests[6].starts_with("PUT /api/v1/projects/proj_cli_full/wrapped-key "));
    assert!(requests[7].starts_with("PUT /api/v1/projects/proj_cli_full/encrypted-blob-account "));

    Ok(())
}

#[test]
fn cli_wallet_restore_installs_body_with_passphrase_fallback() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let context = Tn::init_project_with_options(
        "cli-wallet-restore-context",
        TnProjectOptions {
            project_dir: Some(tmp.path().join("context")),
            ..Default::default()
        },
    )?;
    let (body, server, passphrase) = cli_restore_fixture(tmp.path(), "cli-wallet-restore-source")?;
    let target = tmp.path().join("restored");

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("restore")
        .arg("--yaml")
        .arg(context.yaml_path())
        .arg("--target-dir")
        .arg(&target)
        .arg("--vault")
        .arg(server.base_url())
        .arg("--account-id")
        .arg("acct_cli_restore")
        .arg("--project-id")
        .arg("proj_cli_restore")
        .arg("--passphrase")
        .arg(passphrase)
        .env("TN_IDENTITY_DIR", tmp.path().join("identity"))
        .output()?;

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("project id: proj_cli_restore"));
    assert!(stdout.contains("written:"));
    assert!(stdout.contains("deduped:"));
    assert_eq!(std::fs::read(target.join("tn.yaml"))?, body["body/tn.yaml"]);
    assert_eq!(
        std::fs::read(target.join("keys").join("local.private"))?,
        body["body/keys/local.private"]
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_cli_restore/wrapped-key "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj_cli_restore/encrypted-blob "));

    Ok(())
}

#[test]
fn cli_wallet_restore_refuses_overwrite_without_flag() -> tn_proto::Result<()> {
    let tmp = tempfile::tempdir()?;
    let context = Tn::init_project_with_options(
        "cli-wallet-restore-conflict-context",
        TnProjectOptions {
            project_dir: Some(tmp.path().join("context-conflict")),
            ..Default::default()
        },
    )?;
    let (_body, server, passphrase) =
        cli_restore_fixture(tmp.path(), "cli-wallet-restore-conflict-source")?;
    let target = tmp.path().join("restore-conflict");
    std::fs::create_dir_all(&target)?;
    std::fs::write(target.join("tn.yaml"), b"different existing file")?;

    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .arg("wallet")
        .arg("restore")
        .arg("--yaml")
        .arg(context.yaml_path())
        .arg("--target-dir")
        .arg(&target)
        .arg("--vault")
        .arg(server.base_url())
        .arg("--account-id")
        .arg("acct_cli_restore")
        .arg("--project-id")
        .arg("proj_cli_restore")
        .arg("--passphrase")
        .arg(passphrase)
        .env("TN_IDENTITY_DIR", tmp.path().join("identity-conflict"))
        .output()?;

    assert!(
        !output.status.success(),
        "cli unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already exists with different contents"));
    assert_eq!(
        std::fs::read(target.join("tn.yaml"))?,
        b"different existing file"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_cli_restore/wrapped-key "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj_cli_restore/encrypted-blob "));

    Ok(())
}

fn cli_restore_fixture(
    root: &std::path::Path,
    source_dir: &str,
) -> tn_proto::Result<(tn_proto::VaultBodyPlaintext, LocalHttpServer, &'static str)> {
    let source = Tn::init_project_with_options(
        "cli-wallet-restore-source",
        TnProjectOptions {
            project_dir: Some(root.join(source_dir)),
            ..Default::default()
        },
    )?;
    source.info(
        "wallet.restore.cli",
        serde_json::json!({ "order_id": "CLI-RESTORE-1" }),
    )?;
    let body = source.vault().collect_body()?;

    let passphrase = "restore cli passphrase";
    let awk = tn_proto::VaultAwk::new([62_u8; 32]);
    let bek = tn_proto::VaultBek::new([63_u8; 32]);
    let salt = [64_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[65_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let wrapped_bek = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[66_u8; 12])?;
    let encrypted = tn_proto::encrypt_vault_body_with_nonce(&body, &bek, &[67_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped_bek.into_json()).expect("wrapped json");
    let encrypted_json = serde_json::json!({
        "ciphertext_b64": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        )
    })
    .to_string();
    let server = LocalHttpServer::start_many(vec![
        HttpResponse::json(200, &credential_wrap_list_json(&salt, &wrapped_awk)),
        HttpResponse::json(200, &wrapped_json),
        HttpResponse::json(200, &encrypted_json),
    ])?;
    Ok((body, server, passphrase))
}

struct WrappedRaw {
    wrapped_b64: String,
    nonce_b64: String,
}

fn credential_wrap_list_json(salt: &[u8], wrapped: &WrappedRaw) -> String {
    serde_json::json!([{
        "is_primary": true,
        "kdf": "pbkdf2-sha256",
        "kdf_params": {
            "salt_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                salt
            ),
            "iterations": 10000
        },
        "wrapped_account_key_b64": wrapped.wrapped_b64,
        "wrap_nonce_b64": wrapped.nonce_b64
    }])
    .to_string()
}

fn wrap_raw_with_nonce(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> tn_proto::Result<WrappedRaw> {
    use aes_gcm::aead::{Aead as _, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| tn_proto::Error::InvalidArgument(format!("invalid test key: {err}")))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| tn_proto::Error::InvalidArgument("test wrap failed".into()))?;
    Ok(WrappedRaw {
        wrapped_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        nonce_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
    })
}

fn assert_help_contains(args: &[&str], expected: &[&str]) -> tn_proto::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_tn-proto"))
        .args(args)
        .output()?;

    assert!(
        output.status.success(),
        "cli help failed for {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in expected {
        assert!(
            stdout.contains(needle),
            "help for {:?} did not contain {:?}\nstdout:\n{}",
            args,
            needle,
            stdout
        );
    }

    Ok(())
}

#[derive(Clone)]
struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.as_bytes().to_vec(),
        }
    }

    fn binary(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body: body.to_vec(),
        }
    }
}

struct LocalHttpServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LocalHttpServer {
    fn start_json(body: &str) -> tn_proto::Result<Self> {
        Self::start_many(vec![HttpResponse::json(200, body)])
    }

    fn start_many(responses: Vec<HttpResponse>) -> tn_proto::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for response in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                };
                let _ = stream.set_nonblocking(false);
                let mut buf = [0_u8; 8192];
                let mut request_text = String::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            request_text.push_str(&String::from_utf8_lossy(&buf[..n]));
                            if request_text.contains("\r\n\r\n") {
                                let content_len = request_text
                                    .lines()
                                    .find_map(|line| {
                                        line.strip_prefix("content-length: ")
                                            .or_else(|| line.strip_prefix("Content-Length: "))
                                            .and_then(|value| value.trim().parse::<usize>().ok())
                                    })
                                    .unwrap_or(0);
                                let body_len = request_text
                                    .split_once("\r\n\r\n")
                                    .map(|(_, body)| body.as_bytes().len())
                                    .unwrap_or(0);
                                if body_len >= content_len {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                captured.lock().expect("request lock").push(request_text);
                let reason = if response.status == 200 {
                    "OK"
                } else {
                    "ERROR"
                };
                let response_head = format!(
                    "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.status,
                    reason,
                    response.content_type,
                    response.body.len(),
                );
                let _ = stream.write_all(response_head.as_bytes());
                let _ = stream.write_all(&response.body);
            }
        });

        Ok(Self {
            base_url: format!("http://{addr}"),
            requests,
            handle: Some(handle),
        })
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn request(&self) -> String {
        self.requests()
            .into_iter()
            .next()
            .expect("request should have been captured")
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().expect("server thread should finish");
        }
    }
}
