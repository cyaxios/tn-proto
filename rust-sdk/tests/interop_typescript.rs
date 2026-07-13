mod common;

use std::process::Command;

use serde_json::{json, Value};
use tempfile::TempDir;
use tn_proto::{
    AbsorbReceiptExt, BundleForRecipientOptions, MintInvitationOptions, ReadOptions,
    SecretExportConsent, Tn,
};

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn typescript_emits_rust_reads() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let tmp_arg = tmp.path().to_string_lossy().to_string();
    let yaml_path = run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const projectDir = process.argv[1];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
tn.info("ts.rust_sdk_interop.created", { marker: "typescript-to-rust" });
console.log(tn.yamlPath);
await tn.close();
"#,
        &[&tmp_arg],
    );

    let tn = Tn::init(yaml_path.trim())?;
    let entries = tn.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    let entry = common::find_event(&entries, "ts.rust_sdk_interop.created");
    assert_eq!(
        entry.get("marker").and_then(Value::as_str),
        Some("typescript-to-rust")
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn rust_emits_typescript_reads() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let tmp_arg = tmp.path().to_string_lossy().to_string();
    let yaml_path = run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const projectDir = process.argv[1];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
console.log(tn.yamlPath);
await tn.close();
"#,
        &[&tmp_arg],
    );
    let yaml_path = yaml_path.trim().to_string();

    let tn = Tn::init(&yaml_path)?;
    tn.info(
        "rust.rust_sdk_interop.created",
        json!({ "marker": "rust-to-typescript" }),
    )?;
    tn.close()?;

    let output = run_node(
        r#"
import { Tn } from "./src/tn.ts";

const yamlPath = process.argv[1];
const tn = await Tn.init(yamlPath, { stdout: false });
const rows = Array.from(tn.read({ allRuns: true })).map((entry) => ({
  event_type: entry.event_type,
  fields: entry.fields ?? entry,
}));
console.log(JSON.stringify(rows));
await tn.close();
"#,
        &[&yaml_path],
    );
    assert!(
        output.contains("rust.rust_sdk_interop.created") && output.contains("rust-to-typescript"),
        "TypeScript read did not see Rust event: {output}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn rust_admin_snapshot_typescript_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
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
    let tmp_arg = tmp.path().to_string_lossy().to_string();
    let output = run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const pkgPath = process.argv[1];
const projectDir = process.argv[2];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
const receipt = await tn.pkg.absorb(pkgPath);
console.log(JSON.stringify(receipt));
await tn.close();
"#,
        &[&pkg_arg, &tmp_arg],
    );
    let receipt = last_json_object(&output);
    assert_eq!(
        receipt.get("kind").and_then(Value::as_str),
        Some("admin_log_snapshot")
    );
    assert!(
        receipt.get("rejectedReason").is_none()
            || receipt.get("rejectedReason") == Some(&Value::Null),
        "TypeScript rejected Rust admin snapshot: {receipt}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn typescript_admin_snapshot_rust_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("typescript-admin-snapshot.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();

    run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const outPath = process.argv[1];
const projectDir = process.argv[2];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
tn.info("ts.package.created", { marker: "typescript-package-to-rust" });
await tn.pkg.export({ adminLogSnapshot: { outPath } }, outPath);
console.log(outPath);
await tn.close();
"#,
        &[&pkg_arg, &tmp_arg],
    );

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "admin_log_snapshot");
    assert_ne!(
        receipt.legacy_status, "rejected",
        "Rust rejected TypeScript admin snapshot: {receipt:?}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn rust_project_seed_typescript_bootstrap_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-project-seed.tnpkg");
    let restore_dir = tmp.path().join("ts-restore");

    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let producer_did = producer.did().to_string();
    producer
        .pkg()
        .export_project_seed(&pkg_path, None, SecretExportConsent::acknowledge())?;

    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let restore_arg = restore_dir.to_string_lossy().to_string();
    let output = run_node(
        r#"
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { DeviceKey, Tn, absorbBootstrap } from "./src/index.ts";

const pkgPath = process.argv[1];
const restoreDir = process.argv[2];
const receipt = absorbBootstrap(pkgPath, { cwd: restoreDir });
const tn = await Tn.init(join(restoreDir, "tn.yaml"), { stdout: false });
const cfg = tn.config();
const seed = new Uint8Array(readFileSync(join(cfg.keystorePath, "local.private")));
const derivedDid = DeviceKey.fromSeed(seed).did;
tn.info("ts.restored.project_seed", { marker: "rust-project-seed-to-typescript" });
const rows = Array.from(tn.read()).filter((entry) => !entry.event_type.startsWith("tn."));
const last = rows.at(-1);
console.log(JSON.stringify({
  kind: receipt.kind,
  rejectedReason: receipt.rejectedReason ?? null,
  did: tn.did,
  derivedDid,
  groups: Array.from(cfg.groups.keys()).sort(),
  event_type: last?.event_type ?? null,
  fields: last?.fields ?? null,
}));
await tn.close();
"#,
        &[&pkg_arg, &restore_arg],
    );

    let restored = last_json_object(&output);
    assert_eq!(
        restored.get("kind").and_then(Value::as_str),
        Some("project_seed")
    );
    assert!(
        restored.get("rejectedReason").is_none()
            || restored.get("rejectedReason") == Some(&Value::Null),
        "TypeScript rejected Rust project_seed: {restored}"
    );
    assert_eq!(
        restored.get("did").and_then(Value::as_str),
        Some(producer_did.as_str())
    );
    assert_eq!(
        restored.get("derivedDid").and_then(Value::as_str),
        Some(producer_did.as_str())
    );
    assert_eq!(
        restored.get("event_type").and_then(Value::as_str),
        Some("ts.restored.project_seed")
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn typescript_project_seed_rust_verifies_and_stashes() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("typescript-project-seed.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();

    run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const outPath = process.argv[1];
const projectDir = process.argv[2];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
tn.info("ts.project_seed.source", { marker: "typescript-project-seed-to-rust" });
tn._rt.exportPkg({ kind: "project_seed", confirmIncludesSecrets: true }, outPath);
console.log(outPath);
await tn.close();
"#,
        &[&pkg_arg, &tmp_arg],
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
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn rust_kit_bundle_typescript_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-kit-bundle.tnpkg");

    let producer = Tn::ephemeral()?;
    producer.pkg().export_kit_bundle(
        &pkg_path,
        Some(vec!["default".to_string()]),
        Some("did:key:zTypescriptInteropRecipient".to_string()),
    )?;

    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();
    let output = run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const pkgPath = process.argv[1];
const projectDir = process.argv[2];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
const receipt = await tn.pkg.absorb(pkgPath);
const duplicate = await tn.pkg.absorb(pkgPath);
console.log(JSON.stringify({
  kind: receipt.kind,
  acceptedCount: receipt.acceptedCount,
  dedupedCount: receipt.dedupedCount,
  rejectedReason: receipt.rejectedReason ?? null,
  replacedKitPaths: receipt.replacedKitPaths ?? [],
  duplicateStatus: duplicate.status ?? null,
  duplicateAcceptedCount: duplicate.acceptedCount,
  duplicateDedupedCount: duplicate.dedupedCount,
}));
await tn.close();
"#,
        &[&pkg_arg, &tmp_arg],
    );

    let receipt = last_json_object(&output);
    assert_eq!(
        receipt.get("kind").and_then(Value::as_str),
        Some("kit_bundle")
    );
    assert!(
        receipt.get("rejectedReason").is_none()
            || receipt.get("rejectedReason") == Some(&Value::Null),
        "TypeScript rejected Rust kit_bundle: {receipt}"
    );
    assert!(
        receipt
            .get("acceptedCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "TypeScript should install at least one Rust kit: {receipt}"
    );
    assert!(
        receipt
            .get("duplicateDedupedCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "TypeScript duplicate absorb should dedupe the Rust kit: {receipt}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn rust_sealed_kit_bundle_typescript_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("rust-sealed-kit-bundle.tnpkg");
    let tmp_arg = tmp.path().to_string_lossy().to_string();

    let consumer_info = run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const projectDir = process.argv[1];
const tn = await Tn.init(join(projectDir, "ts-sealed-kit-consumer", "tn.yaml"), {
  stdout: false,
});
console.log(JSON.stringify({
  did: tn.did,
  yaml: tn.yamlPath,
}));
await tn.close();
"#,
        &[&tmp_arg],
    );
    let consumer_info = last_json_object(&consumer_info);
    let consumer_did = consumer_info
        .get("did")
        .and_then(Value::as_str)
        .expect("TypeScript should print consumer did")
        .to_string();
    let consumer_yaml = consumer_info
        .get("yaml")
        .and_then(Value::as_str)
        .expect("TypeScript should print consumer yaml")
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
    let output = run_node(
        r#"
import { existsSync } from "node:fs";
import { join } from "node:path";
import { Tn } from "./src/tn.ts";

const yamlPath = process.argv[1];
const pkgPath = process.argv[2];
const tn = await Tn.init(yamlPath, { stdout: false });
const receipt = await tn.pkg.absorb(pkgPath);
const duplicate = await tn.pkg.absorb(pkgPath);
const cfg = tn.config();
console.log(JSON.stringify({
  kind: receipt.kind,
  acceptedCount: receipt.acceptedCount,
  dedupedCount: receipt.dedupedCount,
  rejectedReason: receipt.rejectedReason ?? null,
  duplicateStatus: duplicate.status ?? null,
  duplicateAcceptedCount: duplicate.acceptedCount,
  duplicateDedupedCount: duplicate.dedupedCount,
  kitExists: existsSync(join(cfg.keystorePath, "default.btn.mykit")),
}));
await tn.close();
"#,
        &[&consumer_yaml, &pkg_arg],
    );

    let receipt = last_json_object(&output);
    assert_eq!(
        receipt.get("kind").and_then(Value::as_str),
        Some("kit_bundle")
    );
    assert!(
        receipt.get("rejectedReason").is_none()
            || receipt.get("rejectedReason") == Some(&Value::Null),
        "TypeScript rejected Rust sealed kit_bundle: {receipt}"
    );
    assert!(
        receipt
            .get("acceptedCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "TypeScript should install the Rust sealed kit: {receipt}"
    );
    assert_eq!(
        receipt.get("kitExists").and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        receipt
            .get("duplicateDedupedCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "TypeScript duplicate absorb should dedupe the Rust sealed kit: {receipt}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn typescript_kit_bundle_rust_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("typescript-kit-bundle.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();

    run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const outPath = process.argv[1];
const projectDir = process.argv[2];
const tn = await Tn.init(join(projectDir, "tn.yaml"), {
  stdout: false,
});
tn._rt.exportPkg({ kind: "kit_bundle" }, outPath);
console.log(outPath);
await tn.close();
"#,
        &[&pkg_arg, &tmp_arg],
    );

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_ne!(receipt.legacy_status, "rejected");
    assert!(
        receipt.accepted_count > 0,
        "Rust should install at least one TypeScript kit: {receipt:?}"
    );

    let duplicate = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(duplicate.kind, "kit_bundle");
    assert_eq!(duplicate.legacy_status, "no_op");
    assert!(duplicate.deduped_count > 0);

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn typescript_sealed_kit_bundle_rust_absorbs() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let pkg_path = tmp.path().join("typescript-sealed-kit-bundle.tnpkg");
    let pkg_arg = pkg_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();
    let consumer = Tn::ephemeral()?;
    let recipient_did = consumer.did().to_string();

    run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { join } from "node:path";

const outPath = process.argv[1];
const projectDir = process.argv[2];
const recipientDid = process.argv[3];
const tn = await Tn.init(join(projectDir, "ts-sealed-kit-producer", "tn.yaml"), {
  stdout: false,
});
await tn.pkg.bundleForRecipient({
  recipientDid,
  outPath,
  groups: ["default"],
  sealForRecipient: true,
});
console.log(outPath);
await tn.close();
"#,
        &[&pkg_arg, &tmp_arg, &recipient_did],
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
        "Rust should install the TypeScript sealed kit: {receipt:?}"
    );

    let duplicate = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(duplicate.kind, "kit_bundle");
    assert_eq!(duplicate.legacy_status, "no_op");
    assert!(duplicate.deduped_count > 0);

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn rust_invite_typescript_accepts() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let invite_path = tmp.path().join("tn-invite-rust-typescript.zip");
    let producer = Tn::ephemeral()?;
    producer.inbox().mint_invite_path(
        "did:key:zTypescriptInviteRecipient",
        &invite_path,
        MintInvitationOptions {
            from_email: Some("rust@example.test".to_string()),
            invitation_id: Some("rust-typescript".to_string()),
            ..MintInvitationOptions::default()
        },
    )?;

    let invite_arg = invite_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();
    let output = run_node(
        r#"
import { Tn } from "./src/tn.ts";
import { accept } from "./src/cli/inbox_accept.ts";
import { basename, dirname, extname, join, resolve } from "node:path";
import { existsSync, readFileSync } from "node:fs";

const invitePath = process.argv[1];
const projectDir = process.argv[2];
const yamlPath = join(projectDir, "ts-invite-consumer", "tn.yaml");
const tn = await Tn.init(yamlPath, { stdout: false });
await tn.close();

const result = await accept(invitePath, yamlPath, () => {});
const yamlText = readFileSync(yamlPath, "utf8");
const explicitAdmin = yamlText.match(/admin_log_location:\s*["']?([^"'\r\n]+)["']?/);
const stem = basename(yamlPath, extname(yamlPath));
const adminLog = explicitAdmin
  ? resolve(dirname(yamlPath), explicitAdmin[1].trim())
  : join(dirname(yamlPath), ".tn", stem, "admin", "default.ndjson");
const rows = existsSync(adminLog)
  ? readFileSync(adminLog, "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter((entry) => entry.event_type === "tn.enrolment.absorbed")
  : [];
console.log(JSON.stringify({
  groupName: result.groupName,
  fromEmail: result.fromEmail,
  kitPath: result.kitPath,
  kitExists: existsSync(result.kitPath),
  absorbedCount: rows.length,
  publisherIdentity: rows[0]?.publisher_identity ?? null,
}));
"#,
        &[&invite_arg, &tmp_arg],
    );

    let result = last_json_object(&output);
    assert_eq!(
        result.get("groupName").and_then(Value::as_str),
        Some("default")
    );
    assert_eq!(
        result.get("fromEmail").and_then(Value::as_str),
        Some("rust@example.test")
    );
    assert_eq!(result.get("kitExists").and_then(Value::as_bool), Some(true));
    assert!(
        result
            .get("absorbedCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "TypeScript accept should record tn.enrolment.absorbed: {result}"
    );

    Ok(())
}

#[test]
#[ignore = "requires local ts-sdk dependencies/build setup; run with cargo test -p tn-proto --test interop_typescript -- --ignored"]
fn typescript_invite_rust_accepts() -> tn_proto::Result<()> {
    if !typescript_ready() {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let invite_path = tmp.path().join("tn-invite-typescript-rust.zip");
    let invite_arg = invite_path.to_string_lossy().to_string();
    let tmp_arg = tmp.path().to_string_lossy().to_string();

    let output = run_node(
        r#"
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Tn } from "./src/tn.ts";
import { packTnpkg } from "./src/core/tnpkg_archive.ts";

const invitePath = process.argv[1];
const projectDir = process.argv[2];
const yamlPath = join(projectDir, "ts-invite-producer", "tn.yaml");
const tn = await Tn.init(yamlPath, { stdout: false });
const cfg = tn.config();
const kitPath = join(cfg.keystorePath, "default.btn.mykit");
const kit = readFileSync(kitPath);
const manifest = {
  group_name: "default",
  leaf_index: 9,
  kit_sha256: `sha256:${createHash("sha256").update(kit).digest("hex")}`,
  from_email: "typescript@example.test",
  from_account_did: tn.did,
  invitation_id: "typescript-rust",
  provenance: "ts-sdk",
};
const zip = packTnpkg([
  { name: "manifest.json", data: new TextEncoder().encode(JSON.stringify(manifest)) },
  { name: "default.btn.mykit", data: kit },
]);
writeFileSync(invitePath, zip);
console.log(JSON.stringify({
  inviteExists: existsSync(invitePath),
  fromDid: tn.did,
  kitSha256: manifest.kit_sha256,
}));
await tn.close();
"#,
        &[&invite_arg, &tmp_arg],
    );

    let minted = last_json_object(&output);
    assert_eq!(
        minted.get("inviteExists").and_then(Value::as_bool),
        Some(true)
    );

    let consumer = Tn::ephemeral()?;
    let info = consumer.inbox().inspect_path(&invite_path)?;
    assert_eq!(info.group_name(), "default");
    assert_eq!(
        info.manifest.from_email.as_deref(),
        Some("typescript@example.test")
    );
    assert_eq!(
        info.manifest.invitation_id.as_deref(),
        Some("typescript-rust")
    );
    assert!(matches!(
        info.kit_hash,
        tn_proto::InvitationKitHash::Verified { .. }
    ));

    let accepted = consumer.inbox().accept_path(&invite_path)?;
    assert_eq!(accepted.group_name(), "default");
    assert_eq!(accepted.from_email(), "typescript@example.test");
    assert!(accepted.kit_path.exists());

    let entries = consumer.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    let absorbed = common::find_event(&entries, "tn.enrolment.absorbed");
    assert_eq!(
        absorbed.get("publisher_identity").and_then(Value::as_str),
        minted.get("fromDid").and_then(Value::as_str)
    );
    assert_eq!(
        absorbed.get("package_sha256").and_then(Value::as_str),
        minted.get("kitSha256").and_then(Value::as_str)
    );

    Ok(())
}

fn typescript_ready() -> bool {
    let mut command = node_command();
    command
        .arg("--input-type=module")
        .arg("-e")
        .arg("import { Tn } from './src/tn.ts'; console.log(typeof Tn);");

    match command.output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            eprintln!(
                "skipping TypeScript interop: ts-sdk runtime is not importable in this environment\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
        Err(err) => {
            eprintln!("skipping TypeScript interop: failed to start node: {err}");
            false
        }
    }
}

fn run_node(code: &str, args: &[&str]) -> String {
    let mut command = node_command();
    command.arg("--input-type=module").arg("-e").arg(code);
    for arg in args {
        command.arg(arg);
    }
    let output = command.output().expect("failed to run node");
    assert!(
        output.status.success(),
        "node failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("node stdout should be UTF-8")
}

fn node_command() -> Command {
    let repo = common::repo_root();
    let ts_sdk = repo.join("ts-sdk");
    let mut command = Command::new("node");
    command
        .current_dir(ts_sdk)
        .env("TN_NO_STDOUT", "1")
        .arg("--import")
        .arg("tsx")
        .arg("--import")
        .arg("./test/_setup_wasm.mjs");
    command
}

fn last_json_object(output: &str) -> Value {
    output
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .unwrap_or_else(|| panic!("expected a JSON object in stdout: {output}"))
}
