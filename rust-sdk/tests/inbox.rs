use std::io::{Cursor, Write};

use serde_json::json;
use sha2::{Digest, Sha256};
use tn_proto::{InvitationKitHash, MintInvitationOptions, ReadOptions, Tn};
use zip::write::SimpleFileOptions;

#[test]
fn inbox_lists_local_invitation_zips_sorted() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let dir = temp.path();
    std::fs::write(dir.join("tn-invite-b.zip"), [])?;
    std::fs::write(dir.join("tn-invite-a.zip"), [])?;
    std::fs::write(dir.join("not-an-invite.zip"), [])?;
    std::fs::write(dir.join("tn-invite-c.txt"), [])?;

    let tn = Tn::ephemeral()?;
    let found = tn.inbox().list_local(dir)?;
    assert_eq!(
        found
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["tn-invite-a.zip", "tn-invite-b.zip"]
    );

    let missing = tn.inbox().list_local(dir.join("missing"))?;
    assert!(missing.is_empty());

    Ok(())
}

#[test]
fn inbox_inspects_invitation_zip_and_verifies_kit_hash() -> tn_proto::Result<()> {
    let kit = b"reader kit bytes";
    let manifest = json!({
        "invitation_id": "invite-1",
        "from_account_did": "did:key:zAlice",
        "from_email": "alice@example.test",
        "project_id": "proj_123",
        "project_name": "payments",
        "group_name": "payments",
        "leaf_index": 7,
        "kit_sha256": format!("sha256:{}", sha256_hex(kit)),
        "created_at": "2026-01-02T03:04:05Z",
        "note": "welcome",
        "provenance": "cli-minted",
        "future_field": {"kept": true}
    });
    let bytes = invite_zip_bytes(&manifest, "payments.btn.mykit", kit)?;

    let tn = Tn::ephemeral()?;
    let info = tn.inbox().inspect_bytes(&bytes)?;
    assert_eq!(info.manifest.invitation_id.as_deref(), Some("invite-1"));
    assert_eq!(info.group_name(), "payments");
    assert_eq!(info.kit_entry_name, "payments.btn.mykit");
    assert_eq!(info.kit_len, kit.len());
    assert_eq!(info.kit_sha256_actual, sha256_hex(kit));
    assert!(info.kit_hash_verified());
    assert_eq!(
        info.kit_hash,
        InvitationKitHash::Verified {
            expected: format!("sha256:{}", sha256_hex(kit))
        }
    );
    assert_eq!(info.manifest.extra["future_field"]["kept"], true);

    Ok(())
}

#[test]
fn inbox_accepts_legacy_kit_entry_and_missing_hash() -> tn_proto::Result<()> {
    let manifest = json!({
        "group_name": "default",
        "from_email": "alice@example.test"
    });
    let bytes = invite_zip_bytes(&manifest, "kit.tnpkg", b"legacy kit")?;

    let tn = Tn::ephemeral()?;
    let info = tn.inbox().inspect_bytes(&bytes)?;
    assert_eq!(info.group_name(), "default");
    assert_eq!(info.kit_entry_name, "kit.tnpkg");
    assert_eq!(info.kit_hash, InvitationKitHash::NotPresent);
    assert!(!info.kit_hash_verified());

    Ok(())
}

#[test]
fn inbox_uses_single_kit_shaped_fallback() -> tn_proto::Result<()> {
    let kit = b"fallback kit";
    let manifest = json!({
        "group_name": "readers",
        "kit_sha256": sha256_hex(kit)
    });
    let bytes = invite_zip_bytes(&manifest, "custom-reader.btn.mykit", kit)?;

    let tn = Tn::ephemeral()?;
    let info = tn.inbox().inspect_bytes(&bytes)?;
    assert_eq!(info.kit_entry_name, "custom-reader.btn.mykit");
    assert!(info.kit_hash_verified());

    Ok(())
}

#[test]
fn inbox_rejects_invalid_invitation_zips() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let not_zip = tn.inbox().inspect_bytes(b"not a zip").unwrap_err();
    assert!(not_zip.to_string().contains("invalid invitation zip"));

    let missing_manifest = raw_zip_bytes([("default.btn.mykit", b"kit".as_slice())])?;
    let err = tn.inbox().inspect_bytes(&missing_manifest).unwrap_err();
    assert!(err.to_string().contains("missing manifest.json"));

    let missing_kit =
        raw_zip_bytes([("manifest.json", br#"{"group_name":"default"}"#.as_slice())])?;
    let err = tn.inbox().inspect_bytes(&missing_kit).unwrap_err();
    assert!(err.to_string().contains("missing kit.tnpkg"));

    let kit = b"kit";
    let bad_hash = invite_zip_bytes(
        &json!({
            "group_name": "default",
            "kit_sha256": "sha256:0000"
        }),
        "default.btn.mykit",
        kit,
    )?;
    let err = tn.inbox().inspect_bytes(&bad_hash).unwrap_err();
    assert!(err.to_string().contains("kit hash mismatch"));

    let ambiguous = raw_zip_bytes([
        ("manifest.json", br#"{"group_name":"missing"}"#.as_slice()),
        ("one.btn.mykit", b"one".as_slice()),
        ("two.tnpkg", b"two".as_slice()),
    ])?;
    let err = tn.inbox().inspect_bytes(&ambiguous).unwrap_err();
    assert!(err.to_string().contains("missing kit.tnpkg"));

    Ok(())
}

#[test]
fn inbox_accept_installs_kit_backs_up_existing_and_emits_attestation() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let group = "default";
    let kit = b"accepted reader kit";
    let manifest = json!({
        "invitation_id": "invite-accept",
        "from_account_did": "did:key:zInvitePublisher",
        "from_email": "alice@example.test",
        "group_name": group,
        "leaf_index": 12,
        "kit_sha256": format!("sha256:{}", sha256_hex(kit)),
    });
    let bytes = invite_zip_bytes(&manifest, "default.btn.mykit", kit)?;
    let existing_kit = tn
        .yaml_path()
        .parent()
        .unwrap()
        .join(".tn")
        .join("keys")
        .join("default.btn.mykit");
    assert!(
        existing_kit.exists(),
        "ephemeral runtime should seed default kit"
    );
    let existing_bytes = std::fs::read(&existing_kit)?;

    let result = tn.inbox().accept_bytes(&bytes)?;
    assert_eq!(result.group_name(), group);
    assert_eq!(result.from_email(), "alice@example.test");
    assert_eq!(result.leaf_index(), Some(&json!(12)));
    assert_eq!(result.kit_path, existing_kit);
    assert_eq!(std::fs::read(&result.kit_path)?, kit);

    let backup = result
        .backup_path
        .as_ref()
        .expect("existing default kit should be backed up");
    assert!(backup.exists());
    assert_eq!(std::fs::read(backup)?, existing_bytes);

    let entries = tn.read(ReadOptions::default())?;
    let absorbed = entries
        .iter()
        .find(|entry| entry.event_type() == Some("tn.enrolment.absorbed"))
        .expect("accept should emit enrolment absorbed attestation");
    let fields = absorbed.as_map();
    assert_eq!(fields["group"], group);
    assert_eq!(fields["publisher_identity"], "did:key:zInvitePublisher");
    assert_eq!(
        fields["package_sha256"],
        format!("sha256:{}", sha256_hex(kit))
    );
    assert_eq!(fields["absorbed_at"], result.absorbed_at);

    Ok(())
}

#[test]
fn inbox_accept_rejects_bad_hash_before_mutating_keystore() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let kit_path = tn
        .yaml_path()
        .parent()
        .unwrap()
        .join(".tn")
        .join("keys")
        .join("default.btn.mykit");
    let before = std::fs::read(&kit_path)?;
    let before_entries = tn.read(ReadOptions::default())?.len();

    let bytes = invite_zip_bytes(
        &json!({
            "group_name": "default",
            "from_account_did": "did:key:zInvitePublisher",
            "kit_sha256": "sha256:bad"
        }),
        "default.btn.mykit",
        b"tampered kit",
    )?;
    let err = tn.inbox().accept_bytes(&bytes).unwrap_err();
    assert!(err.to_string().contains("kit hash mismatch"));
    assert_eq!(std::fs::read(&kit_path)?, before);
    assert_eq!(tn.read(ReadOptions::default())?.len(), before_entries);

    Ok(())
}

#[test]
fn inbox_mint_invite_writes_python_typescript_shaped_zip() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let out = tn.log_path().parent().unwrap().join("tn-invite-rust.zip");

    let result = tn.inbox().mint_invite_path(
        "did:key:zRecipient",
        &out,
        MintInvitationOptions {
            group: Some("default".to_string()),
            from_email: Some("alice@example.test".to_string()),
            project_id: Some("proj_123".to_string()),
            project_name: Some("payments".to_string()),
            note: Some("hello".to_string()),
            invitation_id: Some("invite-rust".to_string()),
            provenance: Some("test".to_string()),
        },
    )?;

    assert_eq!(result.path, out);
    assert_eq!(result.recipient_did, "did:key:zRecipient");
    assert_eq!(result.kit_entry_name, "default.btn.mykit");
    assert!(result.zip_len > 0);
    assert!(out.exists());

    let info = tn.inbox().inspect_path(&out)?;
    assert_eq!(info.kit_entry_name, "default.btn.mykit");
    assert!(info.kit_hash_verified());
    assert_eq!(info.manifest.invitation_id.as_deref(), Some("invite-rust"));
    assert_eq!(info.manifest.from_account_did.as_deref(), Some(tn.did()));
    assert_eq!(
        info.manifest.from_email.as_deref(),
        Some("alice@example.test")
    );
    assert_eq!(info.manifest.project_id.as_deref(), Some("proj_123"));
    assert_eq!(info.manifest.project_name.as_deref(), Some("payments"));
    assert_eq!(info.manifest.group_name.as_deref(), Some("default"));
    assert_eq!(info.manifest.leaf_index, Some(json!(1)));
    assert_eq!(info.manifest.note.as_deref(), Some("hello"));
    assert_eq!(info.manifest.provenance.as_deref(), Some("test"));
    assert_eq!(info.manifest.kit_sha256, result.manifest.kit_sha256);

    Ok(())
}

#[test]
fn inbox_mint_invite_accept_roundtrip_between_rust_ceremonies() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let consumer = Tn::ephemeral()?;
    let out = producer
        .log_path()
        .parent()
        .unwrap()
        .join("tn-invite-peer.zip");

    let minted = producer.inbox().mint_invite_path(
        consumer.did(),
        &out,
        MintInvitationOptions {
            from_email: Some("producer@example.test".to_string()),
            invitation_id: Some("roundtrip".to_string()),
            ..MintInvitationOptions::default()
        },
    )?;
    assert_eq!(minted.recipient_did, consumer.did());
    assert_eq!(minted.manifest.leaf_index, Some(json!(1)));

    let accepted = consumer.inbox().accept_path(&out)?;
    assert_eq!(accepted.group_name(), "default");
    assert_eq!(accepted.from_email(), "producer@example.test");
    assert_eq!(
        accepted.info.manifest.from_account_did.as_deref(),
        Some(producer.did())
    );
    assert_eq!(
        accepted.info.manifest.kit_sha256,
        minted.manifest.kit_sha256
    );
    assert_eq!(
        std::fs::read(&accepted.kit_path)?,
        invite_kit_bytes(&std::fs::read(&out)?, "default.btn.mykit")?
    );

    let entries = consumer.read(ReadOptions::default())?;
    assert!(entries.iter().any(|entry| {
        entry.event_type() == Some("tn.enrolment.absorbed")
            && entry
                .get("publisher_identity")
                .and_then(serde_json::Value::as_str)
                == Some(producer.did())
    }));

    Ok(())
}

#[test]
fn inbox_mint_invite_uses_python_friendly_label_placeholder() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    let out = tn.log_path().parent().unwrap().join("tn-invite-label.zip");

    let result = tn
        .inbox()
        .mint_invite_path("Frank", &out, MintInvitationOptions::default())?;
    assert_eq!(result.recipient_did, "did:key:zLabel-Frank");

    let recipients = tn.admin().recipients("default", false)?;
    assert!(recipients
        .iter()
        .any(|entry| entry.recipient_identity.as_deref() == Some("did:key:zLabel-Frank")));

    Ok(())
}

fn invite_zip_bytes(
    manifest: &serde_json::Value,
    kit_name: &str,
    kit_bytes: &[u8],
) -> tn_proto::Result<Vec<u8>> {
    let manifest = serde_json::to_vec_pretty(manifest)?;
    raw_zip_bytes([
        (kit_name, kit_bytes),
        ("manifest.json", manifest.as_slice()),
    ])
}

fn raw_zip_bytes<const N: usize>(entries: [(&str, &[u8]); N]) -> tn_proto::Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(name, opts)?;
            writer.write_all(bytes)?;
        }
        writer.finish()?;
    }
    Ok(buf)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn invite_kit_bytes(zip_bytes: &[u8], kit_name: &str) -> tn_proto::Result<Vec<u8>> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let mut kit = archive.by_name(kit_name)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut kit, &mut bytes)?;
    Ok(bytes)
}
