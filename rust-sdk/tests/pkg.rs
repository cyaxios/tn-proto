use std::collections::BTreeMap;

use serde_json::json;
use tn_core::tnpkg::{
    read_tnpkg, sign_manifest, verify_manifest, write_tnpkg, ManifestKind, TnpkgSource,
};
use tn_proto::{
    AbsorbReceiptExt, AbsorbStatus, BundleForRecipientOptions, CompileEnrolmentOptions,
    OfferOptions, PackageSignatureStatus, PkgExportOptions, ReadOptions, SecretExportConsent, Tn,
    TnProjectOptions,
};

#[test]
fn admin_snapshot_export_absorb_roundtrip() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    let kit_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("reader.btn.mykit");
    producer.admin().add_recipient(
        "payments",
        Some("did:key:zPkgRecipient".to_string()),
        &kit_path,
    )?;
    producer.info("payment.created", json!({ "order_id": "PKG-100" }))?;

    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("admin-snapshot.tnpkg");
    let written = producer.pkg().export_admin_snapshot(&pkg_path)?;
    assert_eq!(written, pkg_path);
    assert!(pkg_path.exists());

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "admin_log_snapshot");
    assert_eq!(receipt.status(), AbsorbStatus::Accepted);
    assert!(receipt.accepted());
    assert!(receipt.accepted_count > 0 || receipt.noop);
    assert_ne!(receipt.legacy_status, "rejected");

    let state = consumer.pkg().absorb_path(&pkg_path)?;
    assert!(state.no_op());
    assert!(state.noop || state.deduped_count > 0);

    Ok(())
}

#[test]
fn kit_bundle_export_absorb_roundtrip() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;

    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("reader-kits.tnpkg");
    let written = producer.pkg().export_kit_bundle(
        &pkg_path,
        Some(vec!["default".to_string()]),
        Some("did:key:zPkgRecipient".to_string()),
    )?;
    assert_eq!(written, pkg_path);
    assert!(pkg_path.exists());

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.legacy_status, "enrolment_applied");
    assert!(receipt.accepted_count > 0);
    assert!(receipt
        .replaced_kit_paths
        .iter()
        .any(|path| path.ends_with("default.btn.mykit")));

    let duplicate = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(duplicate.kind, "kit_bundle");
    assert_eq!(duplicate.legacy_status, "no_op");
    assert_eq!(duplicate.status(), AbsorbStatus::NoOp);
    assert_eq!(duplicate.accepted_count, 0);
    assert!(duplicate.deduped_count > 0);
    assert!(duplicate.replaced_kit_paths.is_empty());

    Ok(())
}

#[test]
fn kit_bundle_export_after_ephemeral_group_reload() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;

    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("payments-reader-kits.tnpkg");
    let written = producer.pkg().export_kit_bundle(
        &pkg_path,
        Some(vec!["payments".to_string()]),
        Some("did:key:zPkgRecipient".to_string()),
    )?;

    assert_eq!(written, pkg_path);
    assert!(pkg_path.exists());

    Ok(())
}

#[test]
fn group_keys_export_is_self_addressed_narrow_full_keystore_scope() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;

    let pkg_path = tn
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("group-keys.tnpkg");
    let written = tn.pkg().export_group_keys(&pkg_path, None)?;

    assert_eq!(written, pkg_path);
    let info = tn.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.manifest.kind, ManifestKind::FullKeystore);
    assert_eq!(info.category(), tn_proto::PackageCategory::GroupKeys);
    assert!(info.is_group_key_snapshot());
    assert_eq!(info.manifest.scope, "group_keys");
    assert_eq!(info.manifest.publisher_identity, tn.did());
    assert_eq!(info.manifest.recipient_identity.as_deref(), Some(tn.did()));
    assert_eq!(
        info.manifest
            .state
            .as_ref()
            .and_then(|state| state.get("kind"))
            .and_then(serde_json::Value::as_str),
        Some("group-keys-v1")
    );
    assert!(info
        .manifest
        .state
        .as_ref()
        .and_then(|state| state.get("groups"))
        .and_then(|groups| groups.get("payments"))
        .is_some());
    assert!(info.has_body_entry("body/keys/payments.btn.state"));
    assert!(info.has_body_entry("body/keys/payments.btn.mykit"));
    assert!(!info.has_body_entry("body/local.private"));
    assert!(!info.has_body_entry("body/keys/local.private"));
    assert!(!info.has_body_entry("body/index_master.key"));
    assert!(!info.has_body_entry("body/WARNING_CONTAINS_PRIVATE_KEYS"));

    Ok(())
}

#[test]
fn compile_enrolment_writes_recipient_kit_bundle() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");
    let out_path = dir.join("compiled-enrolment.tnpkg");

    let result = producer.pkg().compile_enrolment(CompileEnrolmentOptions {
        group: "default".to_string(),
        recipient_did: "did:key:zCompileRecipient".to_string(),
        out_path: out_path.clone(),
        seal_for_recipient: false,
    })?;

    assert_eq!(result.path, out_path);
    assert_eq!(result.recipient_did, "did:key:zCompileRecipient");
    assert_eq!(result.groups, vec!["default".to_string()]);
    assert_eq!(result.manifest_sha256.len(), 64);
    assert_eq!(result.package_sha256.len(), 64);

    let info = producer.pkg().inspect_path(&result.path)?;
    assert_eq!(info.kind(), ManifestKind::KitBundle);
    assert_eq!(
        info.manifest.recipient_identity.as_deref(),
        Some("did:key:zCompileRecipient")
    );
    assert!(info.contains_reader_keys());

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&result.path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.status(), AbsorbStatus::Accepted);

    Ok(())
}

#[test]
fn offer_compiles_bundle_and_attests_offer_event() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");
    let out_path = dir.join("offer.tnpkg");

    let receipt = producer.pkg().offer(OfferOptions {
        group: "default".to_string(),
        peer_did: "did:key:zOfferPeer".to_string(),
        out_path: out_path.clone(),
        seal_for_recipient: false,
    })?;

    assert_eq!(receipt.path, out_path);
    assert_eq!(receipt.status, "offered");
    assert_eq!(receipt.group, "default");
    assert_eq!(receipt.peer_did, "did:key:zOfferPeer");
    assert_eq!(receipt.package_sha256.len(), 64);

    let info = producer.pkg().inspect_path(&receipt.path)?;
    assert_eq!(info.kind(), ManifestKind::KitBundle);
    assert_eq!(
        info.manifest.recipient_identity.as_deref(),
        Some("did:key:zOfferPeer")
    );

    let entries = producer.read(ReadOptions::default())?;
    let event = entries
        .iter()
        .find(|entry| entry.event_type() == Some("tn.offer.compiled"))
        .expect("offer helper should emit tn.offer.compiled");
    assert_eq!(
        event
            .get("peer_identity")
            .and_then(serde_json::Value::as_str),
        Some("did:key:zOfferPeer")
    );
    assert_eq!(
        event
            .get("package_sha256")
            .and_then(serde_json::Value::as_str),
        Some(format!("sha256:{}", receipt.package_sha256).as_str())
    );

    Ok(())
}

#[test]
fn package_info_classifies_advanced_package_kinds() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");

    let offer_path = dir.join("offer.tnpkg");
    producer.pkg().export_with(
        &offer_path,
        PkgExportOptions {
            kind: ManifestKind::Offer,
            to_did: Some("did:key:zOfferRecipient".to_string()),
            package_body: Some(br#"{"kind":"offer","id":"offer-1"}"#.to_vec()),
            ..PkgExportOptions::default()
        },
    )?;
    let offer = producer.pkg().inspect_path(&offer_path)?;
    assert_eq!(offer.category(), tn_proto::PackageCategory::Offer);
    assert!(offer.is_offer());
    assert!(offer.has_package_json());
    assert!(offer.is_addressed_to("did:key:zOfferRecipient"));
    let offer_payload = producer.pkg().package_json_path(&offer_path)?;
    assert_eq!(offer_payload.category(), tn_proto::PackageCategory::Offer);
    assert!(offer_payload.verified());
    assert_eq!(offer_payload.value["id"], "offer-1");
    assert_eq!(
        offer_payload.recipient_did(),
        Some("did:key:zOfferRecipient")
    );
    let offer_bytes_payload = producer
        .pkg()
        .package_json_bytes(&std::fs::read(&offer_path)?)?;
    assert_eq!(offer_bytes_payload.value["kind"], "offer");

    let enrolment_path = dir.join("enrolment.tnpkg");
    producer.pkg().export_with(
        &enrolment_path,
        PkgExportOptions {
            kind: ManifestKind::Enrolment,
            to_did: Some(producer.did().to_string()),
            package_body: Some(br#"{"kind":"enrolment","id":"enrol-1"}"#.to_vec()),
            ..PkgExportOptions::default()
        },
    )?;
    let enrolment = producer.pkg().inspect_path(&enrolment_path)?;
    assert_eq!(enrolment.category(), tn_proto::PackageCategory::Enrolment);
    assert!(enrolment.is_enrolment());
    assert!(enrolment.has_package_json());
    let enrolment_payload = producer.pkg().package_json_path(&enrolment_path)?;
    assert_eq!(
        enrolment_payload.category(),
        tn_proto::PackageCategory::Enrolment
    );
    assert_eq!(enrolment_payload.publisher_did(), producer.did());
    assert_eq!(enrolment_payload.value["id"], "enrol-1");

    let invite_path = dir.join("recipient-invite.tnpkg");
    write_reserved_package(
        &invite_path,
        ManifestKind::RecipientInvite,
        producer.did(),
        Some("did:key:zInviteRecipient"),
        br#"{"kind":"recipient_invite","id":"invite-1"}"#,
    )?;
    let invite = producer.pkg().inspect_path(&invite_path)?;
    assert_eq!(
        invite.category(),
        tn_proto::PackageCategory::RecipientInvite
    );
    assert!(invite.is_recipient_invite());
    assert!(invite.has_package_json());
    let invite_payload = producer.pkg().package_json_path(&invite_path)?;
    assert_eq!(
        invite_payload.category(),
        tn_proto::PackageCategory::RecipientInvite
    );
    assert!(!invite_payload.verified());
    assert_eq!(invite_payload.value["id"], "invite-1");

    let contact_path = dir.join("contact-update.tnpkg");
    write_contact_update_package(
        &contact_path,
        producer.did(),
        Some("did:key:zContactRecipient"),
        &valid_contact_update_body(json!({})),
    )?;
    let contact = producer.pkg().inspect_path(&contact_path)?;
    assert_eq!(contact.category(), tn_proto::PackageCategory::ContactUpdate);
    assert!(contact.is_contact_update());
    assert!(!contact.has_package_json());
    assert!(contact.has_body_entry("body/contact_update.json"));

    Ok(())
}

#[test]
fn contact_update_package_parser_validates_python_typescript_schema() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");

    let valid_path = dir.join("valid-contact-update.tnpkg");
    write_contact_update_package(
        &valid_path,
        producer.did(),
        Some("did:key:zContactRecipient"),
        &valid_contact_update_body(json!({
            "extra_future_field": "ignored",
        })),
    )?;

    let parsed = producer.pkg().contact_update_path(&valid_path)?;
    assert_eq!(
        parsed.info.category(),
        tn_proto::PackageCategory::ContactUpdate
    );
    assert!(!parsed.verified());
    assert_eq!(parsed.publisher_did(), producer.did());
    assert_eq!(parsed.recipient_did(), Some("did:key:zContactRecipient"));
    assert_eq!(parsed.body.account_id, "01J9X000000000000000000ABC");
    assert_eq!(parsed.body.label, "primary");
    assert_eq!(
        parsed.body.package_did.as_deref(),
        Some("did:key:z6MkPackage1")
    );
    assert_eq!(parsed.body.x25519_pub_b64, None);
    assert_eq!(parsed.body.source_link_id, None);
    assert!(parsed.body.to_json().get("extra_future_field").is_none());

    let parsed_from_bytes = producer
        .pkg()
        .contact_update_bytes(&std::fs::read(&valid_path)?)?;
    assert_eq!(parsed_from_bytes.body, parsed.body);

    let null_optional =
        tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
            "package_did": null,
            "x25519_pub_b64": null,
            "source_link_id": null,
        })))?;
    assert_eq!(null_optional.package_did, None);
    assert_eq!(null_optional.x25519_pub_b64, None);
    assert_eq!(null_optional.source_link_id, None);

    Ok(())
}

#[test]
fn contact_update_package_parser_reports_schema_errors() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");

    let missing_path = dir.join("contact-update-missing-field.tnpkg");
    let mut missing = valid_contact_update_body(json!({}));
    missing.as_object_mut().unwrap().remove("package_did");
    write_contact_update_package(
        &missing_path,
        producer.did(),
        Some("did:key:zContactRecipient"),
        &missing,
    )?;
    let err = producer
        .pkg()
        .contact_update_path(&missing_path)
        .unwrap_err();
    assert!(err.to_string().contains("missing required key"));
    assert!(err.to_string().contains("package_did"));

    let null_required = tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
        "account_id": null,
    })))
    .unwrap_err();
    assert!(null_required.to_string().contains("must not be null"));

    let wrong_optional =
        tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
            "source_link_id": 42,
        })))
        .unwrap_err();
    assert!(wrong_optional
        .to_string()
        .contains("must be a string or null"));

    let not_object = tn_proto::ContactUpdateBody::from_json(&json!(["not", "object"])).unwrap_err();
    assert!(not_object.to_string().contains("must be a JSON object"));

    let malformed_path = dir.join("contact-update-malformed.tnpkg");
    write_contact_update_package_raw(
        &malformed_path,
        producer.did(),
        Some("did:key:zContactRecipient"),
        b"not json",
    )?;
    let err = producer
        .pkg()
        .contact_update_path(&malformed_path)
        .unwrap_err();
    assert!(err.to_string().contains("not valid JSON"));

    let admin_path = dir.join("not-contact-update.tnpkg");
    producer.pkg().export_admin_snapshot(&admin_path)?;
    let err = producer.pkg().contact_update_path(&admin_path).unwrap_err();
    assert!(err.to_string().contains("expected contact_update"));

    Ok(())
}

#[test]
fn contact_update_body_application_matches_python_typescript_idempotency() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let first = tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({})))?;

    let applied = tn.pkg().apply_contact_update_body(&first)?;
    assert!(!applied.replaced);
    assert_eq!(applied.contacts_len, 1);
    assert_eq!(applied.contacts_path, tn.pkg().contacts_path());
    let contacts = read_contacts_yaml(&applied.contacts_path)?;
    assert_eq!(contacts["contacts"][0]["account_id"], first.account_id);
    assert_eq!(
        contacts["contacts"][0]["package_did"].as_str(),
        first.package_did.as_deref()
    );

    let replacement = tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
        "label": "new label",
    })))?;
    let replaced = tn.pkg().apply_contact_update_body(&replacement)?;
    assert!(replaced.replaced);
    assert_eq!(replaced.contacts_len, 1);
    let contacts = read_contacts_yaml(&replaced.contacts_path)?;
    assert_eq!(contacts["contacts"][0]["label"], "new label");

    let second_package =
        tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
            "package_did": "did:key:z6MkPackage2",
            "label": "second package",
        })))?;
    let appended = tn.pkg().apply_contact_update_body(&second_package)?;
    assert!(!appended.replaced);
    assert_eq!(appended.contacts_len, 2);

    let oauth_only = tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
        "package_did": null,
        "label": "oauth one",
    })))?;
    let first_oauth = tn.pkg().apply_contact_update_body(&oauth_only)?;
    assert!(!first_oauth.replaced);
    assert_eq!(first_oauth.contacts_len, 3);
    let oauth_replacement =
        tn_proto::ContactUpdateBody::from_json(&valid_contact_update_body(json!({
            "package_did": null,
            "label": "oauth two",
        })))?;
    let second_oauth = tn.pkg().apply_contact_update_body(&oauth_replacement)?;
    assert!(second_oauth.replaced);
    assert_eq!(second_oauth.contacts_len, 3);

    Ok(())
}

#[test]
fn contact_update_absorb_applies_signed_package_and_rejects_bad_packages() -> tn_proto::Result<()> {
    let consumer = Tn::ephemeral()?;
    let dir = consumer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");
    let signer = tn_core::DeviceKey::generate();

    let signed_path = dir.join("signed-contact-update.tnpkg");
    write_signed_contact_update_package(
        &signed_path,
        &signer,
        Some(consumer.did()),
        &valid_contact_update_body(json!({
            "label": "signed contact",
        })),
    )?;

    let receipt = consumer.pkg().absorb_path(&signed_path)?;
    assert_eq!(receipt.kind, "contact_update");
    assert_eq!(receipt.status(), AbsorbStatus::Accepted);
    assert_eq!(receipt.legacy_status, "enrolment_applied");
    let contacts = read_contacts_yaml(&consumer.pkg().contacts_path())?;
    assert_eq!(contacts["contacts"][0]["label"], "signed contact");

    let duplicate = consumer.pkg().absorb_bytes(&std::fs::read(&signed_path)?)?;
    assert_eq!(duplicate.status(), AbsorbStatus::Accepted);
    let contacts = read_contacts_yaml(&consumer.pkg().contacts_path())?;
    assert_eq!(contacts["contacts"].as_sequence().unwrap().len(), 1);

    let bad_body_path = dir.join("bad-contact-update.tnpkg");
    write_signed_contact_update_package(
        &bad_body_path,
        &signer,
        Some(consumer.did()),
        &valid_contact_update_body(json!({
            "account_id": null,
        })),
    )?;
    let rejected = consumer.pkg().absorb_path(&bad_body_path)?;
    assert_eq!(rejected.status(), AbsorbStatus::Rejected);
    assert!(rejected
        .legacy_reason
        .contains("contact_update body invalid"));

    let invalid_signature_path = dir.join("invalid-signature-contact-update.tnpkg");
    write_contact_update_package(
        &invalid_signature_path,
        signer.did(),
        Some(consumer.did()),
        &valid_contact_update_body(json!({
            "label": "invalid signature",
        })),
    )?;
    let rejected = consumer.pkg().absorb_path(&invalid_signature_path)?;
    assert_eq!(rejected.status(), AbsorbStatus::Rejected);
    assert!(rejected.legacy_reason.contains("signature"));

    Ok(())
}

#[test]
fn package_json_helpers_report_missing_or_malformed_payloads() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");

    let admin_path = dir.join("no-package-json.tnpkg");
    producer.pkg().export_admin_snapshot(&admin_path)?;
    let err = producer.pkg().package_json_path(&admin_path).unwrap_err();
    assert!(err.to_string().contains("body/package.json"));

    let malformed_path = dir.join("malformed-package-json.tnpkg");
    producer.pkg().export_with(
        &malformed_path,
        PkgExportOptions {
            kind: ManifestKind::Offer,
            package_body: Some(b"not json".to_vec()),
            ..PkgExportOptions::default()
        },
    )?;
    let err = producer
        .pkg()
        .package_json_path(&malformed_path)
        .unwrap_err();
    assert!(err.to_string().contains("expected"));

    Ok(())
}

#[test]
fn group_keys_export_honors_group_filter_and_errors_when_empty() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    tn.admin().ensure_group("audits", ["audit_id"])?;
    let dir = tn
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");

    let payments_path = dir.join("payments-group-keys.tnpkg");
    tn.pkg()
        .export_group_keys(&payments_path, Some(vec!["payments".to_string()]))?;
    let info = tn.pkg().inspect_path(&payments_path)?;
    assert!(info.has_body_entry("body/keys/payments.btn.state"));
    assert!(info.has_body_entry("body/keys/payments.btn.mykit"));
    assert!(!info.has_body_entry("body/keys/audits.btn.state"));
    assert!(!info.has_body_entry("body/keys/audits.btn.mykit"));

    let err = tn
        .pkg()
        .export_group_keys(
            dir.join("missing-group-keys.tnpkg"),
            Some(vec!["missing".to_string()]),
        )
        .unwrap_err();
    assert!(err.to_string().contains("group_keys: no btn groups"));

    Ok(())
}

fn write_reserved_package(
    path: &std::path::Path,
    kind: ManifestKind,
    publisher_did: &str,
    recipient_did: Option<&str>,
    package_json: &[u8],
) -> tn_proto::Result<()> {
    let manifest = tn_core::Manifest {
        kind,
        version: 1,
        publisher_identity: publisher_did.to_string(),
        recipient_identity: recipient_did.map(ToOwned::to_owned),
        ceremony_id: "reserved-package-test".to_string(),
        as_of: "2026-06-26T00:00:00Z".to_string(),
        scope: "admin".to_string(),
        clock: BTreeMap::new(),
        event_count: 1,
        head_row_hash: None,
        state: None,
        manifest_signature_b64: Some("not-a-valid-signature".to_string()),
    };
    let mut body = tn_core::tnpkg::BodyContents::new();
    body.insert("body/package.json".to_string(), package_json.to_vec());
    write_tnpkg(path, &manifest, &body)?;
    Ok(())
}

fn write_contact_update_package(
    path: &std::path::Path,
    publisher_did: &str,
    recipient_did: Option<&str>,
    body: &serde_json::Value,
) -> tn_proto::Result<()> {
    let body_bytes = serde_json::to_vec(body)?;
    write_contact_update_package_raw(path, publisher_did, recipient_did, &body_bytes)
}

fn write_contact_update_package_raw(
    path: &std::path::Path,
    publisher_did: &str,
    recipient_did: Option<&str>,
    body: &[u8],
) -> tn_proto::Result<()> {
    let manifest = tn_core::Manifest {
        kind: ManifestKind::ContactUpdate,
        version: 1,
        publisher_identity: publisher_did.to_string(),
        recipient_identity: recipient_did.map(ToOwned::to_owned),
        ceremony_id: "vault-publisher".to_string(),
        as_of: "2026-06-26T00:00:00Z".to_string(),
        scope: "default".to_string(),
        clock: BTreeMap::new(),
        event_count: 1,
        head_row_hash: None,
        state: None,
        manifest_signature_b64: Some("not-a-valid-signature".to_string()),
    };
    let mut contents = tn_core::tnpkg::BodyContents::new();
    contents.insert("body/contact_update.json".to_string(), body.to_vec());
    write_tnpkg(path, &manifest, &contents)?;
    Ok(())
}

fn write_signed_contact_update_package(
    path: &std::path::Path,
    signer: &tn_core::DeviceKey,
    recipient_did: Option<&str>,
    body: &serde_json::Value,
) -> tn_proto::Result<()> {
    let mut manifest = tn_core::Manifest {
        kind: ManifestKind::ContactUpdate,
        version: 1,
        publisher_identity: signer.did().to_string(),
        recipient_identity: recipient_did.map(ToOwned::to_owned),
        ceremony_id: "vault-publisher".to_string(),
        as_of: "2026-06-26T00:00:00Z".to_string(),
        scope: "default".to_string(),
        clock: BTreeMap::new(),
        event_count: 1,
        head_row_hash: None,
        state: None,
        manifest_signature_b64: None,
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signer.private_bytes());
    sign_manifest(&mut manifest, &signing_key)?;
    let mut contents = tn_core::tnpkg::BodyContents::new();
    contents.insert(
        "body/contact_update.json".to_string(),
        serde_json::to_vec(body)?,
    );
    write_tnpkg(path, &manifest, &contents)?;
    Ok(())
}

fn valid_contact_update_body(overrides: serde_json::Value) -> serde_json::Value {
    let mut body = json!({
        "account_id": "01J9X000000000000000000ABC",
        "label": "primary",
        "package_did": "did:key:z6MkPackage1",
        "x25519_pub_b64": null,
        "claimed_at": "2026-04-29T12:00:00+00:00",
        "source_link_id": null,
    });
    let body_object = body.as_object_mut().unwrap();
    if let Some(overrides) = overrides.as_object() {
        for (key, value) in overrides {
            body_object.insert(key.clone(), value.clone());
        }
    }
    body
}

fn read_contacts_yaml(path: &std::path::Path) -> tn_proto::Result<serde_yml::Value> {
    Ok(serde_yml::from_str(&std::fs::read_to_string(path)?)?)
}

#[test]
fn inspect_package_reports_manifest_and_signature_status() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("inspect-admin-snapshot.tnpkg");
    producer.pkg().export_admin_snapshot(&pkg_path)?;

    let info = producer.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), ManifestKind::AdminLogSnapshot);
    assert_eq!(info.publisher_did(), producer.did());
    assert_eq!(info.recipient_did(), None);
    assert_eq!(info.ceremony_id(), info.manifest.ceremony_id);
    assert!(info.is_published_by(producer.did()));
    assert!(!info.is_addressed_to(producer.did()));
    assert_eq!(info.signature, PackageSignatureStatus::Verified);
    assert!(info.signature.verified());
    assert!(info.verified());
    assert!(!info.contains_secret_material());
    assert!(!info.contains_reader_keys());
    assert_eq!(info.body_entry_count, 1);
    assert_eq!(info.body_entry_names, vec!["body/admin.ndjson".to_string()]);
    assert!(info.has_body_entry("body/admin.ndjson"));
    assert!(!info.has_body_entry("body/default.btn.mykit"));

    let bytes = std::fs::read(&pkg_path)?;
    let from_bytes = producer.pkg().inspect_bytes(&bytes)?;
    assert_eq!(from_bytes.manifest.kind, ManifestKind::AdminLogSnapshot);
    assert_eq!(from_bytes.signature, PackageSignatureStatus::Verified);

    Ok(())
}

#[test]
fn inspect_package_classifies_reader_and_secret_material() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");

    let reader_bundle = root.join("inspect-reader-kits.tnpkg");
    producer.pkg().bundle_for_recipient(
        "did:key:zPkgRecipient",
        &reader_bundle,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: false,
        },
    )?;
    let reader_info = producer.pkg().inspect_path(&reader_bundle)?;
    assert_eq!(reader_info.kind(), ManifestKind::KitBundle);
    assert_eq!(reader_info.recipient_did(), Some("did:key:zPkgRecipient"));
    assert!(reader_info.is_published_by(producer.did()));
    assert!(reader_info.is_addressed_to("did:key:zPkgRecipient"));
    assert!(!reader_info.is_addressed_to(producer.did()));
    assert!(reader_info.verified());
    assert!(reader_info.has_body_entry("body/default.btn.mykit"));
    assert!(reader_info.contains_reader_keys());
    assert!(!reader_info.contains_secret_material());

    let seed_bundle = root.join("inspect-project-seed.tnpkg");
    producer
        .pkg()
        .export_project_seed(&seed_bundle, None, SecretExportConsent::acknowledge())?;
    let seed_info = producer.pkg().inspect_path(&seed_bundle)?;
    assert_eq!(seed_info.kind(), ManifestKind::ProjectSeed);
    assert!(seed_info.verified());
    assert!(seed_info.contains_reader_keys());
    assert!(seed_info.contains_secret_material());

    Ok(())
}

#[test]
fn inspect_package_surfaces_invalid_signature_without_absorbing() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("inspect-tamper-source.tnpkg");
    producer.pkg().export_admin_snapshot(&pkg_path)?;

    let (mut manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    manifest.event_count += 1;
    let tampered_path = pkg_path.with_file_name("inspect-tampered.tnpkg");
    write_tnpkg(&tampered_path, &manifest, &body)?;

    let info = producer.pkg().inspect_path(&tampered_path)?;
    assert_eq!(info.manifest.event_count, manifest.event_count);
    assert!(matches!(info.signature, PackageSignatureStatus::Invalid(_)));

    Ok(())
}

#[test]
fn bundle_for_recipient_packages_fresh_recipient_kit() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let self_kit = std::fs::read(root.join(".tn").join("keys").join("default.btn.mykit"))?;
    let pkg_path = root.join("recipient-default.tnpkg");

    let result = producer.pkg().bundle_for_recipient(
        "did:key:zPkgRecipient",
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: false,
        },
    )?;

    assert_eq!(result.path, pkg_path);
    assert_eq!(result.recipient_did, "did:key:zPkgRecipient");
    assert_eq!(result.groups, vec!["default".to_string()]);

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    verify_manifest(&manifest)?;
    assert_eq!(manifest.kind, ManifestKind::KitBundle);
    assert_eq!(
        manifest.recipient_identity.as_deref(),
        Some("did:key:zPkgRecipient")
    );
    let bundled = body
        .get("body/default.btn.mykit")
        .expect("default recipient kit should be packaged");
    assert_ne!(
        bundled, &self_kit,
        "recipient bundles must not ship the publisher self-kit"
    );

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.legacy_status, "enrolment_applied");
    assert_eq!(receipt.status(), AbsorbStatus::Accepted);
    assert_eq!(receipt.accepted_count, 1);

    Ok(())
}

#[test]
fn bundle_for_recipient_can_seal_body_for_real_recipient_did() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let recipient = tn_core::DeviceKey::generate();
    let root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let pkg_path = root.join("recipient-default-sealed.tnpkg");

    let result = producer.pkg().bundle_for_recipient(
        recipient.did(),
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: true,
        },
    )?;

    assert_eq!(result.path, pkg_path);
    assert_eq!(result.recipient_did, recipient.did());
    assert_eq!(result.groups, vec!["default".to_string()]);

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    verify_manifest(&manifest)?;
    assert_eq!(manifest.kind, ManifestKind::KitBundle);
    assert_eq!(
        manifest.recipient_identity.as_deref(),
        Some(recipient.did())
    );
    assert!(body.contains_key("body/encrypted.bin"));
    assert!(!body.contains_key("body/default.btn.mykit"));

    let body_encryption = manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .and_then(serde_json::Value::as_object)
        .expect("sealed bundle should carry body_encryption metadata");
    let wraps = body_encryption
        .get("recipient_wraps")
        .and_then(serde_json::Value::as_array)
        .expect("sealed bundle should carry recipient_wraps");
    assert_eq!(wraps.len(), 1);
    assert_eq!(
        wraps[0].get("frame").and_then(serde_json::Value::as_str),
        Some("tn-sealed-box-v1")
    );
    assert_eq!(
        wraps[0]
            .get("recipient_identity")
            .and_then(serde_json::Value::as_str),
        Some(recipient.did())
    );
    assert_eq!(body_encryption.get("recipient_wrap"), Some(&wraps[0]));

    let info = producer.pkg().inspect_path(&pkg_path)?;
    assert_eq!(info.kind(), ManifestKind::KitBundle);
    assert!(info.verified());
    assert!(info.has_body_entry("body/encrypted.bin"));
    assert!(!info.has_body_entry("body/default.btn.mykit"));

    Ok(())
}

#[test]
fn recipient_can_absorb_sealed_bundle_addressed_to_own_did() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let recipient_seed = [9_u8; 32];
    let recipient_device = tn_core::DeviceKey::from_private_bytes(&recipient_seed)?;
    let recipient_root = tempfile::tempdir()?;
    let recipient = Tn::init_project_with_options(
        "sealed-recipient",
        TnProjectOptions {
            project_dir: Some(recipient_root.path().to_path_buf()),
            device_private_bytes: Some(recipient_seed.to_vec()),
            ..TnProjectOptions::default()
        },
    )?;
    assert_eq!(recipient.did(), recipient_device.did());

    let producer_root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let pkg_path = producer_root.join("recipient-absorb-sealed.tnpkg");
    producer.pkg().bundle_for_recipient(
        recipient.did(),
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: true,
        },
    )?;

    let receipt = recipient.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.status(), AbsorbStatus::Accepted);
    assert_eq!(receipt.legacy_status, "enrolment_applied");
    assert_eq!(receipt.accepted_count, 1);
    assert!(recipient
        .config()
        .yaml_path
        .parent()
        .expect("project yaml should have parent")
        .join("keys")
        .join("default.btn.mykit")
        .is_file());

    Ok(())
}

#[test]
fn recipient_rejects_sealed_bundle_addressed_to_another_did() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let intended = tn_core::DeviceKey::from_private_bytes(&[10_u8; 32])?;
    let other_root = tempfile::tempdir()?;
    let other = Tn::init_project_with_options(
        "sealed-other",
        TnProjectOptions {
            project_dir: Some(other_root.path().to_path_buf()),
            device_private_bytes: Some(vec![11_u8; 32]),
            ..TnProjectOptions::default()
        },
    )?;

    let producer_root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let pkg_path = producer_root.join("recipient-reject-sealed.tnpkg");
    producer.pkg().bundle_for_recipient(
        intended.did(),
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string()]),
            seal_for_recipient: true,
        },
    )?;

    let receipt = other.pkg().absorb_path(&pkg_path)?;
    assert_eq!(receipt.kind, "kit_bundle");
    assert_eq!(receipt.status(), AbsorbStatus::Rejected);
    assert!(receipt.legacy_reason.contains("sealed-box wrap"));

    Ok(())
}

#[test]
fn bundle_for_recipient_sealing_rejects_keyless_did_before_writing_package() -> tn_proto::Result<()>
{
    let producer = Tn::ephemeral()?;
    let root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let pkg_path = root.join("recipient-keyless-sealed.tnpkg");

    let err = producer
        .pkg()
        .bundle_for_recipient(
            "did:key:zPkgRecipient",
            &pkg_path,
            BundleForRecipientOptions {
                groups: Some(vec!["default".to_string()]),
                seal_for_recipient: true,
            },
        )
        .unwrap_err();

    assert!(err.to_string().contains("recipient sealing"));
    assert!(!pkg_path.exists());

    Ok(())
}

#[test]
fn bundle_for_recipient_defaults_to_non_internal_groups() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let pkg_path = root.join("recipient-default-groups.tnpkg");

    let result = producer.pkg().bundle_for_recipient(
        "did:key:zPkgRecipient",
        &pkg_path,
        BundleForRecipientOptions::default(),
    )?;

    assert_eq!(result.groups, vec!["default".to_string()]);

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    verify_manifest(&manifest)?;
    assert_eq!(manifest.kind, ManifestKind::KitBundle);
    assert!(body.contains_key("body/default.btn.mykit"));
    assert!(!body.contains_key("body/tn.agents.btn.mykit"));

    Ok(())
}

#[test]
fn bundle_for_recipient_result_reports_deduped_groups() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("deduped-groups.tnpkg");

    let result = producer.pkg().bundle_for_recipient(
        "did:key:zPkgRecipient",
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["default".to_string(), "default".to_string()]),
            seal_for_recipient: false,
        },
    )?;

    assert_eq!(result.groups, vec!["default".to_string()]);

    Ok(())
}

#[test]
fn bundle_for_recipient_rejects_unknown_group() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("unknown-group.tnpkg");

    let err = producer.pkg().bundle_for_recipient(
        "did:key:zPkgRecipient",
        &pkg_path,
        BundleForRecipientOptions {
            groups: Some(vec!["missing".to_string()]),
            seal_for_recipient: false,
        },
    );

    assert!(err.is_err());
    assert!(!pkg_path.exists());

    Ok(())
}

#[test]
fn full_keystore_export_requires_low_level_confirmation() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("full-keystore.tnpkg");

    let err = producer.pkg().export_with(
        &pkg_path,
        PkgExportOptions {
            kind: ManifestKind::FullKeystore,
            confirm_includes_secrets: false,
            ..PkgExportOptions::default()
        },
    );
    assert!(err.is_err());

    let written =
        producer
            .pkg()
            .export_full_keystore(&pkg_path, None, SecretExportConsent::acknowledge())?;
    assert_eq!(written, pkg_path);

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    verify_manifest(&manifest)?;
    assert_eq!(manifest.kind, ManifestKind::FullKeystore);
    assert!(body.contains_key("body/WARNING_CONTAINS_PRIVATE_KEYS"));
    assert!(body.contains_key("body/local.private"));

    Ok(())
}

#[test]
fn project_seed_export_includes_config_and_key_material() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;

    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("project-seed.tnpkg");
    let written = producer.pkg().export_project_seed(
        &pkg_path,
        Some(vec!["payments".to_string()]),
        SecretExportConsent::acknowledge(),
    )?;
    assert_eq!(written, pkg_path);

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    verify_manifest(&manifest)?;
    assert_eq!(manifest.kind, ManifestKind::ProjectSeed);
    assert_eq!(manifest.publisher_identity, producer.did());
    assert_eq!(manifest.recipient_identity.as_deref(), Some(producer.did()));
    assert!(body.contains_key("body/tn.yaml"));
    assert!(body.contains_key("body/keys/local.private"));
    assert!(body.contains_key("body/keys/payments.btn.mykit"));
    assert!(body.contains_key("body/WARNING_CONTAINS_PRIVATE_KEYS"));

    Ok(())
}

#[test]
fn identity_seed_export_is_self_addressed() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("identity-seed.tnpkg");

    producer
        .pkg()
        .export_identity_seed(&pkg_path, SecretExportConsent::acknowledge())?;

    let (manifest, body) = read_tnpkg(TnpkgSource::Path(&pkg_path))?;
    verify_manifest(&manifest)?;
    assert_eq!(manifest.kind, ManifestKind::IdentitySeed);
    assert_eq!(manifest.publisher_identity, producer.did());
    assert_eq!(manifest.recipient_identity.as_deref(), Some(producer.did()));
    assert!(body.contains_key("body/local.private"));
    assert!(body.contains_key("body/local.public"));
    assert!(body.contains_key("body/tn.yaml"));

    Ok(())
}

#[test]
fn malformed_package_bytes_return_rejected_receipt() -> tn_proto::Result<()> {
    let consumer = Tn::ephemeral()?;

    let receipt = consumer.pkg().absorb_bytes(b"not a tnpkg archive")?;

    assert_eq!(receipt.kind, "unknown");
    assert_eq!(receipt.legacy_status, "rejected");
    assert!(receipt.rejected());
    assert_eq!(receipt.accepted_count, 0);
    assert_eq!(receipt.deduped_count, 0);
    assert!(receipt.legacy_reason.contains("not a valid `.tnpkg` zip"));

    Ok(())
}

#[test]
fn bootstrap_seed_absorb_is_stashed_on_active_runtime() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let pkg_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("identity-seed-for-active-runtime.tnpkg");
    producer
        .pkg()
        .export_identity_seed(&pkg_path, SecretExportConsent::acknowledge())?;

    let consumer = Tn::ephemeral()?;
    let receipt = consumer.pkg().absorb_path(&pkg_path)?;

    assert_eq!(receipt.kind, "identity_seed");
    assert_eq!(receipt.legacy_status, "stashed");
    assert!(receipt.stashed());
    assert_eq!(receipt.accepted_count, 0);
    assert!(receipt.legacy_reason.contains("no bootstrap handler yet"));

    Ok(())
}
