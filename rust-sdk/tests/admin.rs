mod common;

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

#[test]
fn ensure_group_routes_fields_for_existing_group() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;

    let result = tn.admin().ensure_group("default", ["order_id", "amount"])?;
    assert_eq!(result.group, "default");
    assert_eq!(result.fields, vec!["order_id", "amount"]);
    assert!(!result.created);
    assert!(result.changed);

    tn.info(
        "admin.routing",
        json!({
            "order_id": "A100",
            "amount": 4999,
            "note": "still private by default",
        }),
    )?;

    let entries = tn.read(ReadOptions::default())?;
    let entry = common::find_event(&entries, "admin.routing");
    assert_eq!(entry.get("order_id").and_then(Value::as_str), Some("A100"));
    assert_eq!(entry.get("amount").and_then(Value::as_i64), Some(4999));

    let raw_log = std::fs::read_to_string(tn.log_path())?;
    assert!(!raw_log.contains("A100"));

    Ok(())
}

#[test]
fn ensure_group_creates_new_btn_group_and_routes_fields() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    let result = tn
        .admin()
        .ensure_group("payments", ["order_id", "amount"])?;

    assert_eq!(result.group, "payments");
    assert!(result.created);
    assert!(result.changed);
    assert!(tn.group_names().iter().any(|name| name == "payments"));

    tn.info(
        "payment.created",
        json!({
            "order_id": "PAY-100",
            "amount": 2500,
            "description": "new group route",
        }),
    )?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    let added = common::find_event(&entries, "tn.group.added");
    assert_eq!(added.get("group").and_then(Value::as_str), Some("payments"));
    assert_eq!(added.get("cipher").and_then(Value::as_str), Some("btn"));

    let payment = common::find_event(&entries, "payment.created");
    assert_eq!(
        payment.get("order_id").and_then(Value::as_str),
        Some("PAY-100")
    );
    assert_eq!(payment.get("amount").and_then(Value::as_i64), Some(2500));

    let raw_log = std::fs::read_to_string(tn.log_path())?;
    assert!(!raw_log.contains("PAY-100"));

    Ok(())
}

#[test]
fn add_recipient_mints_kit_and_updates_admin_state() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;

    let kit_path = tn
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("alice.btn.mykit");
    let recipient_did = "did:key:zRustSdkRecipient";

    let result =
        tn.admin()
            .add_recipient("payments", Some(recipient_did.to_string()), &kit_path)?;

    assert_eq!(result.group, "payments");
    assert_eq!(result.recipient_did.as_deref(), Some(recipient_did));
    assert_eq!(result.leaf_index, 1);
    assert_eq!(result.kit_path, kit_path);
    assert!(kit_path.exists());

    let state = tn.admin().state(Some("payments"))?;
    let recipient = state
        .recipients
        .iter()
        .find(|row| row.leaf_index == result.leaf_index)
        .expect("admin state should include minted recipient");
    assert_eq!(recipient.group, "payments");
    assert_eq!(recipient.recipient_identity.as_deref(), Some(recipient_did));
    assert_eq!(recipient.active_status, "active");

    Ok(())
}

#[test]
fn revoke_recipient_updates_admin_state() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;

    let kit_path = tn
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("bob.btn.mykit");
    let add = tn.admin().add_recipient(
        "payments",
        Some("did:key:zRustSdkBob".to_string()),
        &kit_path,
    )?;

    let revoke = tn.admin().revoke_recipient("payments", add.leaf_index)?;
    assert_eq!(revoke.group, "payments");
    assert_eq!(revoke.leaf_index, add.leaf_index);

    let state = tn.admin().state(Some("payments"))?;
    let recipient = state
        .recipients
        .iter()
        .find(|row| row.leaf_index == add.leaf_index)
        .expect("admin state should include revoked recipient");
    assert_eq!(recipient.active_status, "revoked");
    assert!(recipient.revoked_at.is_some());

    Ok(())
}

#[test]
fn recipients_and_revoked_count_reflect_lifecycle() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.admin().ensure_group("payments", ["order_id"])?;

    let kit_path = tn
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("carol.btn.mykit");
    let add = tn.admin().add_recipient(
        "payments",
        Some("did:key:zRustSdkCarol".to_string()),
        &kit_path,
    )?;

    let active = tn.admin().recipients("payments", false)?;
    assert!(active.iter().any(|row| row.leaf_index == add.leaf_index));
    assert_eq!(tn.admin().revoked_count("payments")?, 0);

    tn.admin().revoke_recipient("payments", add.leaf_index)?;

    let active_after_revoke = tn.admin().recipients("payments", false)?;
    assert!(!active_after_revoke
        .iter()
        .any(|row| row.leaf_index == add.leaf_index));

    let all = tn.admin().recipients("payments", true)?;
    let revoked = all
        .iter()
        .find(|row| row.leaf_index == add.leaf_index)
        .expect("revoked recipient should be present when include_revoked=true");
    assert!(revoked.revoked);
    assert!(revoked.revoked_at.is_some());
    assert_eq!(tn.admin().revoked_count("payments")?, 1);

    Ok(())
}
