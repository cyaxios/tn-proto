// Demonstrates the recipient lifecycle for a BTN group. It creates a routed
// group, mints a reader kit for a recipient, revokes that recipient by leaf
// index, then reads back the signed admin events.

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;

    tn.admin()
        .ensure_group("analytics", ["request_id", "path"])?;

    let kit_path = tn
        .log_path()
        .parent()
        .expect("ephemeral logs have a parent directory")
        .join("analyst.analytics.btn.mykit");

    let added = tn.admin().add_recipient(
        "analytics",
        Some("did:key:zFormerAnalyst".to_string()),
        &kit_path,
    )?;
    println!(
        "minted reader kit for {} at leaf {}",
        added.recipient_did.as_deref().unwrap_or("unknown"),
        added.leaf_index
    );
    println!("kit path: {}", added.kit_path.display());

    tn.info(
        "request.served",
        json!({
            "request_id": "r-1",
            "path": "/dashboard",
            "status": 200,
        }),
    )?;

    let revoked = tn.admin().revoke_recipient("analytics", added.leaf_index)?;
    println!(
        "revoked leaf {} from group {}",
        revoked.leaf_index, revoked.group
    );

    tn.info(
        "request.served",
        json!({
            "request_id": "r-2",
            "path": "/admin",
            "status": 200,
        }),
    )?;

    let active = tn.admin().recipients("analytics", false)?;
    let historical = tn.admin().recipients("analytics", true)?;
    println!("active recipients: {}", active.len());
    println!("historical recipients: {}", historical.len());
    println!(
        "revoked recipients in publisher state: {}",
        tn.admin().revoked_count("analytics")?
    );

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: true,
    })?;
    let admin_events = entries
        .iter()
        .filter_map(|entry| entry.get("event_type").and_then(Value::as_str))
        .filter(|event_type| event_type.starts_with("tn.recipient."))
        .collect::<Vec<_>>();
    println!("recipient admin events: {admin_events:?}");

    Ok(())
}
