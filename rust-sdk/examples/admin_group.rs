// Demonstrates the admin namespace by creating a routed group, emitting an
// event that uses the group's fields, and reading the decrypted entry back.

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;

    let ensured = tn
        .admin()
        .ensure_group("payments", ["order_id", "amount"])?;
    println!("ensured group: {ensured:#?}");

    tn.info(
        "payment.created",
        json!({
            "order_id": "PAY-100",
            "amount": 2500,
            "note": "routed into the payments group",
        }),
    )?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    for entry in entries {
        if entry.get("event_type").and_then(Value::as_str) == Some("payment.created") {
            println!("{entry:#?}");
        }
    }

    Ok(())
}
