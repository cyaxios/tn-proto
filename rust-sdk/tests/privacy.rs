mod common;

use serde_json::json;
use tn_proto::{ReadOptions, Tn};

#[test]
fn private_fields_are_not_written_as_plaintext() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let secret = "secret-order-token-tn-proto-privacy";

    tn.info(
        "privacy.created",
        json!({
            "order_id": secret,
            "amount": 4999,
        }),
    )?;

    let raw_log = std::fs::read_to_string(tn.log_path())?;
    assert!(raw_log.contains("privacy.created"));
    assert!(raw_log.contains("ciphertext"));
    assert!(raw_log.contains("field_hashes"));
    assert!(
        !raw_log.contains(secret),
        "raw log leaked private field value: {raw_log}"
    );

    let entries = tn.read(ReadOptions::default())?;
    let entry = common::find_event(&entries, "privacy.created");
    assert_eq!(
        entry.get("order_id").and_then(serde_json::Value::as_str),
        Some(secret)
    );

    Ok(())
}
