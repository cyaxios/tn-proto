mod common;

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

#[test]
fn verify_read_marks_valid_entries() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("verify.valid", json!({ "marker": "valid-row" }))?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: true,
    })?;
    let entry = common::find_event(&entries, "verify.valid");
    assert_eq!(common::valid_flags(entry), (true, true, true));

    Ok(())
}

#[test]
fn verify_read_flags_tampered_rows() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("verify.original", json!({ "marker": "tamper-row" }))?;

    let log_path = tn.log_path().to_path_buf();
    let raw_log = std::fs::read_to_string(&log_path)?;
    assert!(raw_log.contains("verify.original"));
    std::fs::write(
        &log_path,
        raw_log.replace("verify.original", "verify.tampered"),
    )?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: true,
    })?;
    let entry = common::find_event(&entries, "verify.tampered");
    let (signature, row_hash, chain) = common::valid_flags(entry);

    assert!(
        !signature || !row_hash || !chain,
        "tampered entry unexpectedly verified: {entry:#?}"
    );
    assert_eq!(
        entry.get("marker").and_then(Value::as_str),
        Some("tamper-row")
    );

    Ok(())
}
