mod common;

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

#[test]
fn default_read_verifies_and_flags_valid_entries() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("verify.valid", json!({ "marker": "valid-row" }))?;

    // The automatic secure default performs full verification and attaches
    // the validity metadata; no explicit flag is required anymore.
    let entries = tn.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;
    let entry = common::find_event(&entries, "verify.valid");
    assert_eq!(common::valid_flags(entry), (true, true, true));

    let valid = entry
        .get("_valid")
        .and_then(Value::as_object)
        .expect("_valid block");
    assert_eq!(valid.get("writer_authenticated"), Some(&Value::Bool(true)));
    assert_eq!(valid.get("writer_authorized"), Some(&Value::Bool(true)));
    assert_eq!(valid.get("reasons"), Some(&json!([])));

    Ok(())
}

#[test]
fn default_read_raises_on_tampered_rows() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("verify.original", json!({ "marker": "tamper-row" }))?;

    let log_path = tn.log_path().to_path_buf();
    let raw_log = std::fs::read_to_string(&log_path)?;
    assert!(raw_log.contains("verify.original"));
    std::fs::write(
        &log_path,
        raw_log.replace("verify.original", "verify.tampered"),
    )?;

    let error = tn
        .read(ReadOptions {
            all_runs: true,
            ..ReadOptions::default()
        })
        .expect_err("auto verification must reject the tampered row");
    assert!(error.to_string().contains("row_hash_invalid"), "{error}");

    Ok(())
}

#[test]
fn disabled_read_returns_tampered_rows_with_accurate_flags() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("verify.original", json!({ "marker": "tamper-row" }))?;

    let log_path = tn.log_path().to_path_buf();
    let raw_log = std::fs::read_to_string(&log_path)?;
    std::fs::write(
        &log_path,
        raw_log.replace("verify.original", "verify.tampered"),
    )?;

    // Explicitly disabling verification is the fail-open escape hatch: the
    // tampered row comes back, but its flags still tell the truth.
    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
        ..ReadOptions::default()
    })?;
    let entry = common::find_event(&entries, "verify.tampered");
    let (signature, row_hash, _chain) = common::valid_flags(entry);
    // TN signs the row-hash value. Rewriting an envelope field leaves that
    // signature cryptographically valid over the now-stale hash, while the
    // independent row-hash recomputation correctly catches the tamper.
    assert!(
        signature,
        "signature over the stored row hash remains valid: {entry:#?}"
    );
    assert!(
        !row_hash,
        "tampered row_hash must not recompute: {entry:#?}"
    );
    assert_eq!(
        entry.get("marker").and_then(Value::as_str),
        Some("tamper-row")
    );

    Ok(())
}
