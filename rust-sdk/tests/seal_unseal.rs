//! Rust SDK smoke tests for `Tn::seal` / `Tn::unseal`.
//!
//! Thin, ergonomic-surface coverage only: `SealedObject` round-trips
//! through the wire string, `SealOptions`/`UnsealOptions` pass through to
//! `tn-core`, and a failed verify check surfaces as the SDK's first-class
//! `Error::Verify`. Full wire-parity, fragile-value, key-bag-walk, and
//! receipt-routing coverage already lives in
//! `crypto/tn-core/tests/seal_unseal.rs` — this file does not repeat it.

mod common;

use serde_json::{json, Value};
use tn_proto::{Error, ReadOptions, SealOptions, Tn, UnsealOptions};

#[test]
fn seal_unseal_roundtrip() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let sealed = tn.seal(
        "obj.invoice.v1",
        json!({ "amount": 9800, "customer": "acme" }),
        SealOptions {
            receipt: false,
            ..SealOptions::default()
        },
    )?;

    // Standalone envelope conventions on the returned object.
    assert_eq!(sealed.envelope["sequence"], json!(0));
    assert_eq!(sealed.envelope["prev_hash"], json!(""));
    assert_eq!(sealed.envelope["tn_sealed"], json!(1));
    assert!(!sealed.wire.ends_with('\n'), "wire must have no trailing newline");
    assert_eq!(sealed.to_string(), sealed.wire, "Display must print the wire line");

    let out = tn.unseal(&sealed.wire, UnsealOptions::default())?;
    assert!(out.valid.signature && out.valid.row_hash);
    assert!(out.hidden_groups.is_empty());
    assert!(out.sealed_blocks.is_empty());
    assert_eq!(out.fields["amount"], json!(9800));
    assert_eq!(out.fields["customer"], json!("acme"));
    assert!(
        !out.fields.contains_key("tn_sealed"),
        "the wire marker must not leak into unsealed fields"
    );

    tn.close()?;
    Ok(())
}

#[test]
fn unseal_verify_error_variant() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let sealed = tn.seal(
        "obj.test.v1",
        json!({ "x": 1 }),
        SealOptions {
            receipt: false,
            ..SealOptions::default()
        },
    )?;
    let mut env = sealed.envelope.clone();
    env.insert("tn_sealed".to_string(), json!(2));
    let tampered = serde_json::to_string(&Value::Object(env)).expect("re-serialize tampered envelope");

    let err = tn
        .unseal(&tampered, UnsealOptions::default())
        .expect_err("tampered public field must fail verification");
    match err {
        Error::Verify {
            failed_checks,
            sequence,
            event_type,
        } => {
            assert_eq!(failed_checks, vec!["row_hash".to_string()]);
            assert_eq!(sequence, 0);
            assert_eq!(event_type, "obj.test.v1");
        }
        other => panic!("expected Error::Verify, got {other:?}"),
    }

    tn.close()?;
    Ok(())
}

#[test]
fn unseal_no_key_public_frame() -> tn_proto::Result<()> {
    let publisher = Tn::ephemeral()?;
    let sealed = publisher.seal(
        "obj.memo.v1",
        json!({ "body": "private" }),
        SealOptions {
            receipt: false,
            ..SealOptions::default()
        },
    )?;

    // A second, unrelated ceremony (its own random btn material) holds no
    // fitting key: no error, the verified public frame comes back with
    // the block still sealed.
    let stranger = Tn::ephemeral()?;
    let out = stranger.unseal(&sealed.wire, UnsealOptions::default())?;
    assert!(out.valid.signature && out.valid.row_hash);
    assert_eq!(out.hidden_groups, vec!["default".to_string()]);
    assert_eq!(out.sealed_blocks.len(), 1);
    assert_eq!(out.sealed_blocks[0].name, "default");
    assert!(!out.fields.contains_key("body"));
    assert!(out.plaintext.is_empty());

    publisher.close()?;
    stranger.close()?;
    Ok(())
}

#[test]
fn seal_receipt_row() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let sealed = tn.seal(
        "obj.invoice.v1",
        json!({ "amount": 9800 }),
        SealOptions::default(),
    )?;

    let entries = tn.read(ReadOptions::default())?;
    let receipt = common::find_event(&entries, "tn.object.sealed");
    assert_eq!(
        receipt.get("object_id").and_then(Value::as_str),
        sealed.envelope["row_hash"].as_str()
    );
    assert_eq!(
        receipt.get("object_type").and_then(Value::as_str),
        Some("obj.invoice.v1")
    );
    assert_eq!(receipt.get("groups").cloned(), Some(json!(["default"])));

    tn.close()?;
    Ok(())
}
