// Demonstrates package export and absorb. It creates an admin snapshot and a
// recipient kit bundle from one ephemeral ceremony, then absorbs both into a
// second ephemeral ceremony.

use serde_json::json;
use tn_proto::{BundleForRecipientOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    producer.info("payment.created", json!({ "order_id": "PKG-100" }))?;

    let root = producer
        .log_path()
        .ancestors()
        .find(|path| path.join("tn.yaml").exists())
        .expect("ephemeral ceremony root should contain tn.yaml");
    let admin_snapshot = root.join("admin-snapshot.tnpkg");
    let reader_bundle = root.join("reader-kits.tnpkg");

    producer.pkg().export_admin_snapshot(&admin_snapshot)?;
    println!("wrote admin snapshot: {}", admin_snapshot.display());

    producer.pkg().bundle_for_recipient(
        "did:key:zExampleReader",
        &reader_bundle,
        BundleForRecipientOptions {
            groups: Some(vec!["payments".to_string()]),
            seal_for_recipient: false,
        },
    )?;
    println!("wrote reader bundle: {}", reader_bundle.display());

    let consumer = Tn::ephemeral()?;
    let admin_receipt = consumer.pkg().absorb_path(&admin_snapshot)?;
    println!("absorbed admin snapshot: {admin_receipt:#?}");
    let bundle_receipt = consumer.pkg().absorb_path(&reader_bundle)?;
    println!("absorbed reader bundle: {bundle_receipt:#?}");

    Ok(())
}
