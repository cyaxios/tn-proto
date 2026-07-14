// Demonstrates a verified read over all runs. The example writes a single
// event to an ephemeral ceremony, then reads it back with verification enabled.

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    tn.info(
        "example.read",
        json!({
            "message": "read this entry back",
            "source": "rust-sdk",
        }),
    )?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    })?;

    for entry in entries {
        if entry.get("event_type").and_then(Value::as_str) == Some("example.read") {
            println!("{entry:#?}");
        }
    }

    Ok(())
}
