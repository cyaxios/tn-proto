// Minimal tn-proto example: create an ephemeral ceremony, emit one event, and
// read it back. This does not write to a persistent project directory.

use serde_json::{json, Value};
use tn_proto::{ReadOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    tn.info(
        "example.hello",
        json!({
            "message": "hello from Rust",
            "count": 1,
        }),
    )?;

    for entry in tn.read(ReadOptions::default())? {
        if entry.get("event_type").and_then(Value::as_str) == Some("example.hello") {
            println!("{entry:#?}");
        }
    }

    Ok(())
}
