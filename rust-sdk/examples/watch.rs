// Demonstrates the synchronous polling watcher. It starts from the latest read
// position, filters by event-type prefix, emits matching and non-matching
// events, then waits briefly for matching entries.

use std::time::Duration;

use serde_json::json;
use tn_proto::{Tn, WatchOptions, WatchStart};

fn main() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    tn.info("example.before_watch", json!({ "ignored": true }))?;

    let mut watch = tn.watch(WatchOptions {
        start: WatchStart::Latest,
        event_type_prefix: Some("example.watch.".to_string()),
        poll_interval: Duration::from_millis(50),
        ..WatchOptions::default()
    })?;

    tn.info("example.other", json!({ "ignored": true }))?;
    tn.info(
        "example.watch.created",
        json!({
            "message": "visible to the watcher",
            "source": "rust-sdk",
        }),
    )?;

    for entry in watch.wait_for_entries(Duration::from_secs(1))? {
        println!("{entry:#?}");
    }

    Ok(())
}
