use serde_json::{json, Value};
use std::fs;
use std::time::{Duration, Instant};
use tn_proto::{PollingWatchOptions, Tn, WatchOptions, WatchStart};

#[test]
fn watch_latest_polls_entries_emitted_after_start() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("watch.before", json!({ "item": "old" }))?;

    let mut watch = tn.watch(WatchOptions::default())?;
    assert!(watch.poll()?.is_empty());

    tn.info("watch.after_one", json!({ "item": "new-1" }))?;
    tn.info("watch.after_two", json!({ "item": "new-2" }))?;

    let entries = watch.poll()?;
    let event_types = entries
        .iter()
        .filter_map(|entry| entry.get("event_type").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(event_types, vec!["watch.after_one", "watch.after_two"]);

    assert!(watch.poll()?.is_empty());

    Ok(())
}

#[test]
fn polling_watch_alias_uses_same_read_backed_behavior() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("polling.before", json!({ "item": "old" }))?;

    let mut watch = tn.polling_watch(PollingWatchOptions::default())?;
    assert!(watch.poll()?.is_empty());

    tn.info("polling.after", json!({ "item": "new" }))?;

    let entries = watch.poll()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), Some("polling.after"));

    Ok(())
}

#[cfg(feature = "watch")]
#[test]
fn native_watch_wakes_on_log_change() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.native_watch(tn_proto::NativeWatchOptions::default())?;

    tn.info("native.watch", json!({ "item": "changed" }))?;

    let entries = watch.wait_for_entries(Duration::from_secs(5))?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), Some("native.watch"));

    Ok(())
}

#[cfg(feature = "watch")]
#[test]
fn native_watch_honors_read_backed_filters() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.native_watch(tn_proto::NativeWatchOptions {
        polling: WatchOptions {
            event_type_prefix: Some("native.keep".to_string()),
            ..WatchOptions::default()
        },
    })?;

    tn.info("native.drop", json!({ "item": "ignored" }))?;
    tn.info("native.keep.one", json!({ "item": "accepted" }))?;

    let entries = watch.wait_for_entries(Duration::from_secs(5))?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), Some("native.keep.one"));

    Ok(())
}

#[test]
fn watch_beginning_replays_current_read_view() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("watch.replay", json!({ "item": "existing" }))?;

    let mut watch = tn.watch(WatchOptions {
        start: WatchStart::Beginning,
        ..WatchOptions::default()
    })?;

    let entries = watch.poll()?;
    assert!(entries
        .iter()
        .any(|entry| { entry.get("event_type").and_then(Value::as_str) == Some("watch.replay") }));

    Ok(())
}

#[test]
fn wait_for_entries_returns_ready_entries_without_sleeping_full_timeout() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions::default())?;
    tn.info("watch.ready", json!({ "item": "ready" }))?;

    let started = Instant::now();
    let entries = watch.wait_for_entries(Duration::from_secs(5))?;

    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("event_type").and_then(Value::as_str),
        Some("watch.ready")
    );

    Ok(())
}

#[test]
fn wait_for_entries_returns_empty_after_timeout() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions {
        poll_interval: Duration::from_millis(10),
        ..WatchOptions::default()
    })?;

    let started = Instant::now();
    let entries = watch.wait_for_entries(Duration::from_millis(25))?;

    assert!(entries.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(20));

    Ok(())
}

#[test]
fn watch_filters_by_exact_event_type() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions {
        event_type: Some("watch.match".to_string()),
        ..WatchOptions::default()
    })?;

    tn.info("watch.skip", json!({ "item": "ignored" }))?;
    tn.info("watch.match", json!({ "item": "accepted" }))?;

    let entries = watch.poll()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("event_type").and_then(Value::as_str),
        Some("watch.match")
    );

    assert!(watch.poll()?.is_empty());

    Ok(())
}

#[test]
fn watch_filters_by_event_type_prefix() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions {
        event_type_prefix: Some("order.".to_string()),
        ..WatchOptions::default()
    })?;

    tn.info("invoice.created", json!({ "id": "INV-1" }))?;
    tn.info("order.created", json!({ "id": "ORD-1" }))?;
    tn.info("order.shipped", json!({ "id": "ORD-1" }))?;

    let event_types = watch
        .poll()?
        .iter()
        .filter_map(|entry| entry.get("event_type").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();

    assert_eq!(event_types, vec!["order.created", "order.shipped"]);

    Ok(())
}

#[test]
fn watch_combined_filters_require_exact_and_prefix_match() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions {
        event_type: Some("order.created".to_string()),
        event_type_prefix: Some("order.".to_string()),
        ..WatchOptions::default()
    })?;

    tn.info("order.shipped", json!({ "id": "ORD-1" }))?;
    tn.info("order.created", json!({ "id": "ORD-2" }))?;

    let entries = watch.poll()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("event_type").and_then(Value::as_str),
        Some("order.created")
    );

    Ok(())
}

#[test]
fn watch_iterator_collects_until_idle() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let watch = tn.watch(WatchOptions::default())?;

    tn.info("watch.iter.one", json!({ "item": 1 }))?;
    tn.info("watch.iter.two", json!({ "item": 2 }))?;

    let entries = watch
        .into_iter_until_idle(Duration::from_millis(10))
        .collect::<tn_proto::Result<Vec<_>>>()?;
    let event_types = entries
        .iter()
        .filter_map(|entry| entry.get("event_type").and_then(Value::as_str))
        .collect::<Vec<_>>();

    assert_eq!(event_types, vec!["watch.iter.one", "watch.iter.two"]);

    Ok(())
}

#[test]
fn watch_iterator_honors_filters() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let watch = tn.watch(WatchOptions {
        event_type_prefix: Some("watch.keep".to_string()),
        ..WatchOptions::default()
    })?;

    tn.info("watch.drop", json!({ "item": "ignored" }))?;
    tn.info("watch.keep.one", json!({ "item": "accepted" }))?;

    let entries = watch
        .into_iter_until_idle(Duration::from_millis(10))
        .collect::<tn_proto::Result<Vec<_>>>()?;

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("event_type").and_then(Value::as_str),
        Some("watch.keep.one")
    );

    Ok(())
}

#[test]
fn watch_resets_cursor_when_read_view_shrinks() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("watch.cursor.one", json!({ "item": 1 }))?;
    tn.info("watch.cursor.two", json!({ "item": 2 }))?;

    let mut watch = tn.watch(WatchOptions {
        start: WatchStart::Beginning,
        ..WatchOptions::default()
    })?;
    assert!(!watch.poll()?.is_empty());
    assert!(watch.cursor() > 0);

    fs::write(tn.log_path(), "")?;
    tn.info("watch.cursor.after_truncate", json!({ "item": 3 }))?;

    let entries = watch.poll()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), Some("watch.cursor.after_truncate"));
    assert_eq!(watch.cursor(), 1);

    Ok(())
}

#[test]
fn watch_forwards_read_options_to_read() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions {
        read: tn_proto::ReadOptions {
            verify: true,
            ..tn_proto::ReadOptions::default()
        },
        ..WatchOptions::default()
    })?;

    tn.info("watch.verify", json!({ "item": "checked" }))?;

    let entries = watch.poll()?;
    let entry = entries
        .iter()
        .find(|entry| entry.event_type() == Some("watch.verify"))
        .expect("watch should return the emitted event");
    let validity = entry
        .validity()
        .expect("verify=true should add an EntryValidity block");

    assert!(validity.signature);
    assert!(validity.row_hash);
    assert!(validity.chain);

    Ok(())
}
