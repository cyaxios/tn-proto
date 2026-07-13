use serde_json::{json, Value};
use std::fs;
use std::time::{Duration, Instant};
use tn_core::runtime::{canonical_file_source_id, CursorKind};
use tn_proto::{PollingWatchOptions, ReadOptions, Tn, TnProjectOptions, WatchOptions, WatchStart};

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

    // The emit-side chain keeps pointing at the pre-truncation tip, so a
    // row appended after truncation cannot chain-verify; the explicit
    // Disabled escape hatch keeps this test about cursor mechanics.
    let mut watch = tn.watch(WatchOptions {
        start: WatchStart::Beginning,
        read: ReadOptions {
            verify: false,
            ..ReadOptions::default()
        },
        ..WatchOptions::default()
    })?;
    assert!(!watch.poll()?.is_empty());
    assert!(watch.cursor() > 0);

    fs::write(tn.log_path(), "")?;
    tn.info("watch.cursor.after_truncate", json!({ "item": 3 }))?;

    let entries = watch.poll()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), Some("watch.cursor.after_truncate"));

    Ok(())
}

#[test]
fn watch_resets_a_relative_log_path_with_the_core_source_id() -> tn_proto::Result<()> {
    let cwd = std::env::current_dir()?;
    let workspace = tempfile::Builder::new()
        .prefix("tn-watch-relative-")
        .tempdir_in(&cwd)?;
    let created = Tn::init_project_with_options(
        "relative-watch",
        TnProjectOptions {
            project_dir: Some(workspace.path().to_path_buf()),
            ..TnProjectOptions::default()
        },
    )?;
    let yaml_path = created.yaml_path().to_path_buf();
    created.close()?;
    let relative_yaml = yaml_path
        .strip_prefix(&cwd)
        .expect("test project lives below the current directory");
    let tn = Tn::init(relative_yaml)?;
    assert!(!tn.log_path().is_absolute());
    tn.info("watch.relative.before", json!({ "item": 1 }))?;

    let mut watch = tn.watch(WatchOptions {
        start: WatchStart::Beginning,
        read: ReadOptions {
            verify: false,
            ..ReadOptions::default()
        },
        ..WatchOptions::default()
    })?;
    assert!(!watch.poll()?.is_empty());
    assert!(watch.cursor() > 0);

    fs::write(tn.log_path(), "")?;
    tn.info("watch.relative.after", json!({ "item": 2 }))?;
    let entries = watch.poll()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), Some("watch.relative.after"));
    Ok(())
}

#[test]
fn watch_forwards_read_options_to_each_poll() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    // The stable verification flag flows through the watcher into every poll.
    let mut watch = tn.watch(WatchOptions {
        read: ReadOptions {
            verify: true,
            ..ReadOptions::default()
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
        .expect("verified reads attach an EntryValidity block");
    assert!(validity.signature);
    assert!(validity.row_hash);
    assert!(validity.chain);
    assert_eq!(
        entry
            .get("_valid")
            .and_then(Value::as_object)
            .and_then(|valid| valid.get("writer_authorized"))
            .and_then(Value::as_bool),
        Some(true)
    );

    Ok(())
}

#[test]
fn watch_cursor_advances_by_source_position_past_rejected_rows() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let mut watch = tn.watch(WatchOptions {
        start: WatchStart::Latest,
        read: ReadOptions {
            all_runs: true,
            verify: false,
            ..ReadOptions::default()
        },
        event_type_prefix: Some("cursor.".to_string()),
        ..WatchOptions::default()
    })?;
    let source_id = canonical_file_source_id(tn.log_path().to_str().expect("utf-8 log path"));

    let cursor_position = |watch: &tn_proto::Watch<'_>| -> u64 {
        let cursor = watch.read_cursor();
        assert_eq!(cursor.version, 1);
        let source = cursor
            .sources
            .get(&source_id)
            .expect("cursor keyed by the canonical log source id");
        assert_eq!(source.kind, CursorKind::ByteOffset);
        source.value.parse().expect("decimal byte offset")
    };

    // The watcher persists the shared cursor shape from construction on.
    let start = cursor_position(&watch);
    assert_eq!(start, fs::metadata(tn.log_path())?.len());
    let serialized = serde_json::to_value(watch.read_cursor())?;
    assert_eq!(serialized["version"], json!(1));
    assert_eq!(
        serialized["sources"][&source_id]["kind"],
        json!("byte_offset")
    );

    tn.info("cursor.one", json!({ "n": 1 }))?;
    let first = watch.poll()?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].event_type(), Some("cursor.one"));
    let after_first = cursor_position(&watch);
    assert!(after_first > start);
    assert_eq!(after_first, fs::metadata(tn.log_path())?.len());

    // A rejected row between two accepted rows: the poll yields only the
    // accepted rows, but the cursor covers all three source positions.
    tn.info("cursor.two", json!({ "n": 2 }))?;
    let mut log = fs::read_to_string(tn.log_path())?;
    log.push_str("this-is-not-a-record\n");
    fs::write(tn.log_path(), log)?;
    tn.info("cursor.three", json!({ "n": 3 }))?;
    let expected_span = fs::metadata(tn.log_path())?.len();

    let second = watch.poll()?;
    let event_types: Vec<_> = second
        .iter()
        .filter_map(|entry| entry.event_type().map(str::to_string))
        .collect();
    assert_eq!(event_types, vec!["cursor.two", "cursor.three"]);
    let after_second = cursor_position(&watch);
    assert!(after_second >= expected_span);
    assert!(after_second > after_first);

    // Rows that are scanned but not yielded (filtered or skipped) still
    // advance the cursor: progress is source position, not entry count.
    tn.info("noise.row", json!({ "n": 4 }))?;
    let third = watch.poll()?;
    assert!(third.is_empty());
    let after_third = cursor_position(&watch);
    assert!(after_third > after_second);

    Ok(())
}
