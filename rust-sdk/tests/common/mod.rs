#![allow(dead_code)]

use serde_json::Value;
use tn_proto::Entry;

pub fn find_event<'a>(entries: &'a [Entry], event_type: &str) -> &'a Entry {
    entries
        .iter()
        .find(|entry| entry.event_type() == Some(event_type))
        .unwrap_or_else(|| panic!("missing event_type {event_type:?}; entries={entries:#?}"))
}

pub fn valid_flags(entry: &Entry) -> (bool, bool, bool) {
    let valid = entry
        .get("_valid")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("entry missing _valid block: {entry:#?}"));
    let flag = |name: &str| {
        valid
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or_else(|| panic!("entry _valid missing bool flag {name:?}: {entry:#?}"))
    };
    (flag("signature"), flag("row_hash"), flag("chain"))
}

pub fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust-sdk should live under the repo root")
        .to_path_buf()
}
