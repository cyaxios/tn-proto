//! Stable Rust-facing read entry type.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// One decrypted flat TN log entry.
///
/// `Entry` intentionally keeps the flexible JSON shape used by the Python and
/// TypeScript SDKs while giving the Rust SDK a stable public type. Known
/// envelope fields such as `event_type`, `level`, and verification flags have
/// convenience accessors; custom event fields remain available through
/// [`Entry::get`] or [`Entry::as_map`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    fields: Map<String, Value>,
}

/// Per-entry verification flags returned by verified reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryValidity {
    /// Signature verification result.
    pub signature: bool,
    /// Row hash verification result.
    pub row_hash: bool,
    /// Hash-chain verification result.
    pub chain: bool,
}

impl Entry {
    /// Wrap a flat JSON object as an SDK entry.
    pub fn from_map(fields: Map<String, Value>) -> Self {
        Self { fields }
    }

    /// Borrow the underlying flat JSON object.
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.fields
    }

    /// Consume the entry and return the underlying flat JSON object.
    pub fn into_map(self) -> Map<String, Value> {
        self.fields
    }

    /// Return a field by name.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    /// True when the entry contains `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// The entry's event type, when present.
    pub fn event_type(&self) -> Option<&str> {
        self.get("event_type").and_then(Value::as_str)
    }

    /// The entry's log level, when present.
    pub fn level(&self) -> Option<&str> {
        self.get("level").and_then(Value::as_str)
    }

    /// The entry's timestamp, when present.
    pub fn timestamp(&self) -> Option<&str> {
        self.get("timestamp").and_then(Value::as_str)
    }

    /// The entry's event id, when present.
    pub fn event_id(&self) -> Option<&str> {
        self.get("event_id").and_then(Value::as_str)
    }

    /// The entry's run id, when present.
    pub fn run_id(&self) -> Option<&str> {
        self.get("run_id").and_then(Value::as_str)
    }

    /// The entry's sequence number, when present.
    pub fn sequence(&self) -> Option<u64> {
        self.get("sequence").and_then(Value::as_u64)
    }

    /// Verification flags attached by `ReadOptions { verify: true, .. }`.
    pub fn validity(&self) -> Option<EntryValidity> {
        let valid = self.get("_valid")?.as_object()?;
        Some(EntryValidity {
            signature: valid.get("signature")?.as_bool()?,
            row_hash: valid.get("row_hash")?.as_bool()?,
            chain: valid.get("chain")?.as_bool()?,
        })
    }
}

impl From<Map<String, Value>> for Entry {
    fn from(fields: Map<String, Value>) -> Self {
        Self::from_map(fields)
    }
}

impl From<Entry> for Map<String, Value> {
    fn from(entry: Entry) -> Self {
        entry.into_map()
    }
}

impl AsRef<Map<String, Value>> for Entry {
    fn as_ref(&self) -> &Map<String, Value> {
        self.as_map()
    }
}
