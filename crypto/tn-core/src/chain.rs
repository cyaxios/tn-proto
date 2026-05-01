//! Chain state and row_hash computation (PRD §5).
//!
//! Mirrors `tn/chain.py` byte-for-byte: SHA-256 over the concatenation of
//! envelope fields with null separators, then the groups' ciphertexts and
//! field-hash tokens sorted by key.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// Initial prev_hash for any event_type chain: `sha256:` followed by 64 zero hex chars.
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Input for a single group inside the row hash: ciphertext bytes + sorted field hashes.
pub struct GroupInput {
    /// Raw ciphertext bytes (un-hex'd or un-base64'd).
    pub ciphertext: Vec<u8>,
    /// Sorted field-name → HMAC token mapping.
    pub field_hashes: BTreeMap<String, String>,
}

/// Input struct for [`compute_row_hash`].
pub struct RowHashInput<'a> {
    /// Publisher DID (did:key:z…).
    pub did: &'a str,
    /// ISO-8601 UTC timestamp.
    pub timestamp: &'a str,
    /// UUID v4.
    pub event_id: &'a str,
    /// Dotted event type (e.g. `order.created`).
    pub event_type: &'a str,
    /// Lower-cased level (e.g. `info`).
    pub level: &'a str,
    /// Previous row hash for this event_type.
    pub prev_hash: &'a str,
    /// Public (unencrypted) envelope fields — BTreeMap keeps sort order stable.
    pub public_fields: &'a BTreeMap<String, Value>,
    /// Per-group ciphertext + field hashes.
    pub groups: &'a BTreeMap<String, GroupInput>,
}

/// Compute the row_hash exactly as Python does: `"sha256:" + hex(sha256(concat))`.
///
/// Layout (each token is followed by a `\x00` byte):
/// 1. did, timestamp, event_id, event_type, level, prev_hash
/// 2. public_fields sorted by key: `key=<str(value)>\x00`
/// 3. groups sorted by name: `group:<name>\x00 ct:<ct-bytes>\x00 <fname>=<token>\x00 …`
pub fn compute_row_hash(input: &RowHashInput<'_>) -> String {
    let mut h = Sha256::new();

    // 1. Envelope scalars — each followed by \x00.
    for s in [
        input.did,
        input.timestamp,
        input.event_id,
        input.event_type,
        input.level,
        input.prev_hash,
    ] {
        h.update(s.as_bytes());
        h.update([0u8]);
    }

    // 2. Public fields (already sorted by BTreeMap).
    for (k, v) in input.public_fields {
        h.update(k.as_bytes());
        h.update(b"=");
        render_value(v, &mut h);
        h.update([0u8]);
    }

    // 3. Groups (already sorted by BTreeMap).
    for (gname, g) in input.groups {
        h.update(b"group:");
        h.update(gname.as_bytes());
        h.update([0u8]);
        h.update(b"ct:");
        h.update(&g.ciphertext);
        h.update([0u8]);
        // field_hashes is BTreeMap → sorted.
        for (fname, ftok) in &g.field_hashes {
            h.update(fname.as_bytes());
            h.update(b"=");
            h.update(ftok.as_bytes());
            h.update([0u8]);
        }
    }

    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Render a JSON value the way Python's `str()` would.
///
/// - `str` → raw UTF-8 bytes (no quotes)
/// - `bool` → `"True"` / `"False"` (Python capitalisation)
/// - `null` → `"None"`
/// - number → decimal string
/// - arrays/objects → JSON fallback (no current fixture exercises these)
fn render_value(v: &Value, h: &mut Sha256) {
    match v {
        Value::String(s) => h.update(s.as_bytes()),
        Value::Bool(true) => h.update(b"True"),
        Value::Bool(false) => h.update(b"False"),
        Value::Null => h.update(b"None"),
        Value::Number(n) => h.update(n.to_string().as_bytes()),
        Value::Array(_) | Value::Object(_) => {
            // Python str(list) / str(dict) — not exercised by current fixtures.
            // Fall back to JSON representation; extend here if a future fixture needs Python repr.
            h.update(v.to_string().as_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// ChainState
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EventChain {
    seq: u64,
    prev_hash: String,
}

/// Per-event_type chain state: monotonic sequence + prev_hash linkage.
///
/// Thread-safe via internal mutex; safe to share across threads.
pub struct ChainState {
    chains: Mutex<HashMap<String, EventChain>>,
}

impl ChainState {
    /// Create an empty chain state (every event_type starts at seq=0, prev=ZERO_HASH).
    pub fn new() -> Self {
        Self {
            chains: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve the next slot for `event_type`: returns `(next_seq, prev_hash)`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (another thread panicked while holding it).
    pub fn advance(&self, event_type: &str) -> (u64, String) {
        let mut g = self.chains.lock().expect("chain state mutex poisoned");
        let ec = g
            .entry(event_type.to_string())
            .or_insert_with(|| EventChain {
                seq: 0,
                prev_hash: ZERO_HASH.to_string(),
            });
        ec.seq += 1;
        (ec.seq, ec.prev_hash.clone())
    }

    /// Commit the new row_hash for `event_type` (called after the row is materialised).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn commit(&self, event_type: &str, row_hash: &str) {
        let mut g = self.chains.lock().expect("chain state mutex poisoned");
        if let Some(ec) = g.get_mut(event_type) {
            ec.prev_hash = row_hash.to_string();
        }
    }

    /// Seed chain state from a prior log scan (for process restart / warm-start).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn seed(&self, entries: HashMap<String, (u64, String)>) {
        let mut g = self.chains.lock().expect("chain state mutex poisoned");
        for (et, (seq, ph)) in entries {
            g.insert(et, EventChain { seq, prev_hash: ph });
        }
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}
