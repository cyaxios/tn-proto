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

    // Build "sha256:<64 hex chars>" in one allocation rather than
    // `format!` + `hex::encode` which allocates twice.
    let digest = h.finalize();
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    let mut hex_buf = [0u8; 64];
    hex::encode_to_slice(digest.as_slice(), &mut hex_buf)
        .expect("32-byte digest into 64-char buffer is infallible");
    out.push_str(
        std::str::from_utf8(&hex_buf).expect("hex::encode_to_slice emits ASCII"),
    );
    out
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

/// Walk an ndjson log line-by-line and return the latest `(seq, row_hash)`
/// observed for each `event_type`. Used by the cross-process emit lock
/// (DX review 0.4.2a3) to refresh chain state from disk truth before
/// advancing — the in-memory `ChainState` is per-process, so two
/// workers racing on `tn.info("evt", …)` previously both started from
/// the same stale view and emitted rows with conflicting `prev_hash`
/// values. This helper produces the authoritative tip; `ChainState`
/// is then re-seeded under the file lock before `advance` runs.
///
/// Lines that don't parse, or that lack `event_type`/`sequence`/
/// `row_hash`, are silently skipped. The intent is to find the
/// chain tip, not to validate the log — verification stays the
/// reader's job.
///
/// Returns an empty map for a missing or unreadable log (treated as
/// "no prior rows"; the runtime's existing init code-path already
/// seeds from disk on `Runtime::init`, so this is only the
/// per-emit refresh layer).
pub fn chain_tips_from_ndjson(bytes: &[u8]) -> HashMap<String, (u64, String)> {
    let mut out: HashMap<String, (u64, String)> = HashMap::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let Some(event_type) = env.get("event_type").and_then(Value::as_str) else {
            continue;
        };
        let Some(seq) = env.get("sequence").and_then(Value::as_u64) else {
            continue;
        };
        let Some(row_hash) = env.get("row_hash").and_then(Value::as_str) else {
            continue;
        };
        // Last-write-wins per event_type: later iterations of the
        // loop overwrite the earlier entry, which matches "the
        // most recent row in the file for this event_type."
        out.insert(event_type.to_string(), (seq, row_hash.to_string()));
    }
    out
}

/// Reverse-scan helper for the cross-process emit lock's hot path.
///
/// Walks `bytes` backward from the end and returns the latest
/// `(sequence, row_hash)` for `event_type`, stopping as soon as the
/// most-recent matching row is found. The forward-scan equivalent
/// (`chain_tips_from_ndjson`) reads the whole file to build a tips map
/// for every event_type; for a single emit we only care about one
/// event_type and stop early, which is the perf fix S11 surfaced
/// (forward scan was O(N) per emit, O(N²) over a session).
///
/// Returns `None` when no row in `bytes` carries the target
/// `event_type` (caller treats this as ZERO_HASH / seq=0, matching
/// the existing init-time semantics). Malformed lines are silently
/// skipped, same contract as `chain_tips_from_ndjson`.
pub fn chain_tip_from_log_tail_reverse(
    bytes: &[u8],
    event_type: &str,
) -> Option<(u64, String)> {
    // Trim trailing newline(s) so the final line, if it doesn't end
    // in `\n`, still scans as one line rather than as an empty
    // segment after a phantom newline.
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'\n' {
        end -= 1;
    }
    while end > 0 {
        // Walk back to the previous `\n` (or to byte 0).
        let mut start = end;
        while start > 0 && bytes[start - 1] != b'\n' {
            start -= 1;
        }
        let line = &bytes[start..end];
        if !line.is_empty() {
            if let Ok(env) = serde_json::from_slice::<Value>(line) {
                if env.get("event_type").and_then(Value::as_str) == Some(event_type) {
                    let seq = env.get("sequence").and_then(Value::as_u64);
                    let rh = env.get("row_hash").and_then(Value::as_str);
                    if let (Some(s), Some(r)) = (seq, rh) {
                        return Some((s, r.to_string()));
                    }
                    // Row matched event_type but is missing
                    // sequence/row_hash — treat as malformed and
                    // keep walking. The next match (if any) wins.
                }
            }
        }
        if start == 0 {
            return None;
        }
        end = start - 1; // skip the `\n` between this line and the previous one
    }
    None
}

/// Multi-file variant of [`chain_tip_from_log_tail_reverse`]: try the
/// active log first, then walk into rotated backups (newest first)
/// until a row for `event_type` is found.
///
/// The runtime emits into a single active file; rotation (today,
/// session-start; in a later release, size-triggered with commit
/// envelopes) shifts the active file to `<log>.1` and starts a fresh
/// active. When the very first emit of an event_type after a
/// rotation needs to chain off the pre-rotation tip, the active file
/// is empty for that event_type and we have to peek into `.1`.
///
/// Caller supplies the byte slices in newest-first order (active,
/// `.1`, `.2`, …). Returns on the first match; `None` when no file
/// in the slice carries `event_type`.
pub fn chain_tip_from_log_files_reverse(
    files_newest_first: &[&[u8]],
    event_type: &str,
) -> Option<(u64, String)> {
    for bytes in files_newest_first {
        if let Some(tip) = chain_tip_from_log_tail_reverse(bytes, event_type) {
            return Some(tip);
        }
    }
    None
}

#[cfg(test)]
mod chain_tip_tests {
    use super::*;

    #[test]
    fn empty_log_returns_empty_map() {
        let tips = chain_tips_from_ndjson(b"");
        assert!(tips.is_empty());
    }

    #[test]
    fn latest_row_per_event_type_wins() {
        let bytes = b"{\"event_type\":\"a\",\"sequence\":1,\"row_hash\":\"sha256:11\"}\n\
                     {\"event_type\":\"a\",\"sequence\":2,\"row_hash\":\"sha256:22\"}\n\
                     {\"event_type\":\"b\",\"sequence\":1,\"row_hash\":\"sha256:bb\"}\n";
        let tips = chain_tips_from_ndjson(bytes);
        assert_eq!(tips.len(), 2);
        assert_eq!(tips["a"], (2, "sha256:22".to_string()));
        assert_eq!(tips["b"], (1, "sha256:bb".to_string()));
    }

    #[test]
    fn malformed_lines_skipped() {
        let bytes = b"not json\n\
                     {\"event_type\":\"a\",\"sequence\":1,\"row_hash\":\"sha256:11\"}\n\
                     {\"missing_fields\":true}\n\
                     {\"event_type\":\"a\",\"sequence\":2,\"row_hash\":\"sha256:22\"}\n\
                     \n";
        let tips = chain_tips_from_ndjson(bytes);
        assert_eq!(tips.len(), 1);
        assert_eq!(tips["a"], (2, "sha256:22".to_string()));
    }

    #[test]
    fn reverse_scan_empty_returns_none() {
        assert!(chain_tip_from_log_tail_reverse(b"", "a").is_none());
    }

    #[test]
    fn reverse_scan_finds_last_match() {
        let bytes = b"{\"event_type\":\"a\",\"sequence\":1,\"row_hash\":\"sha256:11\"}\n\
                     {\"event_type\":\"b\",\"sequence\":1,\"row_hash\":\"sha256:bb\"}\n\
                     {\"event_type\":\"a\",\"sequence\":2,\"row_hash\":\"sha256:22\"}\n";
        assert_eq!(
            chain_tip_from_log_tail_reverse(bytes, "a"),
            Some((2, "sha256:22".to_string()))
        );
        assert_eq!(
            chain_tip_from_log_tail_reverse(bytes, "b"),
            Some((1, "sha256:bb".to_string()))
        );
    }

    #[test]
    fn reverse_scan_returns_none_when_event_type_absent() {
        let bytes = b"{\"event_type\":\"a\",\"sequence\":1,\"row_hash\":\"sha256:11\"}\n";
        assert!(chain_tip_from_log_tail_reverse(bytes, "x").is_none());
    }

    #[test]
    fn reverse_scan_handles_missing_trailing_newline() {
        let bytes = b"{\"event_type\":\"a\",\"sequence\":1,\"row_hash\":\"sha256:11\"}\n\
                     {\"event_type\":\"a\",\"sequence\":2,\"row_hash\":\"sha256:22\"}";
        assert_eq!(
            chain_tip_from_log_tail_reverse(bytes, "a"),
            Some((2, "sha256:22".to_string()))
        );
    }

    #[test]
    fn reverse_scan_skips_malformed_and_finds_earlier_clean_row() {
        let bytes = b"{\"event_type\":\"a\",\"sequence\":1,\"row_hash\":\"sha256:11\"}\n\
                     not json\n\
                     {\"event_type\":\"a\",\"missing_seq\":true}\n";
        assert_eq!(
            chain_tip_from_log_tail_reverse(bytes, "a"),
            Some((1, "sha256:11".to_string()))
        );
    }

    #[test]
    fn multi_file_reverse_scan_falls_back_to_backup() {
        let active: &[u8] = b"{\"event_type\":\"b\",\"sequence\":1,\"row_hash\":\"sha256:bb\"}\n";
        let backup1: &[u8] =
            b"{\"event_type\":\"a\",\"sequence\":3,\"row_hash\":\"sha256:a3\"}\n";
        let backup2: &[u8] =
            b"{\"event_type\":\"a\",\"sequence\":2,\"row_hash\":\"sha256:a2\"}\n\
              {\"event_type\":\"x\",\"sequence\":1,\"row_hash\":\"sha256:x1\"}\n";
        let files: Vec<&[u8]> = vec![active, backup1, backup2];
        assert_eq!(
            chain_tip_from_log_files_reverse(&files, "a"),
            Some((3, "sha256:a3".to_string()))
        );
        assert_eq!(
            chain_tip_from_log_files_reverse(&files, "x"),
            Some((1, "sha256:x1".to_string()))
        );
        assert_eq!(chain_tip_from_log_files_reverse(&files, "missing"), None);
    }

    #[test]
    fn multi_file_reverse_scan_active_wins_over_backup() {
        let active: &[u8] = b"{\"event_type\":\"a\",\"sequence\":5,\"row_hash\":\"sha256:a5\"}\n";
        let backup1: &[u8] =
            b"{\"event_type\":\"a\",\"sequence\":3,\"row_hash\":\"sha256:a3\"}\n";
        let files: Vec<&[u8]> = vec![active, backup1];
        assert_eq!(
            chain_tip_from_log_files_reverse(&files, "a"),
            Some((5, "sha256:a5".to_string()))
        );
    }

    #[test]
    fn reverse_scan_equivalent_to_forward_scan_for_single_event_type() {
        // 1000 alternating-event_type lines — reverse-scan should
        // terminate at the last matching row, not walk to byte 0.
        let mut buf: Vec<u8> = Vec::with_capacity(1024 * 100);
        for i in 0..500u64 {
            buf.extend_from_slice(
                format!(
                    "{{\"event_type\":\"a\",\"sequence\":{},\"row_hash\":\"sha256:a{}\"}}\n",
                    i + 1,
                    i + 1
                )
                .as_bytes(),
            );
            buf.extend_from_slice(
                format!(
                    "{{\"event_type\":\"b\",\"sequence\":{},\"row_hash\":\"sha256:b{}\"}}\n",
                    i + 1,
                    i + 1
                )
                .as_bytes(),
            );
        }
        let tips = chain_tips_from_ndjson(&buf);
        assert_eq!(
            chain_tip_from_log_tail_reverse(&buf, "a"),
            Some(tips["a"].clone())
        );
        assert_eq!(
            chain_tip_from_log_tail_reverse(&buf, "b"),
            Some(tips["b"].clone())
        );
    }
}
