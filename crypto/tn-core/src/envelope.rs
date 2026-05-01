//! Envelope build + ndjson serialization.
//!
//! Matches `tn/logger.py::emit` output format:
//! - Envelope key order: did, timestamp, event_id, event_type, level, sequence,
//!   prev_hash, row_hash, signature; then public fields in insertion order;
//!   then group payloads in insertion order.
//! - Group payload sub-object: `{"ciphertext": "<b64-std>", "field_hashes": {...}}`.
//! - Output: `json.dumps(envelope, separators=(",", ":")) + "\n"` equivalent.
//!
//! Requires `serde_json` with the `preserve_order` feature (enabled at the
//! workspace level) so `Map<String, Value>` preserves insertion order.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::Result;

/// A single group's encrypted payload as serialized in the envelope.
#[derive(Serialize)]
pub struct GroupPayload {
    /// Raw ciphertext bytes — serialized as standard base64.
    #[serde(serialize_with = "ser_b64")]
    pub ciphertext: Vec<u8>,
    /// Sorted field-name → HMAC token.
    pub field_hashes: BTreeMap<String, String>,
}

fn ser_b64<S: serde::Serializer>(b: &Vec<u8>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(b))
}

/// Input struct for [`build_envelope`].
pub struct EnvelopeInput<'a> {
    /// Publisher DID.
    pub did: &'a str,
    /// ISO-8601 UTC timestamp.
    pub timestamp: &'a str,
    /// UUID v4.
    pub event_id: &'a str,
    /// Event type (e.g. `order.created`).
    pub event_type: &'a str,
    /// Lower-cased level.
    pub level: &'a str,
    /// Monotonic sequence per event_type.
    pub sequence: u64,
    /// Previous row hash in this chain.
    pub prev_hash: &'a str,
    /// Row hash of this entry (already computed).
    pub row_hash: &'a str,
    /// URL-safe no-padding base64 signature over row_hash bytes.
    pub signature_b64: &'a str,
    /// Public fields (inserted in iteration order into envelope JSON).
    pub public_fields: Map<String, Value>,
    /// Per-group payloads already built (inserted in iteration order).
    pub group_payloads: Map<String, Value>,
}

/// Build an envelope JSON line with trailing newline, matching Python's output.
///
/// Key order: the 9 mandatory scalar fields first, then public fields in
/// insertion order (skipping any that collide with a mandatory key), then
/// group payloads in insertion order.
pub fn build_envelope(input: EnvelopeInput<'_>) -> Result<String> {
    let mut env = Map::new();
    env.insert("did".into(), Value::String(input.did.into()));
    env.insert("timestamp".into(), Value::String(input.timestamp.into()));
    env.insert("event_id".into(), Value::String(input.event_id.into()));
    env.insert("event_type".into(), Value::String(input.event_type.into()));
    env.insert("level".into(), Value::String(input.level.into()));
    env.insert("sequence".into(), Value::Number(input.sequence.into()));
    env.insert("prev_hash".into(), Value::String(input.prev_hash.into()));
    env.insert("row_hash".into(), Value::String(input.row_hash.into()));
    env.insert(
        "signature".into(),
        Value::String(input.signature_b64.into()),
    );
    for (k, v) in input.public_fields {
        // Skip any public field whose key collides with a mandatory header key.
        env.entry(k).or_insert(v);
    }
    for (k, v) in input.group_payloads {
        env.insert(k, v);
    }
    let mut out = serde_json::to_string(&env)?;
    out.push('\n');
    Ok(out)
}
