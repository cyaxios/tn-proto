//! TN envelope assembly and ndjson serialization — the on-the-wire record
//! shape. Internal primitive: most readers want the high-level API instead —
//! see [`crate::Runtime`] (write/read attested events, behind `tn.info()` /
//! `tn read`) and [`crate::Manifest`] (signed packages, behind `tn export`).
//! Reach here directly only when hand-building or parsing raw envelope bytes.
//!
//! Matches `tn/logger.py` output format:
//! - Envelope key order: device_identity, timestamp, event_id, event_type, level, sequence,
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
    /// Publisher device identity (`did:key:z…`).
    pub device_identity: &'a str,
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
    /// Per-group payloads, pre-rendered as JSON snippets (0.4.2a7).
    /// Was `Map<String, Value>` — that paid for a `to_value` tree
    /// alloc inside the encrypt loop AND a re-serialize inside
    /// envelope_build (double-walk). The runtime now serializes
    /// each `GroupPayload` straight to a JSON string at encrypt
    /// time; envelope_build splices the string in verbatim.
    pub group_payloads: BTreeMap<String, String>,
}

/// The 9 mandatory envelope keys in canonical write order. Any public
/// field with a colliding name is skipped on insertion (mandatory keys
/// always win — matches the prior `Map::entry().or_insert()` semantics).
const MANDATORY_KEYS: [&str; 9] = [
    "device_identity",
    "timestamp",
    "event_id",
    "event_type",
    "level",
    "sequence",
    "prev_hash",
    "row_hash",
    "signature",
];

/// Build an envelope JSON line with trailing newline, matching Python's output.
///
/// Key order: the 9 mandatory scalar fields first, then public fields in
/// insertion order (skipping any that collide with a mandatory key), then
/// group payloads in insertion order.
///
/// Direct string-builder shape (0.4.2a7 perf fix). The prior version
/// constructed a `Map<String, Value>` intermediate and ran
/// `serde_json::to_string` over the tree — that paid for 9-12 hash
/// inserts + key/value allocations + a second walk during
/// serialization. This version writes JSON straight into the output
/// buffer for the mandatory fields (whose values are runtime-trusted
/// strings: identities, ISO timestamps, hex/base64 hashes, signatures —
/// none contain JSON-special characters) and delegates only the
/// user-supplied ``public_fields`` and ``group_payloads`` to
/// `serde_json::to_writer` for proper escaping.
pub fn build_envelope(input: EnvelopeInput<'_>) -> Result<String> {
    let mut out = String::with_capacity(512);
    out.push('{');

    // Mandatory scalars — known order, runtime-controlled values
    // (no JSON-special chars). Write directly.
    write_safe_string_field(&mut out, "device_identity", input.device_identity);
    out.push(',');
    write_safe_string_field(&mut out, "timestamp", input.timestamp);
    out.push(',');
    write_safe_string_field(&mut out, "event_id", input.event_id);
    out.push(',');
    write_safe_string_field(&mut out, "event_type", input.event_type);
    out.push(',');
    write_safe_string_field(&mut out, "level", input.level);
    out.push(',');
    // u64 number — itoa-free fast path via std `write!`.
    use std::fmt::Write as _;
    write!(out, "\"sequence\":{}", input.sequence).expect("write to String is infallible");
    out.push(',');
    write_safe_string_field(&mut out, "prev_hash", input.prev_hash);
    out.push(',');
    write_safe_string_field(&mut out, "row_hash", input.row_hash);
    out.push(',');
    write_safe_string_field(&mut out, "signature", input.signature_b64);

    // public_fields: user-supplied values may contain JSON-special
    // chars in either keys or string values, so delegate per-value
    // to serde_json. Skip any key that collides with a mandatory
    // header field — preserves the prior `Map::entry().or_insert()`
    // semantics.
    for (k, v) in &input.public_fields {
        if MANDATORY_KEYS.iter().any(|m| *m == k.as_str()) {
            continue;
        }
        out.push(',');
        write_user_field(&mut out, k, v)?;
    }

    // group_payloads: pre-rendered JSON snippets from the encrypt
    // loop. Group names are runtime-controlled (alphanumeric +
    // underscore) so no key escaping; the value is already valid
    // JSON so splice in verbatim.
    for (k, v) in &input.group_payloads {
        out.push(',');
        out.push('"');
        out.push_str(k);
        out.push_str("\":");
        out.push_str(v);
    }

    out.push('}');
    out.push('\n');
    Ok(out)
}

/// Write a `"key":"value"` pair where both key and value are
/// runtime-trusted (contain no JSON-special characters and are not
/// empty-checked). Used for the mandatory header fields.
fn write_safe_string_field(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    out.push_str(value);
    out.push('"');
}

/// Write a `"key":<json-value>` pair where either the key or the
/// value may need JSON escaping. Delegates to `serde_json` for
/// correctness. Used for the user-supplied public_fields and
/// group_payloads tails of the envelope.
fn write_user_field(out: &mut String, key: &str, value: &Value) -> Result<()> {
    // Key: serialize as a JSON string. serde_json handles the
    // backslash + quote + control-char escapes correctly.
    let key_json = serde_json::to_string(key)?;
    out.push_str(&key_json);
    out.push(':');
    let val_json = serde_json::to_string(value)?;
    out.push_str(&val_json);
    Ok(())
}
