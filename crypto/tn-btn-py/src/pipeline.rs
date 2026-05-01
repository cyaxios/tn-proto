//! Architectural preview: full `tn.info()` envelope pipeline in Rust.
//!
//! This module exists to prove the speedup premise. It does NOT
//! replace the Python pipeline wholesale — no field classification,
//! no handler fanout, no chain state management beyond what the
//! caller threads through. One event at a time, one group named
//! "default", one signer. Enough to measure.
//!
//! The pipeline (per event):
//! 1. Canonical JSON serialization of the fields dict.
//! 2. Encrypt the plaintext with the publisher's `btn` cipher.
//! 3. HMAC-SHA256 index tokens over each field (value bytes).
//! 4. Build the row_hash canonical input (mimics tn.chain::compute_row_hash).
//! 5. SHA-256 row_hash.
//! 6. Ed25519 sign row_hash bytes (ASCII).
//! 7. Build envelope dict (including base64 of ciphertext).
//! 8. JSON-encode the envelope with separators=(",", ":"), append "\n".
//! 9. Return bytes.
//!
//! Caller handles: chain state (prev_hash, sequence), timestamp,
//! event_id, file write.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::PyPublisherState;

type HmacSha256 = Hmac<Sha256>;

/// Canonical JSON encode a plain dict of string->scalar for the inner
/// plaintext body (before cipher encrypt). Mirrors tn.canonical.canonical_bytes.
///
/// For this architectural preview we accept fields as Vec<(String, Value)>
/// where the value is already serde-valid. Keys are sorted; compact
/// JSON (no whitespace).
fn canonical_body(fields: &[(String, Value)]) -> Vec<u8> {
    let mut sorted: Vec<&(String, Value)> = fields.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut map = serde_json::Map::with_capacity(sorted.len());
    for (k, v) in sorted {
        map.insert(k.clone(), v.clone());
    }
    serde_json::to_vec(&Value::Object(map)).expect("json serialize canonical")
}

/// HMAC-SHA256 index token over a field value. Matches the shape
/// tn.indexing.index_token produces: "hmac-sha256:v1:<hex>".
///
/// Input: the group's 32-byte index key + field name + field value
/// (as canonical JSON bytes of just the value).
fn index_token(index_key: &[u8], field_name: &str, value_bytes: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(index_key).expect("hmac key");
    mac.update(field_name.as_bytes());
    mac.update(b"\0");
    mac.update(value_bytes);
    let tag = mac.finalize().into_bytes();
    let mut out = String::from("hmac-sha256:v1:");
    for b in tag.iter() {
        use std::fmt::Write;
        write!(out, "{:02x}", b).unwrap();
    }
    out
}

/// Compute row_hash canonical input + SHA-256. Mirrors
/// tn.chain.compute_row_hash closely enough to produce stable output
/// for a benchmark (the exact prefix format matches).
///
/// Argument count tracks the underlying canonical-hash specification; bundling
/// them into a struct would obscure the 1:1 mapping to the spec fields.
#[allow(clippy::too_many_arguments)]
fn compute_row_hash(
    did: &str,
    timestamp: &str,
    event_id: &str,
    event_type: &str,
    level: &str,
    prev_hash: &str,
    ciphertext: &[u8],
    field_hashes: &[(String, String)],
) -> String {
    let mut h = Sha256::new();
    h.update(did.as_bytes());
    h.update(b"\n");
    h.update(timestamp.as_bytes());
    h.update(b"\n");
    h.update(event_id.as_bytes());
    h.update(b"\n");
    h.update(event_type.as_bytes());
    h.update(b"\n");
    h.update(level.as_bytes());
    h.update(b"\n");
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(ciphertext);
    h.update(b"\n");
    for (k, v) in field_hashes {
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(v.as_bytes());
        h.update(b"\n");
    }
    let digest = h.finalize();
    let mut out = String::from("sha256:");
    for b in digest.iter() {
        use std::fmt::Write;
        write!(out, "{:02x}", b).unwrap();
    }
    out
}

/// Build a full ndjson envelope line for one event, in Rust.
///
/// Single FFI call replaces ~10 phases of the Python `emit()` hot loop.
///
/// Arguments (in order):
///   publisher_state: btn PublisherState (for encrypt)
///   signer_seed:     32-byte Ed25519 private seed
///   did:             publisher's did:key string
///   index_key:       32-byte HMAC key for field-level index tokens
///   event_type:      e.g. "bench.event"
///   timestamp:       ISO 8601 UTC with micros, e.g. "2026-04-21T18:59:20.605157Z"
///   event_id:        UUID-like string
///   sequence:        monotonic counter for this event_type
///   prev_hash:       previous row_hash or zero-sentinel
///   level:           "info" / "debug" / ...
///   fields_json:     bytes of canonical JSON `[["k1", v1], ["k2", v2], ...]`
///                    (each value is a JSON value; we sort + re-serialize
///                    for the plaintext body AND use raw value bytes for
///                    HMAC tokens)
///
/// Returns: (envelope_bytes, row_hash)
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn build_envelope_line<'py>(
    py: Python<'py>,
    publisher_state: &PyPublisherState,
    signer_seed: &[u8],
    did: &str,
    index_key: &[u8],
    event_type: &str,
    timestamp: &str,
    event_id: &str,
    sequence: u64,
    prev_hash: &str,
    level: &str,
    fields_json: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    if signer_seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "signer_seed must be 32 bytes, got {}",
            signer_seed.len()
        )));
    }
    if index_key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "index_key must be 32 bytes, got {}",
            index_key.len()
        )));
    }

    // Parse the fields_json as an array of [key, value] pairs.
    let parsed: Value = serde_json::from_slice(fields_json)
        .map_err(|e| PyValueError::new_err(format!("fields_json parse: {e}")))?;
    let arr = parsed
        .as_array()
        .ok_or_else(|| PyValueError::new_err("fields_json must be a JSON array"))?;
    let mut fields: Vec<(String, Value)> = Vec::with_capacity(arr.len());
    for item in arr {
        let pair = item
            .as_array()
            .ok_or_else(|| PyValueError::new_err("each field must be [key, value]"))?;
        if pair.len() != 2 {
            return Err(PyValueError::new_err(
                "each field must be exactly 2 elements",
            ));
        }
        let k = pair[0]
            .as_str()
            .ok_or_else(|| PyValueError::new_err("field key must be string"))?
            .to_string();
        fields.push((k, pair[1].clone()));
    }

    // 1. Canonical body bytes (plaintext for cipher).
    let body = canonical_body(&fields);

    // 2. Encrypt.
    let ct = publisher_state
        .encrypt_internal(&body)
        .map_err(|e| PyValueError::new_err(format!("btn encrypt: {e}")))?;

    // 3. HMAC index tokens per field.
    let mut field_hashes: Vec<(String, String)> = Vec::with_capacity(fields.len());
    for (k, v) in &fields {
        let value_bytes = serde_json::to_vec(v).unwrap();
        let tok = index_token(index_key, k, &value_bytes);
        field_hashes.push((k.clone(), tok));
    }
    // Sort field_hashes by name (same as canonical order).
    field_hashes.sort_by(|a, b| a.0.cmp(&b.0));

    // 4 + 5. row_hash.
    let row_hash = compute_row_hash(
        did,
        timestamp,
        event_id,
        event_type,
        level,
        prev_hash,
        &ct,
        &field_hashes,
    );

    // 6. Sign row_hash.
    let seed: [u8; 32] = signer_seed.try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(row_hash.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    // 7. Build envelope.
    let mut envelope = serde_json::Map::new();
    envelope.insert("did".into(), Value::String(did.into()));
    envelope.insert("timestamp".into(), Value::String(timestamp.into()));
    envelope.insert("event_id".into(), Value::String(event_id.into()));
    envelope.insert("event_type".into(), Value::String(event_type.into()));
    envelope.insert("level".into(), Value::String(level.into()));
    envelope.insert("sequence".into(), Value::Number(sequence.into()));
    envelope.insert("prev_hash".into(), Value::String(prev_hash.into()));
    envelope.insert("row_hash".into(), Value::String(row_hash.clone()));
    envelope.insert("signature".into(), Value::String(sig_b64));

    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    let mut field_hashes_map = serde_json::Map::new();
    for (k, v) in &field_hashes {
        field_hashes_map.insert(k.clone(), Value::String(v.clone()));
    }
    envelope.insert(
        "default".into(),
        json!({
            "ciphertext": ct_b64,
            "field_hashes": Value::Object(field_hashes_map),
        }),
    );

    // 8. Serialize envelope + newline.
    let mut line = serde_json::to_vec(&Value::Object(envelope)).expect("envelope serialize");
    line.push(b'\n');

    Ok((PyBytes::new_bound(py, &line), row_hash))
}
