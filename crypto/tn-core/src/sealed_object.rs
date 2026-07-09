//! Sealed-object shape and verification — the pure half of
//! `tn.seal` / `tn.unseal`.
//!
//! A sealed object is a standalone envelope: the same nine-scalar wire
//! schema the emit path writes, with `sequence: 0`, `prev_hash: ""`,
//! `level: ""`, the reserved public marker `tn_sealed: 1`, always
//! signed, and group blocks encrypted per the sealing ceremony's yaml.
//! It travels outside any log (a file, an HTTP body, a prompt), so a
//! verifier holds nothing but the object itself.
//!
//! That drives the one behavioral difference from the log reader: the
//! row-hash recompute here is **self-describing** — every key that is
//! not one of the nine reserved envelope scalars and not a group block
//! is a public field. (The log read path filters through the local
//! yaml's `public_fields`, which would make a foreign sealed object
//! unverifiable.)
//!
//! Mirrors `python/tn/seal.py` (the normative reference). The fs-bound
//! halves — `Runtime::seal` / `Runtime::unseal` and the keystore
//! key-bag walk — live in `runtime/seal.rs`; this module is
//! unconditional so wasm/no-fs builds can parse and verify sealed
//! objects.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};

use crate::chain::{compute_row_hash, GroupInput, RowHashInput};
use crate::signing::signature_from_b64;
use crate::{DeviceKey, Error, Result};

/// The reserved public marker key every sealed object carries
/// (`tn_sealed: 1`). A number, so the row-hash preimage's `str(value)`
/// renders identically across SDK implementations.
pub const TN_SEALED_KEY: &str = "tn_sealed";

/// Event type of the receipt row `seal` chains through the normal
/// runtime emit path (default on).
pub const SEALED_RECEIPT_EVENT: &str = "tn.object.sealed";

/// The nine mandatory envelope scalars (mirror `seal.py`'s
/// `_ENVELOPE_RESERVED`). Everything else in a sealed object is either
/// a public field or a group block.
pub const ENVELOPE_RESERVED: [&str; 9] = [
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

/// JavaScript's `Number.MAX_SAFE_INTEGER` (2^53 - 1). Public integers
/// past this are not exactly representable as float64, so a JSON
/// runtime that parses them into a double silently changes their value.
pub const JS_SAFE_INT_MAX: u64 = (1 << 53) - 1;

/// One encrypted group block lifted out of a sealed envelope:
/// base64-decoded ciphertext plus the (sorted) field-hash tokens.
#[derive(Debug, Clone)]
pub struct GroupBlock {
    /// Raw ciphertext bytes (base64-decoded from the wire).
    pub ciphertext: Vec<u8>,
    /// Field-name → HMAC index token, as carried on the wire.
    pub field_hashes: BTreeMap<String, String>,
}

/// Outcome of [`verify_sealed`]: which of the two integrity checks
/// passed. Mirrors Python's `valid` dict (`{"signature": …,
/// "row_hash": …}`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SealedValid {
    /// The envelope's `signature` verifies over its `row_hash` bytes
    /// under its `device_identity`.
    pub signature: bool,
    /// The `row_hash` recomputes from the envelope's own contents.
    pub row_hash: bool,
}

/// A sealed object as returned by `Runtime::seal`: the parsed envelope
/// plus the verbatim wire line.
///
/// `wire` is the compact envelope JSON **without** a trailing newline
/// (Python's `str(sealed)` has none). Callers must transport `wire`
/// verbatim — re-serializing the envelope through a foreign JSON
/// runtime is exactly the round-trip the fragile-value guard exists to
/// protect, and key order is load-bearing only for byte-identity, not
/// verification.
pub struct SealedObjectLine {
    /// The envelope as a parsed JSON object (wire-faithful key order).
    pub envelope: Map<String, Value>,
    /// The compact envelope JSON line, no trailing newline. This is
    /// the transport artifact.
    pub wire: String,
}

fn malformed(reason: impl Into<String>) -> Error {
    Error::Malformed {
        kind: "sealed object",
        reason: reason.into(),
    }
}

/// Parse sealed-object source text into an envelope map.
///
/// Mirrors `seal.py::_parse_envelope_text`: the text must be JSON, the
/// JSON must be an object, and the object must pass
/// [`require_envelope_shape`].
///
/// # Errors
///
/// [`Error::Malformed`] (`kind: "sealed object"`) for invalid JSON, a
/// non-object document, or missing required keys. Having no key that
/// fits is NOT an error anywhere in the unseal pipeline — malformed
/// input is the only thing this rejects.
pub fn parse_sealed_source(text: &str) -> Result<Map<String, Value>> {
    let obj: Value = serde_json::from_str(text)
        .map_err(|e| malformed(format!("not a sealed object: invalid JSON ({e})")))?;
    match obj {
        Value::Object(m) => require_envelope_shape(m),
        _ => Err(malformed("not a sealed object: JSON is not an object")),
    }
}

/// Require the seven keys unseal dereferences unconditionally:
/// `device_identity`, `event_type`, `row_hash`, `signature`,
/// `timestamp`, `event_id`, `sequence`.
///
/// `seal` always writes all nine envelope scalars; requiring these
/// seven up front means malformed input surfaces as a typed error,
/// never a lookup panic deeper in the pipeline (mirrors
/// `seal.py::_require_envelope_shape`).
///
/// # Errors
///
/// [`Error::Malformed`] (`kind: "sealed object"`) naming the missing
/// keys.
pub fn require_envelope_shape(env: Map<String, Value>) -> Result<Map<String, Value>> {
    const REQUIRED: [&str; 7] = [
        "device_identity",
        "event_type",
        "row_hash",
        "signature",
        "timestamp",
        "event_id",
        "sequence",
    ];
    let missing: Vec<&str> = REQUIRED
        .iter()
        .copied()
        .filter(|k| !env.contains_key(*k))
        .collect();
    if !missing.is_empty() {
        return Err(malformed(format!(
            "not a sealed object: missing {}",
            missing.join(", ")
        )));
    }
    Ok(env)
}

/// Lift every encrypted group block out of the envelope.
///
/// The wire is self-describing: any object value carrying a
/// `"ciphertext"` key is a group block (mirrors the unseal loop in
/// `seal.py:298-308`). Ciphertext is standard base64.
///
/// # Errors
///
/// [`Error::Malformed`] (`kind: "sealed object"`) when a block's
/// ciphertext is not a decodable base64 string, or a field-hash entry
/// is not a string. (Python raises `UnsealError` for the former; the
/// latter would crash its verify recompute — a typed error is the
/// closest honest behavior.)
pub fn extract_group_blocks(env: &Map<String, Value>) -> Result<BTreeMap<String, GroupBlock>> {
    let mut blocks: BTreeMap<String, GroupBlock> = BTreeMap::new();
    for (k, v) in env {
        let Some(obj) = v.as_object() else { continue };
        if !obj.contains_key("ciphertext") {
            continue;
        }
        let ct_b64 = obj.get("ciphertext").and_then(Value::as_str);
        let ciphertext = ct_b64
            .and_then(|s| STANDARD.decode(s).ok())
            .ok_or_else(|| malformed(format!("group block {k:?} has undecodable ciphertext")))?;
        let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
        if let Some(fh) = obj.get("field_hashes").and_then(Value::as_object) {
            for (fname, ftok) in fh {
                let tok = ftok.as_str().ok_or_else(|| {
                    malformed(format!(
                        "group block {k:?} has a non-string field hash for {fname:?}"
                    ))
                })?;
                field_hashes.insert(fname.clone(), tok.to_string());
            }
        }
        blocks.insert(
            k.clone(),
            GroupBlock {
                ciphertext,
                field_hashes,
            },
        );
    }
    Ok(blocks)
}

/// Verify a sealed envelope: recompute its row hash self-describingly
/// and check its signature. Never errors — any decode or verify
/// failure simply reports `false` for that check (the caller decides
/// whether that is fatal; mirrors `seal.py:310-345`).
///
/// Self-describing recompute: every key not in [`ENVELOPE_RESERVED`]
/// and not in `blocks` is a public field. `timestamp` / `event_id` /
/// `level` / `prev_hash` default to `""` when absent.
pub fn verify_sealed(env: &Map<String, Value>, blocks: &BTreeMap<String, GroupBlock>) -> SealedValid {
    let mut public_out: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in env {
        if ENVELOPE_RESERVED.contains(&k.as_str()) || blocks.contains_key(k) {
            continue;
        }
        public_out.insert(k.clone(), v.clone());
    }
    let groups: BTreeMap<String, GroupInput> = blocks
        .iter()
        .map(|(name, b)| {
            (
                name.clone(),
                GroupInput {
                    ciphertext: b.ciphertext.clone(),
                    field_hashes: b.field_hashes.clone(),
                },
            )
        })
        .collect();

    let str_of = |key: &str| env.get(key).and_then(Value::as_str).unwrap_or("");
    let expected = compute_row_hash(&RowHashInput {
        device_identity: str_of("device_identity"),
        timestamp: str_of("timestamp"),
        event_id: str_of("event_id"),
        event_type: str_of("event_type"),
        level: str_of("level"),
        prev_hash: str_of("prev_hash"),
        public_fields: &public_out,
        groups: &groups,
    });

    let row_hash_ok = expected == str_of("row_hash");

    // Signature check: verify env["signature"] over env["row_hash"]
    // bytes under env["device_identity"]. Any failure shape (missing
    // key, bad base64, malformed DID) means unverified, never an Err.
    let signature_ok = (|| {
        let did = env.get("device_identity")?.as_str()?;
        let row = env.get("row_hash")?.as_str()?;
        let sig_b64 = env.get("signature")?.as_str()?;
        let sig = signature_from_b64(sig_b64).ok()?;
        DeviceKey::verify_did(did, row.as_bytes(), &sig).ok()
    })()
    .unwrap_or(false);

    SealedValid {
        signature: signature_ok,
        row_hash: row_hash_ok,
    }
}

/// Reject public field values that cannot survive a foreign JSON
/// round-trip. Mirrors `seal.py::_reject_fragile_public`.
///
/// A sealed object is verified by re-hashing its PUBLIC fields as
/// `str(value)` (encrypted group fields are hashed as opaque
/// ciphertext, so they are safe for any value). A non-Python JSON
/// runtime that parses the object into native values and re-serializes
/// it — a browser, PowerShell/.NET, most LLM tool boundaries — will
/// reformat some numbers: an integral float like `1.0` collapses to
/// `1` and an integer past 2^53 loses precision. Any of those flips
/// the recomputed row hash far from the seal call, so we refuse them
/// here, loudly and locally.
///
/// Booleans are exempt (they round-trip cleanly); lists and dicts are
/// checked recursively; error messages name the offending path
/// (`'pv[0]'`, `'pv.amt'`).
///
/// # Errors
///
/// [`Error::InvalidConfig`] for any float, or any integer whose
/// magnitude exceeds [`JS_SAFE_INT_MAX`].
pub fn reject_fragile_public(public_out: &Map<String, Value>) -> Result<()> {
    fn check(value: &Value, path: &str) -> Result<()> {
        match value {
            // Value::Bool round-trips cleanly (true/false) — exempt.
            // (In serde_json Bool is not a Number, so no explicit
            // bool-before-int ordering is needed as in Python.)
            Value::Number(n) => {
                if n.is_f64() {
                    return Err(Error::InvalidConfig(format!(
                        "public field '{path}' is a float ({n}); floats do not \
                         have a canonical form across JSON runtimes (an integral float \
                         like 1.0 collapses to 1 when a browser or .NET reserializes \
                         the object), which would break row-hash verification. Put it \
                         in an encrypted group (any type is safe there), or pass it as \
                         a string or Decimal."
                    )));
                }
                let magnitude = n
                    .as_u64()
                    .or_else(|| n.as_i64().map(i64::unsigned_abs))
                    .unwrap_or(0);
                if magnitude > JS_SAFE_INT_MAX {
                    return Err(Error::InvalidConfig(format!(
                        "public field '{path}' is an integer beyond +/-(2**53-1) \
                         ({n}); a JSON runtime that parses it into a float64 \
                         loses precision, which would break row-hash verification. \
                         Put it in an encrypted group (any type is safe there), or \
                         pass it as a string."
                    )));
                }
                Ok(())
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    check(item, &format!("{path}[{i}]"))?;
                }
                Ok(())
            }
            Value::Object(m) => {
                for (k, v) in m {
                    check(v, &format!("{path}.{k}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    for (k, v) in public_out {
        check(v, k)?;
    }
    Ok(())
}

/// Reconstruct a group's AAD bytes from a record's public `tn_aad` echo.
///
/// The writer bound `canonical_bytes(marker)` to the group's body and
/// echoed the `{group: marker}` map as a canonical JSON string under
/// `tn_aad`. Parse it and re-canonicalize this group's marker so
/// `decrypt_with_aad` verifies; an absent / empty / malformed entry
/// yields empty bytes (nothing was bound). Mirrors
/// `tn.reader._aad_bytes_for` and the TS `aadBytesFor`. Shared by the
/// log read path (`runtime/read.rs`) and the sealed-object decrypt
/// walk.
pub fn aad_bytes_for(env: &Value, group: &str) -> Vec<u8> {
    let raw = match env.get("tn_aad").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(),
    };
    let binding: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    match binding.get(group) {
        Some(marker @ Value::Object(o)) if !o.is_empty() => {
            crate::canonical::canonical_bytes(marker).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}
