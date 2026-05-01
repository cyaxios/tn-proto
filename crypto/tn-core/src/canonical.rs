//! Canonical JSON serialization (RFC 8785 lite).
//!
//! Matches `tn/canonical.py::canonical_bytes` byte-for-byte:
//! - sorted keys at every nesting level
//! - compact separators (`,` and `:`, no whitespace)
//! - UTF-8 output, non-ASCII preserved (no \uXXXX escapes for BMP chars)
//! - `bytes` pre-wrapped as `{"$b64": "<base64>"}` via `wrap_bytes`
//! - NaN/inf floats rejected

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};

use crate::{Error, Result};

/// Serialize `value` to deterministic canonical bytes.
///
/// Matches the Python `canonical_bytes` byte-for-byte for supported inputs.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    encode(value, &mut out)?;
    Ok(out)
}

fn encode(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(Error::InvalidConfig(
                        "float NaN/inf not supported in canonical form".into(),
                    ));
                }
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => write_json_string(s, out),
        Value::Array(xs) => {
            out.push(b'[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            out.push(b'{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(k, out);
                out.push(b':');
                encode(&m[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_json_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0c' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Wrap bytes as the canonical `{"$b64": "..."}` JSON value used by `canonical_bytes`.
pub fn wrap_bytes(b: &[u8]) -> Value {
    let mut m = Map::new();
    m.insert("$b64".into(), Value::String(STANDARD.encode(b)));
    Value::Object(m)
}
