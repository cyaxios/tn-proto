//! Shared parsing for handler YAML specs.
//!
//! The Python registry parses each handler kind ad-hoc (see
//! `python/tn/handlers/registry.py`). The Rust side normalizes specs
//! into a small struct first so each handler module receives a single
//! shape instead of poking at `serde_yml::Value` directly.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

use crate::{Error, Result};

/// Compiled filter — mirror of Python `tn.filters.compile_filter` and
/// TS `compileFilter`. Empty / `None` matches everything.
#[derive(Debug, Clone, Default)]
pub struct FilterSpec {
    /// Exact `event_type` match.
    pub event_type: Option<String>,
    /// Prefix that `event_type` must start with.
    pub event_type_prefix: Option<String>,
    /// Prefix that `event_type` must NOT start with.
    pub not_event_type_prefix: Option<String>,
    /// `event_type` membership allowlist.
    pub event_type_in: Option<HashSet<String>>,
    /// Exact `level` match.
    pub level: Option<String>,
    /// `level` membership allowlist.
    pub level_in: Option<HashSet<String>>,
}

impl FilterSpec {
    /// Apply the filter to one envelope. Empty filter passes everything.
    pub fn matches(&self, envelope: &JsonValue) -> bool {
        let et = envelope
            .get("event_type")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let lv = envelope
            .get("level")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if let Some(want) = &self.event_type {
            if et != want {
                return false;
            }
        }
        if let Some(prefix) = &self.event_type_prefix {
            if !et.starts_with(prefix.as_str()) {
                return false;
            }
        }
        if let Some(prefix) = &self.not_event_type_prefix {
            if et.starts_with(prefix.as_str()) {
                return false;
            }
        }
        if let Some(set) = &self.event_type_in {
            if !set.contains(et) {
                return false;
            }
        }
        if let Some(want) = &self.level {
            if lv != want {
                return false;
            }
        }
        if let Some(set) = &self.level_in {
            if !set.contains(lv) {
                return false;
            }
        }
        true
    }
}

/// Parsed handler spec — every kind shares this base, plus extra fields
/// stored as the raw JSON-converted YAML for kind-specific decoding.
#[derive(Debug, Clone)]
pub struct HandlerSpec {
    /// `kind` (lower-cased). One of `vault.push`, `vault.pull`,
    /// `fs.drop`, `fs.scan` for this module.
    pub kind: String,
    /// `name` — defaults to `kind` when omitted.
    pub name: String,
    /// Optional standard filter block.
    pub filter: FilterSpec,
    /// JSON-converted raw spec, for kind-specific keys.
    pub raw: JsonValue,
}

/// Convert a `serde_yml::Value` to `serde_json::Value` so handler
/// implementations can re-use the rest of the JSON ecosystem.
fn yaml_to_json(v: &serde_yml::Value) -> Result<JsonValue> {
    let s = serde_json::to_string(v)
        .map_err(|e| Error::InvalidConfig(format!("handler spec yaml->json: {e}")))?;
    serde_json::from_str(&s)
        .map_err(|e| Error::InvalidConfig(format!("handler spec yaml->json parse: {e}")))
}


/// Lower-cased string field lookup with fallback.
pub fn str_field<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    v.get(key).and_then(JsonValue::as_str)
}

/// Required string field — returns InvalidConfig when missing or non-string.
pub fn require_str(v: &JsonValue, key: &str, ctx: &str) -> Result<String> {
    str_field(v, key).map_or_else(
        || Err(Error::InvalidConfig(format!("{ctx}: missing required string field {key:?}"))),
        |s| Ok(s.to_string()),
    )
}

/// Parse a handler spec dict into [`HandlerSpec`].
///
/// # Errors
/// Returns `Error::InvalidConfig` when the YAML node is not a mapping
/// or `kind` is missing.
pub fn parse_handler_spec(raw: &serde_yml::Value) -> Result<HandlerSpec> {
    let json = yaml_to_json(raw)?;
    let kind_raw = str_field(&json, "kind").ok_or_else(|| {
        Error::InvalidConfig("handler spec missing required string field \"kind\"".into())
    })?;
    let kind = kind_raw.to_ascii_lowercase();
    let name = str_field(&json, "name").map_or_else(|| kind.clone(), str::to_string);
    let filter = parse_filter(&json);
    Ok(HandlerSpec {
        kind,
        name,
        filter,
        raw: json,
    })
}

fn parse_filter(spec: &JsonValue) -> FilterSpec {
    // Two shapes: top-level shorthand keys (event_type_prefix, level_in,
    // ...) OR a nested `filter:` mapping. Mirror Python's
    // `tn.filters.compile_filter` shorthand-first behaviour.
    let mut out = FilterSpec::default();
    let candidates: [&JsonValue; 2] = [spec, spec.get("filter").unwrap_or(&JsonValue::Null)];
    for src in candidates {
        if let Some(s) = str_field(src, "event_type") {
            out.event_type = Some(s.to_string());
        }
        if let Some(s) = str_field(src, "event_type_prefix") {
            out.event_type_prefix = Some(s.to_string());
        }
        if let Some(s) = str_field(src, "not_event_type_prefix") {
            out.not_event_type_prefix = Some(s.to_string());
        }
        if let Some(arr) = src.get("event_type_in").and_then(JsonValue::as_array) {
            let mut set = HashSet::new();
            for v in arr {
                if let Some(s) = v.as_str() {
                    set.insert(s.to_string());
                }
            }
            out.event_type_in = Some(set);
        }
        if let Some(s) = str_field(src, "level") {
            out.level = Some(s.to_string());
        }
        if let Some(arr) = src.get("level_in").and_then(JsonValue::as_array) {
            let mut set = HashSet::new();
            for v in arr {
                if let Some(s) = v.as_str() {
                    set.insert(s.to_string());
                }
            }
            out.level_in = Some(set);
        }
    }
    out
}

/// Parse a duration as seconds. Accepts numbers (assumed seconds) or
/// strings like `"60s"`, `"5m"`, `"1h"`, `"500ms"` — same shape as
/// Python `_parse_duration`.
///
/// # Errors
/// Returns `Error::InvalidConfig` for unparseable values.
pub fn parse_duration(v: &JsonValue, default_secs: f64) -> Result<f64> {
    if v.is_null() {
        return Ok(default_secs);
    }
    if let Some(n) = v.as_f64() {
        return Ok(n);
    }
    if let Some(n) = v.as_i64() {
        // f64 cast of i64 only loses precision past 2^53; fine for poll intervals.
        #[allow(clippy::cast_precision_loss)]
        return Ok(n as f64);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim().to_ascii_lowercase();
        let (num_part, mult) = if let Some(pre) = s.strip_suffix("ms") {
            (pre, 0.001)
        } else if let Some(pre) = s.strip_suffix('s') {
            (pre, 1.0)
        } else if let Some(pre) = s.strip_suffix('m') {
            (pre, 60.0)
        } else if let Some(pre) = s.strip_suffix('h') {
            (pre, 3600.0)
        } else {
            (s.as_str(), 1.0)
        };
        return num_part
            .trim()
            .parse::<f64>()
            .map(|n| n * mult)
            .map_err(|e| Error::InvalidConfig(format!("invalid duration {s:?}: {e}")));
    }
    Err(Error::InvalidConfig(format!(
        "invalid duration value: {v:?}"
    )))
}

/// Resolve a path relative to `yaml_dir` if not absolute.
pub fn resolve_path(p: &str, yaml_dir: &Path) -> PathBuf {
    let candidate = Path::new(p);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        yaml_dir.join(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn duration_string_seconds() {
        assert!(
            (parse_duration(&json!("30s"), 1.0).expect("30s parses") - 30.0).abs() < f64::EPSILON
        );
    }

    #[test]
    fn duration_minutes() {
        assert!(
            (parse_duration(&json!("5m"), 1.0).expect("5m parses") - 300.0).abs() < f64::EPSILON
        );
    }

    #[test]
    fn duration_milliseconds() {
        assert!(
            (parse_duration(&json!("500ms"), 1.0).expect("500ms parses") - 0.5).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn duration_number() {
        assert!(
            (parse_duration(&json!(45), 1.0).expect("45 parses") - 45.0).abs() < f64::EPSILON
        );
    }

    #[test]
    fn filter_event_type_prefix() {
        let f = FilterSpec {
            event_type_prefix: Some("tn.".into()),
            ..Default::default()
        };
        assert!(f.matches(&json!({"event_type": "tn.recipient.added"})));
        assert!(!f.matches(&json!({"event_type": "user.signup"})));
    }
}
