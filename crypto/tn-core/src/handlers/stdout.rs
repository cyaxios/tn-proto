//! Stdout handler — write envelope info to stdout.
//!
//! Mirrors `tn.handlers.stdout.StdoutHandler` (Python) and
//! `StdoutHandler` (TS). Default-on per `Runtime::init` so out-of-the-box
//! emits land on stdout in addition to the configured file/sink handlers.
//! Opt-out via the `TN_NO_STDOUT=1` env var.
//!
//! Two output formats:
//!
//! * `pretty` (default) — terse human-readable single line:
//!   `HH:MM:SS.mmm LEVEL  seq=N  event_type`. No DID, no hashes, no
//!   signatures, no ciphertext: those live in the on-disk attestation
//!   file for audit, not on a developer's terminal.
//! * `json` — the canonical newline-terminated NDJSON envelope (the
//!   same bytes the file handler writes to disk). Use this when piping
//!   stdout to a log shipper, `jq`, etc.
//!
//! Format selection (precedence high -> low):
//!
//! 1. `TN_STDOUT_FORMAT` env var (`pretty` | `json`)
//! 2. `format:` field on the yaml `handlers:` entry
//! 3. constructor argument
//! 4. default: `pretty`

use std::io::Write;

use serde_json::Value;

use super::{spec::FilterSpec, TnHandler};

/// Output format for the stdout handler. Mirrors the Python and TS
/// `format` kwarg / yaml field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StdoutFormat {
    /// Terse human-readable line: `HH:MM:SS.mmm LEVEL  seq=N  event_type`.
    /// Default — what shows on a developer's terminal.
    #[default]
    Pretty,
    /// Canonical newline-terminated NDJSON envelope (same bytes the
    /// file handler writes to disk). For log shippers / `jq` / etc.
    Json,
}

impl StdoutFormat {
    /// Parse from a yaml-supplied string. Unknown values fall back to
    /// the default (`Pretty`) without erroring — operators get a
    /// readable terminal even on typos.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        // "pretty" and "" are explicit; every other value (including
        // unknown formats) falls through to the same default — so
        // the wildcard arm subsumes the `"pretty" | ""` case. Kept
        // as one arm to silence clippy::match_same_arms.
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Pretty,
        }
    }

    /// Resolve the effective format, with the env-var override winning
    /// over the configured value. Same precedence as Python's
    /// `_resolve_format`.
    #[must_use]
    pub fn resolve(configured: Self) -> Self {
        match std::env::var("TN_STDOUT_FORMAT") {
            Ok(s) if !s.is_empty() => Self::parse(&s),
            _ => configured,
        }
    }
}

/// Synchronous handler that writes envelope info to `std::io::stdout()`.
///
/// Default-on: every `Runtime::init` registers one of these unless the
/// `TN_NO_STDOUT=1` env var is set. Cheap by design — one locked write
/// per emit.
pub struct StdoutHandler {
    name: String,
    filter: FilterSpec,
    format: StdoutFormat,
}

impl StdoutHandler {
    /// New handler with no filter — accepts every envelope. Format
    /// defaults to `Pretty` (overridable by `TN_STDOUT_FORMAT`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "stdout".to_string(),
            filter: FilterSpec::default(),
            format: StdoutFormat::default(),
        }
    }

    /// New handler that only emits envelopes matching `filter`.
    #[must_use]
    pub fn with_filter(filter: FilterSpec) -> Self {
        Self {
            name: "stdout".to_string(),
            filter,
            format: StdoutFormat::default(),
        }
    }

    /// New handler with explicit format + filter (used by the yaml
    /// registry path).
    #[must_use]
    pub fn with_format_and_filter(format: StdoutFormat, filter: FilterSpec) -> Self {
        Self {
            name: "stdout".to_string(),
            filter,
            format,
        }
    }
}

impl Default for StdoutHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Render an envelope `Value` as a terse human-readable line. Matches
/// the Python ``_format_pretty`` byte-for-byte.
fn render_pretty(envelope: &Value) -> Vec<u8> {
    let ts_full = envelope
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("");
    // "2026-05-05T22:27:23.712506Z" -> "22:27:23.712"
    let mut ts: &str = ts_full;
    if let Some(idx) = ts.find('T') {
        ts = &ts[idx + 1..];
    }
    if let Some(stripped) = ts.strip_suffix('Z') {
        ts = stripped;
    }
    // Truncate fractional to milliseconds.
    let ts_owned: String = if let Some(dot) = ts.find('.') {
        let head = &ts[..dot];
        let frac = &ts[dot + 1..];
        let trimmed = if frac.len() > 3 { &frac[..3] } else { frac };
        format!("{head}.{trimmed}")
    } else {
        ts.to_string()
    };

    let level_raw = envelope.get("level").and_then(Value::as_str).unwrap_or("");
    let level = if level_raw.is_empty() {
        "LOG".to_string()
    } else {
        level_raw.to_ascii_uppercase()
    };

    let seq = envelope
        .get("sequence")
        .map(|v| match v {
            Value::Number(n) => n.to_string(),
            other => other.to_string(),
        })
        .unwrap_or_default();

    let event_type = envelope
        .get("event_type")
        .and_then(Value::as_str)
        .unwrap_or("");

    // Match Python's `f"{ts:<12} {level:<5}  seq={seq}  {event_type}\n"`.
    format!("{ts_owned:<12} {level:<5}  seq={seq}  {event_type}\n").into_bytes()
}

impl TnHandler for StdoutHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, envelope: &Value) -> bool {
        // DX review #23: hide ``tn.*`` admin events from stdout by
        // default. The same default already lives in Python's
        // ``StdoutHandler`` (see python/tn/handlers/stdout.py) and in
        // ``tn.read()`` (admin events live in a separate log addressed
        // explicitly). Restore the previous noisy behaviour by setting
        // ``TN_STDOUT_INCLUDE_ADMIN=1`` in the environment.
        if let Some(et) = envelope.get("event_type").and_then(Value::as_str) {
            if et.starts_with("tn.") {
                let include = std::env::var("TN_STDOUT_INCLUDE_ADMIN")
                    .map(|v| v.trim() == "1")
                    .unwrap_or(false);
                if !include {
                    return false;
                }
            }
        }
        self.filter.matches(envelope)
    }

    fn emit(&self, envelope: &Value, raw_line: &[u8]) {
        // Lock stdout once for the whole write+newline+flush so two threads
        // don't interleave bytes mid-line. Pure best-effort: if stdout is
        // closed (rare), swallow rather than panic the publish path.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();

        // Resolve every emit so a mid-process env-var flip is honored.
        let fmt = StdoutFormat::resolve(self.format);
        match fmt {
            StdoutFormat::Json => {
                let _ = handle.write_all(raw_line);
                if !raw_line.ends_with(b"\n") {
                    let _ = handle.write_all(b"\n");
                }
            }
            StdoutFormat::Pretty => {
                let payload = render_pretty(envelope);
                let _ = handle.write_all(&payload);
            }
        }
        let _ = handle.flush();
    }

    fn close(&self) {
        // Stdout is owned by the process — nothing to release.
    }
}
