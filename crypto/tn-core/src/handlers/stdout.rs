//! Stdout handler — write canonical envelope JSON lines to stdout.
//!
//! Mirrors `tn.handlers.stdout.StdoutHandler` (Python) and
//! `StdoutHandler` (TS). Default-on per `Runtime::init` so out-of-the-box
//! emits land on stdout in addition to the configured file/sink handlers.
//! Opt-out via the `TN_NO_STDOUT=1` env var.

use std::io::Write;

use serde_json::Value;

use super::{spec::FilterSpec, TnHandler};

/// Synchronous handler that writes the raw envelope NDJSON line to
/// `std::io::stdout()`.
///
/// Default-on: every `Runtime::init` registers one of these unless the
/// `TN_NO_STDOUT=1` env var is set. Cheap by design — one locked write
/// per emit, no allocation beyond the optional newline.
pub struct StdoutHandler {
    name: String,
    filter: FilterSpec,
}

impl StdoutHandler {
    /// New handler with no filter — accepts every envelope.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "stdout".to_string(),
            filter: FilterSpec::default(),
        }
    }

    /// New handler that only emits envelopes matching `filter`.
    #[must_use]
    pub fn with_filter(filter: FilterSpec) -> Self {
        Self {
            name: "stdout".to_string(),
            filter,
        }
    }
}

impl Default for StdoutHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TnHandler for StdoutHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, envelope: &Value) -> bool {
        self.filter.matches(envelope)
    }

    fn emit(&self, _envelope: &Value, raw_line: &[u8]) {
        // Lock stdout once for the whole write+newline+flush so two threads
        // don't interleave bytes mid-line. Pure best-effort: if stdout is
        // closed (rare), swallow rather than panic the publish path.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        // Write the canonical line; append a newline if the caller didn't.
        let _ = handle.write_all(raw_line);
        if !raw_line.ends_with(b"\n") {
            let _ = handle.write_all(b"\n");
        }
        let _ = handle.flush();
    }

    fn close(&self) {
        // Stdout is owned by the process — nothing to release.
    }
}
