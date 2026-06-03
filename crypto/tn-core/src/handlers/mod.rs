//! Output handlers for TN runtime events (admin-log §5.2).
//!
//! Mirrors the Python `tn.handlers` package and the TS `@tn/sdk` handlers
//! sub-tree. Defines the [`TnHandler`] trait — the extension point for anything
//! that wants to react to attested envelopes as the runtime writes them (or
//! push admin snapshots out of process). The registry [`build_handlers`]
//! consumes the YAML `handlers:` block and produces a list of trait objects the
//! runtime fans out to.
//!
//! ## Supported kinds
//!
//! | YAML kind   | Implementation               | Purpose                                |
//! |-------------|-----------------------------|----------------------------------------|
//! | `vault.push`| [`vault_push::VaultPushHandler`]| POST `.tnpkg` snapshots to a vault. |
//! | `vault.pull`| [`vault_pull::VaultPullHandler`]| Poll a vault inbox + absorb.        |
//! | `fs.drop`   | [`fs_drop::FsDropHandler`]   | Drop `.tnpkg` into an outbox dir.      |
//! | `fs.scan`   | [`fs_scan::FsScanHandler`]   | Watch a dir + absorb dropped files.    |
//!
//! The Python registry supports more kinds (`file.rotating`, `kafka`,
//! `delta`, `s3`, etc.). Those remain Python-only for now (out of scope for
//! the four push/pull handlers landed in commit 78f5617). Adding them later
//! follows the same trait + registry pattern.
//!
//! Handlers attached via [`crate::Runtime::add_handler`] are fanned out to for
//! every envelope the runtime writes — matching Python's `Logger.handlers` loop
//! (`python/tn/logger.py:343`) and TS's `NodeRuntime` fan-out
//! (`ts-sdk/src/runtime/node_runtime.ts:376`). Each handler's
//! [`accepts`](TnHandler::accepts) filter is consulted per-envelope; a handler
//! that fails is logged and swallowed so a downstream issue never aborts a
//! publish. The vault/fs handlers in this module also drive their own scheduler
//! threads off `&Runtime` for snapshot building ([`crate::Runtime::export`])
//! and absorb ([`crate::Runtime::absorb`]), so push/pull patterns work whether
//! or not the host wires write-time fan-out.
//!
//! ## Filter spec
//!
//! All four kinds accept the standard `filter:` block (mirroring Python's
//! `tn.filters.compile_filter`). Field names use `event_type`,
//! `event_type_prefix`, `not_event_type_prefix`, `event_type_in`,
//! `level`, `level_in`. See [`spec::FilterSpec`].

#![cfg(feature = "fs")]
// Handlers maintain mutex-guarded state and join scheduler threads; the
// expect() calls on those locks document poisoning invariants the
// caller is expected to honour, similar to the rest of tn-core's Mutex
// usage. Documenting `# Panics` on every accessor would be noise.
#![allow(clippy::missing_panics_doc)]
// Handlers and helpers commonly take owned `Arc<Runtime>` so they can
// hand it off to spawned scheduler threads; this is by design, not a
// pessimization.
#![allow(clippy::needless_pass_by_value)]
// Constructors and `with_*` chains are intentionally not `#[must_use]`
// — callers regularly capture them into Arc<dyn TnHandler> and the
// helper-style chain reads cleaner without the attribute on every
// link.
#![allow(clippy::must_use_candidate)]

pub mod fs_drop;
pub mod fs_scan;
pub mod spec;
pub mod stdout;
pub mod vault_pull;
pub mod vault_push;

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::Result;

pub use fs_drop::FsDropHandler;
pub use fs_scan::FsScanHandler;
pub use stdout::{StdoutFormat, StdoutHandler};
pub use vault_pull::{VaultInboxClient, VaultInboxItem, VaultPullHandler};
pub use vault_push::{VaultPostClient, VaultPushHandler};

/// A TN output handler — the trait downstream sinks implement to receive
/// attested events.
///
/// The runtime calls [`accepts`](Self::accepts) then
/// [`emit`](Self::emit) for each envelope it writes, synchronously on the
/// writing thread. Implementations must therefore be cheap and non-blocking in
/// `emit`: the vault/fs handlers in this module hand work to their own
/// background scheduler threads rather than doing I/O inline. `emit` and
/// [`close`](Self::close) are the synchronous control surface; any heavy lifting
/// happens off-thread. Must be `Send + Sync` to live behind the
/// `Arc<dyn TnHandler>` the runtime fans out to. Mirrors
/// `tn.handlers.base.TNHandler` (Python) and `TNHandler` (TS).
pub trait TnHandler: Send + Sync {
    /// Return this handler's stable name.
    ///
    /// Used in diagnostic logs and to derive outbox paths; should be stable for
    /// the handler's lifetime.
    fn name(&self) -> &str;

    /// Decide whether `envelope` should reach this handler.
    ///
    /// Consulted by the runtime before [`emit`](Self::emit); returning `false`
    /// skips the envelope for this handler only. Implementations typically
    /// delegate to their compiled `filter:` and may add an allowlist on top —
    /// e.g. [`FsDropHandler`] additionally requires `event_type` to start with
    /// `tn.`. Must not mutate handler state (the runtime may call it for
    /// handlers that are ultimately skipped).
    fn accepts(&self, envelope: &Value) -> bool;

    /// Hand one accepted envelope to this handler.
    ///
    /// Called only after [`accepts`](Self::accepts) returns `true`. `envelope`
    /// is the parsed JSON record and `raw_line` is the exact newline-terminated
    /// NDJSON bytes the runtime writes to disk — file-style sinks can append
    /// `raw_line` verbatim. Push-style handlers (vault/fs) treat the call as a
    /// trigger and build a snapshot from [`crate::Runtime`] state on their
    /// scheduler thread rather than shipping the envelope itself. Errors are the
    /// handler's to absorb: this returns `()`, and the runtime logs-and-swallows
    /// any panic so one sink never aborts a publish. Must not block the caller.
    fn emit(&self, envelope: &Value, raw_line: &[u8]);

    /// Shut the handler down, best-effort.
    ///
    /// Drains in-flight work, joins any scheduler threads, and persists cursors
    /// so a later run resumes cleanly. Idempotent — calling it more than once is
    /// safe and a no-op after the first.
    fn close(&self);
}

/// A list of reference-counted handlers, as held by a host or the runtime.
///
/// The shape [`build_handlers`] returns and [`crate::Runtime::add_handler`]
/// feeds from; `Arc` so a handler can be shared between the runtime's fan-out
/// and its own scheduler thread.
pub type HandlerList = Vec<Arc<dyn TnHandler>>;

/// Build a handler list from the YAML `handlers:` block.
///
/// Parses each spec and constructs the matching handler. The shared `runtime`
/// backs push handlers; pull/scan handlers capture their own `Arc<Runtime>` so
/// they can drive [`crate::Runtime::export`] / [`crate::Runtime::absorb`] from
/// their scheduler thread. `yaml_dir` resolves relative paths in the spec. This
/// is how a ceremony's configured outputs come to life at runtime init.
///
/// # Errors
/// Returns [`crate::Error::InvalidConfig`] for an unknown handler kind or a
/// malformed spec, mirroring the Python `ValueError`.
pub fn build_handlers(
    specs: &[serde_yml::Value],
    runtime: Arc<crate::Runtime>,
    yaml_dir: &Path,
) -> Result<HandlerList> {
    let mut out: HandlerList = Vec::new();
    for raw in specs {
        let parsed = spec::parse_handler_spec(raw)?;
        let handler: Arc<dyn TnHandler> = match parsed.kind.as_str() {
            "vault.push" => Arc::new(vault_push::VaultPushHandler::from_spec(
                &parsed,
                runtime.clone(),
            )?),
            "vault.pull" => Arc::new(vault_pull::VaultPullHandler::from_spec(
                &parsed,
                runtime.clone(),
                yaml_dir,
            )?),
            "fs.drop" => Arc::new(fs_drop::FsDropHandler::from_spec(
                &parsed,
                runtime.clone(),
                yaml_dir,
            )?),
            "fs.scan" => Arc::new(fs_scan::FsScanHandler::from_spec(
                &parsed,
                runtime.clone(),
                yaml_dir,
            )?),
            "stdout" => {
                let format = raw
                    .as_mapping()
                    .and_then(|m| m.get("format"))
                    .and_then(|v| v.as_str())
                    .map(stdout::StdoutFormat::parse)
                    .unwrap_or_default();
                Arc::new(stdout::StdoutHandler::with_format_and_filter(
                    format,
                    parsed.filter.clone(),
                ))
            }
            other => {
                return Err(crate::Error::InvalidConfig(format!(
                    "tn.yaml: unknown handler kind {other:?} on handler {:?}",
                    parsed.name
                )));
            }
        };
        out.push(handler);
    }
    Ok(out)
}
