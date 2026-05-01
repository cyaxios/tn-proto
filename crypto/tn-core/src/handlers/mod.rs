//! Output handlers for TN runtime events (admin-log §5.2).
//!
//! Mirrors the Python `tn.handlers` package and the TS `@tn/sdk` handlers
//! sub-tree. Defines the [`TnHandler`] trait — anything that wants to react
//! to attested envelopes (or push admin snapshots out of process)
//! implements it. The registry [`build_handlers`] consumes the YAML
//! `handlers:` block and produces a list of trait objects.
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
//! Handlers attached via [`crate::Runtime::add_handler`] receive every
//! emitted envelope through the `Runtime::emit` fan-out — matching
//! Python's `Logger.handlers` loop (`python/tn/logger.py:343`) and TS's
//! `NodeRuntime` fan-out (`ts-sdk/src/runtime/node_runtime.ts:376`).
//! Each handler's `accepts()` filter is consulted per-envelope; failing
//! handlers are logged + swallowed so a downstream issue never aborts a
//! publish. The vault/fs handlers in this module also drive their own
//! scheduler threads off `&Runtime` for snapshot building
//! (`Runtime::export`) and absorb (`Runtime::absorb`), so push/pull
//! patterns work whether or not the host wires emit-time fan-out.
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

pub mod spec;
pub mod fs_drop;
pub mod fs_scan;
pub mod stdout;
pub mod vault_pull;
pub mod vault_push;

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::Result;

pub use fs_drop::FsDropHandler;
pub use fs_scan::FsScanHandler;
pub use stdout::StdoutHandler;
pub use vault_pull::{VaultInboxClient, VaultInboxItem, VaultPullHandler};
pub use vault_push::{VaultPostClient, VaultPushHandler};

/// A TN output handler. Mirrors `tn.handlers.base.TNHandler` (Python) and
/// `TNHandler` (TS).
///
/// Handlers are sync on the caller's thread for [`emit`](Self::emit). The
/// vault/fs handlers in this module spawn their own background scheduler
/// threads when applicable; emit/close is the synchronous control surface.
pub trait TnHandler: Send + Sync {
    /// Stable handler name (used in logs / outbox paths).
    fn name(&self) -> &str;

    /// Whether this envelope should reach the handler. Defaults to the
    /// handler's compiled filter; implementations may add their own
    /// allowlist on top (e.g. [`FsDropHandler`] additionally requires
    /// `event_type` to start with `tn.`).
    fn accepts(&self, envelope: &Value) -> bool;

    /// Process one accepted envelope. The `raw_line` is the bytes the
    /// runtime would have written to disk (newline-terminated NDJSON).
    /// Push-style handlers produce a snapshot from `Runtime` state in
    /// background; the envelope is purely a trigger for them.
    fn emit(&self, envelope: &Value, raw_line: &[u8]);

    /// Best-effort shutdown — drains in-flight work, joins scheduler
    /// threads, persists cursors. Idempotent.
    fn close(&self);
}

/// Heap-allocated handler list used by hosts and tests.
pub type HandlerList = Vec<Arc<dyn TnHandler>>;

/// Build a handler list from the YAML `handlers:` block. The
/// `runtime` is shared across all push handlers; pull/scan handlers
/// hold their own `Arc<Runtime>` so they can drive `export` / `absorb`
/// from their scheduler thread.
///
/// `yaml_dir` resolves relative paths in the spec. `default_log_dir`
/// is reserved for the `file.*` kinds when those land in Rust.
///
/// # Errors
/// Returns `Error::InvalidConfig` for unknown / malformed handler
/// specs, mirroring the Python `ValueError`.
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
            "stdout" => Arc::new(stdout::StdoutHandler::with_filter(parsed.filter.clone())),
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
