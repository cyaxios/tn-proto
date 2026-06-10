//! Materialized AdminState cache (LKV).
//!
//! Mirrors `tn/admin_cache.py` (Section 4 of the 2026-04-24 admin log
//! architecture plan). The cache holds a materialized `AdminState` plus a
//! vector clock keyed by `(did, event_type)`. The on-disk form lives at
//! `<yaml_dir>/.tn/admin/admin.lkv.json`; in-memory form is the
//! `AdminStateCache` struct below.
//!
//! Convergence rules (Section 6.1):
//! - `tn.recipient.added` events are idempotent under set union
//!   (dedupe by `row_hash`).
//! - `tn.recipient.revoked` events are absorbing: once a leaf transitions
//!   `active -> revoked`, subsequent `recipient_added` events for the same
//!   `(group, leaf_index)` are flagged as `LeafReuseAttempt` and excluded
//!   from `state.recipients` (the envelope is still appended; signed events
//!   are facts).
//! - `tn.rotation.completed` events are monotonic on `(group, generation)`;
//!   two events at the same generation with different `previous_kit_sha256`
//!   are flagged as `RotationConflict`.
//! - Same-coordinate forks (`(did, event_type, sequence)` seen twice with
//!   different `row_hash`) are flagged as `SameCoordinateFork`.
//!
//! The cache implementation is split across submodules by responsibility:
//! - `build` — construction + load/refresh entry points (from a runtime,
//!   an explicit source, or the underlying ndjson).
//! - `query` — read-only accessors and queries over the materialized state.
//! - `reduce` — folding admin envelopes into the materialized state
//!   (the per-event-type projections).
//! - `persist` — atomic LKV save and rehydrate.

#![cfg(feature = "fs")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::Config;
use crate::pathutil::resolve;
use crate::runtime::Runtime;
use crate::tnpkg::VectorClock;

mod build;
mod persist;
mod query;
mod reduce;

/// On-disk LKV layout version. Bump if the schema changes incompatibly.
pub const LKV_VERSION: u32 = 1;

/// Admin event prefixes (must match `tn/admin_log.py::_ADMIN_PREFIXES`).
const ADMIN_PREFIXES: &[&str] = &[
    "tn.ceremony.",
    "tn.group.",
    "tn.recipient.",
    "tn.rotation.",
    "tn.coupon.",
    "tn.enrolment.",
    "tn.vault.",
];

/// Return `true` iff `event_type` belongs to the admin namespace.
///
/// Admin events (those under `tn.ceremony.`, `tn.group.`, `tn.recipient.`,
/// `tn.rotation.`, `tn.coupon.`, `tn.enrolment.`, `tn.vault.`) are the ones the
/// dedicated admin log and this cache track. Must match
/// `tn/admin_log.py::_ADMIN_PREFIXES`. Pure.
///
/// # Examples
///
/// ```
/// use tn_core::admin_cache::is_admin_event_type;
///
/// assert!(is_admin_event_type("tn.recipient.added"));
/// assert!(!is_admin_event_type("tn.info"));
/// ```
pub fn is_admin_event_type(event_type: &str) -> bool {
    ADMIN_PREFIXES.iter().any(|p| event_type.starts_with(p))
}

/// Return the default admin-log path relative to the yaml dir:
/// `./.tn/admin/admin.ndjson`.
///
/// The location used when no explicit `protocol_events_location` is configured.
/// See [`resolve_admin_log_path`] for the full resolution that honors config
/// overrides.
pub fn default_admin_log_relative() -> &'static str {
    "./.tn/admin/admin.ndjson"
}

/// Resolve `<yaml_dir>/.tn/admin/admin.ndjson` (or honor an explicit
/// single-file `protocol_events_location`).
///
/// Supports the same template tokens as `Runtime::resolve_pel` for the
/// known-at-config-time placeholders: `{yaml_dir}` and `{ceremony_id}`.
/// Other tokens (`{event_type}`, `{event_class}`, `{date}`, `{did}`)
/// disqualify a template from being a single-file admin log — those
/// templates produce per-event files which the admin cache cannot
/// represent as one path. In that case we still fall back to the default
/// admin file, but the runtime's per-emit `resolve_pel` will use the
/// real per-event path.
pub fn resolve_admin_log_path(yaml_dir: &Path, cfg: &Config) -> PathBuf {
    let pel = &cfg.ceremony.protocol_events_location;
    if pel.is_empty() || pel == "main_log" {
        return yaml_dir.join(".tn").join("admin").join("admin.ndjson");
    }

    // Substitute the at-load-time-known templates first, then check whether
    // any per-emit-only tokens remain. Pre-fix this branch was guarded by
    // ``!pel.contains('{')`` so any template (even just ``{yaml_dir}``)
    // silently fell through to the default path — making the runtime
    // appear to "lose" admin events relative to where the publisher
    // expected them. Now ``{yaml_dir}/.tn/admin/admin.ndjson`` and
    // ``{yaml_dir}/somewhere.ndjson`` both resolve correctly.
    let yaml_dir_s = yaml_dir.to_string_lossy().into_owned();
    let substituted = pel
        .replace("{yaml_dir}", &yaml_dir_s)
        .replace("{ceremony_id}", &cfg.ceremony.id);

    // Per-event-only tokens mean this template is a multi-file template,
    // not a single admin log. Fall back to default.
    if substituted.contains('{') {
        return yaml_dir.join(".tn").join("admin").join("admin.ndjson");
    }

    resolve(yaml_dir, Path::new(&substituted))
}

/// Resolve the LKV cache-file path for a yaml dir:
/// `<yaml_dir>/.tn/admin/admin.lkv.json`.
///
/// Where [`AdminStateCache`] persists its materialized state between runs. The
/// admin log (`admin.ndjson`) is the source of truth; this file is a
/// rebuildable cache.
pub fn lkv_path_for(yaml_dir: &Path) -> PathBuf {
    yaml_dir.join(".tn").join("admin").join("admin.lkv.json")
}

// --------------------------------------------------------------------------
// Conflict types (mirror Python's dataclasses).
// --------------------------------------------------------------------------

/// An equivocation / divergence signal detected while folding the admin log.
///
/// Conflicts are *facts about the log*, not errors: the offending envelope is
/// still recorded (signed events are facts), but the inconsistency is surfaced
/// here so callers can react. Read them via
/// [`AdminStateCache::head_conflicts`]; a [`SameCoordinateFork`](Self::SameCoordinateFork)
/// specifically flips [`AdminStateCache::diverged`] to `true`. Serializes with
/// a snake-case `kind` tag (`leaf_reuse_attempt`, `same_coordinate_fork`,
/// `rotation_conflict`) to match Python's dataclasses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainConflict {
    /// A `tn.recipient.added` arrived for a `(group, leaf_index)` that was
    /// already revoked / retired in local state. Revocation is absorbing, so
    /// the re-add is excluded from `state.recipients` and flagged here.
    LeafReuseAttempt {
        /// Group whose leaf was reused.
        group: String,
        /// Leaf index that was already revoked / retired.
        leaf_index: u64,
        /// `row_hash` of the rejected re-add envelope.
        attempted_row_hash: String,
        /// `row_hash` of the revocation that closed this leaf, if known.
        originally_revoked_at_row_hash: Option<String>,
    },
    /// Two envelopes share `(did, event_type, sequence)` but carry different
    /// `row_hash` — the same producer wrote two different events at one
    /// coordinate (a fork in its chain).
    SameCoordinateFork {
        /// Producing device identity.
        did: String,
        /// Event type at the forked coordinate.
        event_type: String,
        /// Sequence number at the forked coordinate.
        sequence: u64,
        /// `row_hash` of the first envelope seen at this coordinate.
        row_hash_a: String,
        /// `row_hash` of the second, conflicting envelope.
        row_hash_b: String,
    },
    /// Two `tn.rotation.completed` envelopes share `(group, generation)` but
    /// disagree on `previous_kit_sha256` — divergent histories of the same
    /// rotation.
    RotationConflict {
        /// Group whose rotation forked.
        group: String,
        /// Generation number both envelopes claim.
        generation: u64,
        /// `previous_kit_sha256` from the first envelope.
        previous_kit_sha256_a: String,
        /// `previous_kit_sha256` from the second, conflicting envelope.
        previous_kit_sha256_b: String,
    },
}

// --------------------------------------------------------------------------
// AdminStateCache
// --------------------------------------------------------------------------

/// Empty AdminState document (matches Python's `_empty_state()`).
fn empty_state() -> Value {
    let mut out = Map::new();
    out.insert("ceremony".into(), Value::Null);
    out.insert("groups".into(), Value::Array(Vec::new()));
    out.insert("recipients".into(), Value::Array(Vec::new()));
    out.insert("rotations".into(), Value::Array(Vec::new()));
    out.insert("coupons".into(), Value::Array(Vec::new()));
    out.insert("enrolments".into(), Value::Array(Vec::new()));
    out.insert("vault_links".into(), Value::Array(Vec::new()));
    Value::Object(out)
}

/// Where [`AdminStateCache::refresh_with`] pulls merged admin envelopes from.
///
/// Production callers pass a live [`Runtime`] (the cache pulls decrypted,
/// merged envelopes through it); tests and runtime-less callers supply a
/// pre-collected list.
pub enum CacheSource<'a> {
    /// Pull envelopes via `Runtime::admin_envelopes_merged()`. The Runtime
    /// owns decryption; the cache only folds.
    Runtime(&'a Runtime),
    /// Use a pre-collected list of merged JSON envelopes (already merged
    /// with per-group plaintexts). Used by tests + by callers that don't
    /// hold a live runtime.
    Envelopes(Vec<Value>),
}

/// Materialized AdminState cache (the "last known value", LKV). One per
/// ceremony / [`Runtime`].
///
/// Folds the admin log into a queryable [`AdminState`](crate::AdminState)
/// document plus a [`VectorClock`], persisting the result to
/// `<yaml_dir>/.tn/admin/admin.lkv.json` so a later run rehydrates instead of
/// replaying from scratch. This is the engine behind `tn.admin.*` reads.
/// Folding is idempotent (envelopes dedupe by `row_hash`) and convergent under
/// the rules in the module docs, surfacing equivocation as
/// [`ChainConflict`]s rather than failing.
///
/// Build one bound to a [`Runtime`] with [`from_runtime_arc`](Self::from_runtime_arc)
/// (or [`from_runtime`](Self::from_runtime)); the `Arc` backref lets
/// [`state`](Self::state) / [`refresh`](Self::refresh) re-pull fresh merged
/// envelopes without the caller threading the runtime through every call. The
/// `Arc` also lifetime-erases the backref so the cache itself is `'static`.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use std::sync::Arc;
/// use tn_core::{Runtime, AdminStateCache};
///
/// # fn main() -> tn_core::Result<()> {
/// let rt = Arc::new(Runtime::init(Path::new("tn.yaml"))?);
/// let mut cache = AdminStateCache::from_runtime_arc(&rt)?;
///
/// // Active recipients in the default group, conflicts (if any) alongside.
/// let active = cache.recipients("default", false)?;
/// println!("{} active; diverged={}", active.len(), cache.diverged());
/// # Ok(())
/// # }
/// ```
pub struct AdminStateCache {
    #[allow(dead_code)]
    yaml_dir: PathBuf,
    cfg: Config,
    #[allow(dead_code)]
    log_path: PathBuf,
    #[allow(dead_code)]
    admin_log_path: PathBuf,
    lkv_path: PathBuf,
    runtime: Option<std::sync::Arc<Runtime>>,

    state: Value,
    /// `did -> {event_type -> max sequence}`.
    clock: VectorClock,
    head_row_hash: Option<String>,
    at_offset: usize,
    head_conflicts: Vec<ChainConflict>,

    // Internal recovery fields for incremental replay.
    row_hashes: std::collections::HashSet<String>,
    revoked_leaves: BTreeMap<(String, u64), Option<String>>,
    rotations_seen: BTreeMap<(String, u64), String>,
    coord_to_row_hash: BTreeMap<(String, String, u64), String>,
}

fn file_name_or(p: &Path, fallback: &str) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(fallback)
        .to_string()
}
