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

#![cfg(feature = "fs")]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::Config;
use crate::runtime::Runtime;
use crate::tnpkg::VectorClock;
use crate::Result;

mod handlers;
mod persist;

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

/// True iff `event_type` is an admin event subject to the dedicated log.
pub fn is_admin_event_type(event_type: &str) -> bool {
    ADMIN_PREFIXES.iter().any(|p| event_type.starts_with(p))
}

/// Default admin log path: `<yaml_dir>/.tn/admin/admin.ndjson`.
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

    let p = Path::new(&substituted);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        yaml_dir.join(p)
    }
}

/// LKV file path: `<yaml_dir>/.tn/admin/admin.lkv.json`.
pub fn lkv_path_for(yaml_dir: &Path) -> PathBuf {
    yaml_dir.join(".tn").join("admin").join("admin.lkv.json")
}

// --------------------------------------------------------------------------
// Conflict types (mirror Python's dataclasses).
// --------------------------------------------------------------------------

/// Equivocation / divergence signal surfaced via `head_conflicts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ChainConflict {
    /// `tn.recipient.added` arrived for a `(group, leaf_index)` already
    /// revoked / retired in local state.
    LeafReuseAttempt {
        group: String,
        leaf_index: u64,
        attempted_row_hash: String,
        originally_revoked_at_row_hash: Option<String>,
    },
    /// Two envelopes share `(did, event_type, sequence)` but carry different
    /// `row_hash`.
    SameCoordinateFork {
        did: String,
        event_type: String,
        sequence: u64,
        row_hash_a: String,
        row_hash_b: String,
    },
    /// Two `tn.rotation.completed` envelopes share `(group, generation)`
    /// but disagree on `previous_kit_sha256`.
    RotationConflict {
        group: String,
        generation: u64,
        previous_kit_sha256_a: String,
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

/// Source of merged admin envelopes for the cache. Production callers pass
/// a `Runtime` reference; tests can supply a fixed list.
pub enum CacheSource<'a> {
    /// Pull envelopes via `Runtime::admin_envelopes_merged()`. The Runtime
    /// owns decryption; the cache only folds.
    Runtime(&'a Runtime),
    /// Use a pre-collected list of merged JSON envelopes (already merged
    /// with per-group plaintexts). Used by tests + by callers that don't
    /// hold a live runtime.
    Envelopes(Vec<Value>),
}

/// Materialized AdminState cache. One per ceremony / Runtime.
///
/// The cache holds an Arc<Runtime>-style backref via `runtime` so it can
/// re-pull merged admin envelopes on `refresh()` / `state()` without the
/// caller threading the runtime through every call. Lifetime-erased via
/// `Arc` so the cache itself is `'static`.
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

impl AdminStateCache {
    /// Construct a fresh cache. Loads from `<yaml_dir>/.tn/admin/admin.lkv.json`
    /// if present; otherwise replays from the underlying admin log.
    pub fn new(yaml_path: &Path, cfg: Config, log_path: PathBuf) -> Result<Self> {
        let yaml_dir = yaml_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let admin_log_path = resolve_admin_log_path(&yaml_dir, &cfg);
        let lkv_path = lkv_path_for(&yaml_dir);
        let mut c = Self {
            yaml_dir,
            cfg,
            log_path,
            admin_log_path,
            lkv_path,
            runtime: None,
            state: empty_state(),
            clock: BTreeMap::new(),
            head_row_hash: None,
            at_offset: 0,
            head_conflicts: Vec::new(),
            row_hashes: std::collections::HashSet::new(),
            revoked_leaves: BTreeMap::new(),
            rotations_seen: BTreeMap::new(),
            coord_to_row_hash: BTreeMap::new(),
        };
        c.load_from_disk();
        Ok(c)
    }

    /// Construct a cache backed by `rt` and replay all current admin
    /// envelopes into it. Convenience that combines `new()` +
    /// `refresh_with(rt)`.
    pub fn from_runtime(rt: &Runtime) -> Result<Self> {
        let cfg = crate::config::load(rt.yaml_path())?;
        let mut c = Self::new(rt.yaml_path(), cfg, rt.log_path().to_path_buf())?;
        // Pull envelopes through rt and apply.
        let envs = rt.admin_envelopes_merged()?;
        c.replay_envelopes(envs);
        c.save_to_disk()?;
        Ok(c)
    }

    /// Construct a cache backed by an `Arc<Runtime>` so subsequent
    /// `refresh()` / `state()` calls can pull fresh envelopes without
    /// callers threading the runtime through.
    pub fn from_runtime_arc(rt: &std::sync::Arc<Runtime>) -> Result<Self> {
        let cfg = crate::config::load(rt.yaml_path())?;
        let mut c = Self::new(rt.yaml_path(), cfg, rt.log_path().to_path_buf())?;
        c.runtime = Some(rt.clone());
        let envs = rt.admin_envelopes_merged()?;
        c.replay_envelopes(envs);
        c.save_to_disk()?;
        Ok(c)
    }

    /// Refresh the cache from a `CacheSource`. Returns the number of new
    /// envelopes ingested.
    pub fn refresh_with(&mut self, source: CacheSource<'_>) -> Result<usize> {
        let envs = match source {
            CacheSource::Runtime(rt) => rt.admin_envelopes_merged()?,
            CacheSource::Envelopes(v) => v,
        };
        let before = self.at_offset;
        self.replay_envelopes(envs);
        self.save_to_disk()?;
        Ok(self.at_offset.saturating_sub(before))
    }

    fn replay_envelopes(&mut self, mut envs: Vec<Value>) {
        envs.sort_by(|a, b| {
            let at = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
            let bt = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
            let asq = a.get("sequence").and_then(Value::as_u64).unwrap_or(0);
            let bsq = b.get("sequence").and_then(Value::as_u64).unwrap_or(0);
            let arh = a.get("row_hash").and_then(Value::as_str).unwrap_or("");
            let brh = b.get("row_hash").and_then(Value::as_str).unwrap_or("");
            (at, asq, arh).cmp(&(bt, bsq, brh))
        });
        for env in &envs {
            self.apply_envelope(env);
        }
        self.at_offset = self.row_hashes.len();
    }

    /// Number of admin envelopes replayed into this cache.
    pub fn at_offset(&self) -> usize {
        self.at_offset
    }

    /// row_hash of the most recently replayed admin envelope.
    pub fn head_row_hash(&self) -> Option<&str> {
        self.head_row_hash.as_deref()
    }

    /// All detected conflicts (informational).
    pub fn head_conflicts(&self) -> &[ChainConflict] {
        &self.head_conflicts
    }

    /// Vector clock view (read-only).
    pub fn clock(&self) -> &VectorClock {
        &self.clock
    }

    /// Current materialized AdminState. Auto-refreshes if the log advanced.
    pub fn state(&mut self) -> Result<&Value> {
        if let Some(rt) = self.runtime.clone() {
            let envs = rt.admin_envelopes_merged()?;
            // Replay only newly-arrived envelopes (deduped by row_hash inside
            // apply_envelope).
            self.replay_envelopes(envs);
            self.save_to_disk()?;
        }
        Ok(&self.state)
    }

    /// Filtered recipients by group; drops non-active rows when
    /// `include_revoked=false`. Mirrors Python's `cache.recipients()`.
    pub fn recipients(&mut self, group: &str, include_revoked: bool) -> Result<Vec<Value>> {
        if let Some(rt) = self.runtime.clone() {
            let envs = rt.admin_envelopes_merged()?;
            self.replay_envelopes(envs);
            self.save_to_disk()?;
        }
        let mut out = Vec::new();
        let recipients = self
            .state
            .get("recipients")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for rec in recipients {
            let g = rec.get("group").and_then(Value::as_str).unwrap_or("");
            if g != group {
                continue;
            }
            let active = rec
                .get("active_status")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !include_revoked && active != "active" {
                continue;
            }
            out.push(rec);
        }
        out.sort_by_key(|r| r.get("leaf_index").and_then(Value::as_u64).unwrap_or(0));
        Ok(out)
    }

    /// True iff any same-coordinate fork has been observed.
    pub fn diverged(&self) -> bool {
        self.head_conflicts
            .iter()
            .any(|c| matches!(c, ChainConflict::SameCoordinateFork { .. }))
    }

    /// Force a reload. Returns the number of new envelopes ingested.
    ///
    /// When the cache was built with a runtime backref (`from_runtime_arc`)
    /// this re-pulls merged envelopes through `Runtime::admin_envelopes_merged`.
    /// Otherwise it falls back to scanning the underlying ndjson directly
    /// (Python parity; only useful when admin fields ride at envelope root).
    pub fn refresh(&mut self) -> Result<usize> {
        let before = self.at_offset;
        if let Some(rt) = self.runtime.clone() {
            let envs = rt.admin_envelopes_merged()?;
            self.replay_envelopes(envs);
        } else {
            self.replay_forward()?;
        }
        self.save_to_disk()?;
        Ok(self.at_offset.saturating_sub(before))
    }

    // ------------------------------------------------------------------
    // Internal: replay + persist
    // ------------------------------------------------------------------

    fn source_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if self.log_path.exists() {
            out.push(self.log_path.clone());
        }
        if self.admin_log_path != self.log_path && self.admin_log_path.exists() {
            out.push(self.admin_log_path.clone());
        }
        out
    }

    #[allow(dead_code)]
    fn total_envelope_count(&self) -> usize {
        let mut total = 0usize;
        for p in self.source_paths() {
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(env) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let et = env.get("event_type").and_then(Value::as_str).unwrap_or("");
                if is_admin_event_type(et) {
                    total += 1;
                }
            }
        }
        total
    }

    #[allow(dead_code)]
    fn refresh_if_log_advanced(&mut self) -> Result<()> {
        if self.total_envelope_count() <= self.at_offset {
            return Ok(());
        }
        self.replay_forward()?;
        self.save_to_disk()?;
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn replay_forward(&mut self) -> Result<()> {
        let mut envs: Vec<Value> = Vec::new();
        let mut seen_in_pass: std::collections::HashSet<String> = std::collections::HashSet::new();

        for p in self.source_paths() {
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(env) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let et = env.get("event_type").and_then(Value::as_str).unwrap_or("");
                if !is_admin_event_type(et) {
                    continue;
                }
                let Some(rh) = env.get("row_hash").and_then(Value::as_str) else {
                    continue;
                };
                if seen_in_pass.contains(rh) {
                    continue;
                }
                seen_in_pass.insert(rh.to_string());
                envs.push(env);
            }
        }

        // Stable sort by (timestamp, sequence, row_hash) like Python.
        envs.sort_by(|a, b| {
            let at = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
            let bt = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
            let asq = a.get("sequence").and_then(Value::as_u64).unwrap_or(0);
            let bsq = b.get("sequence").and_then(Value::as_u64).unwrap_or(0);
            let arh = a.get("row_hash").and_then(Value::as_str).unwrap_or("");
            let brh = b.get("row_hash").and_then(Value::as_str).unwrap_or("");
            (at, asq, arh).cmp(&(bt, bsq, brh))
        });

        for env in envs {
            self.apply_envelope(&env);
        }
        self.at_offset = self.row_hashes.len();
        Ok(())
    }

}

fn file_name_or(p: &Path, fallback: &str) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(fallback)
        .to_string()
}
