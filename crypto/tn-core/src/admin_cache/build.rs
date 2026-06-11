//! Construction and load/refresh entry points for [`AdminStateCache`].
//!
//! Covers the constructors (`new`, `from_runtime`, `from_runtime_arc`), the
//! explicit-source fold (`refresh_with`), and the replay machinery that reads
//! the underlying ndjson directly when no runtime backref is held.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    empty_state, is_admin_event_type, lkv_path_for, resolve_admin_log_path, AdminStateCache,
    CacheSource,
};
use crate::config::Config;
use crate::runtime::Runtime;
use crate::Result;

impl AdminStateCache {
    /// Construct a cache for the ceremony at `yaml_path`, rehydrating from the
    /// LKV file if one is present and current.
    ///
    /// Loads `<yaml_dir>/.tn/admin/admin.lkv.json` when it exists and matches
    /// the current schema version and ceremony; a stale or missing file leaves
    /// the cache empty (callers then drive a fresh fold). Holds no runtime
    /// backref — pair with [`refresh_with`](Self::refresh_with) to feed
    /// envelopes, or prefer [`from_runtime_arc`](Self::from_runtime_arc).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] only on an unexpected failure constructing the
    /// cache; a missing/unreadable/stale LKV file is handled internally (the
    /// cache simply starts empty).
    pub fn new(yaml_path: &Path, cfg: Config, log_path: PathBuf) -> Result<Self> {
        let yaml_dir = yaml_path.parent().unwrap_or(Path::new(".")).to_path_buf();
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

    /// Construct a cache for `rt` and fold all current admin envelopes into it.
    ///
    /// Convenience that combines [`new`](Self::new) with one
    /// [`refresh_with`](Self::refresh_with) over `rt`, then persists. Does
    /// **not** keep a backref, so later [`state`](Self::state) /
    /// [`refresh`](Self::refresh) calls will not auto-pull new envelopes — use
    /// [`from_runtime_arc`](Self::from_runtime_arc) for a self-refreshing cache.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if loading the config, pulling merged envelopes
    /// from `rt`, or persisting the LKV file fails.
    pub fn from_runtime(rt: &Runtime) -> Result<Self> {
        let cfg = crate::config::load(rt.yaml_path())?;
        let mut c = Self::new(rt.yaml_path(), cfg, rt.log_path().to_path_buf())?;
        // Pull envelopes through rt and apply.
        let envs = rt.admin_envelopes_merged()?;
        c.replay_envelopes(envs);
        c.save_to_disk()?;
        Ok(c)
    }

    /// Construct a self-refreshing cache backed by an `Arc<Runtime>`.
    ///
    /// Like [`from_runtime`](Self::from_runtime) but retains the `Arc` backref,
    /// so subsequent [`state`](Self::state) / [`recipients`](Self::recipients) /
    /// [`refresh`](Self::refresh) calls re-pull fresh merged envelopes through
    /// the runtime automatically. The recommended constructor for a long-lived
    /// cache. Folds and persists once before returning.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if loading the config, pulling merged envelopes
    /// from `rt`, or persisting the LKV file fails.
    pub fn from_runtime_arc(rt: &std::sync::Arc<Runtime>) -> Result<Self> {
        let cfg = crate::config::load(rt.yaml_path())?;
        let mut c = Self::new(rt.yaml_path(), cfg, rt.log_path().to_path_buf())?;
        c.runtime = Some(rt.clone());
        let envs = rt.admin_envelopes_merged()?;
        c.replay_envelopes(envs);
        c.save_to_disk()?;
        Ok(c)
    }

    /// Fold envelopes from an explicit [`CacheSource`] into the cache and
    /// persist.
    ///
    /// The injection point for runtime-less callers and tests: pass
    /// [`CacheSource::Envelopes`] to fold a fixed list, or
    /// [`CacheSource::Runtime`] to pull through a runtime once. Deduped by
    /// `row_hash`, so re-folding overlapping input is safe. Returns the count of
    /// newly-ingested envelopes (the [`at_offset`](Self::at_offset) delta).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if pulling from a `CacheSource::Runtime` source
    /// or persisting the LKV file fails.
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

    pub(super) fn replay_envelopes(&mut self, mut envs: Vec<Value>) {
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

    /// Force a reload and return the number of new envelopes ingested.
    ///
    /// When the cache was built with a runtime backref
    /// ([`from_runtime_arc`](Self::from_runtime_arc)) this re-pulls merged
    /// envelopes through [`Runtime::admin_envelopes_merged`]. Otherwise it falls
    /// back to scanning the underlying ndjson directly (Python parity; only
    /// useful when admin fields ride at the envelope root rather than inside an
    /// encrypted group). Persists the LKV file afterward.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if pulling merged envelopes or persisting the
    /// LKV file fails.
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
