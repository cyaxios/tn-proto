//! Read-only accessors and queries over the materialized [`AdminStateCache`].
//!
//! The query surface behind `tn.admin.*` reads: progress/head pointers, the
//! vector clock, the full materialized state, the per-group recipient view, and
//! the divergence flag. The state/recipient queries auto-refresh first when the
//! cache holds a runtime backref.

use serde_json::Value;

use super::{AdminStateCache, ChainConflict};
use crate::tnpkg::VectorClock;
use crate::Result;

impl AdminStateCache {
    /// Return the number of distinct admin envelopes folded into this cache.
    ///
    /// A monotonic progress counter (the count of unique `row_hash`es seen), not
    /// a byte offset.
    pub fn at_offset(&self) -> usize {
        self.at_offset
    }

    /// Borrow the `row_hash` of the most recently folded admin envelope, if any.
    ///
    /// The cache's head pointer; `None` before any envelope has been folded.
    pub fn head_row_hash(&self) -> Option<&str> {
        self.head_row_hash.as_deref()
    }

    /// Borrow the conflicts detected so far (informational).
    ///
    /// Equivocation signals accumulated while folding — see [`ChainConflict`].
    /// Empty when the log is internally consistent.
    pub fn head_conflicts(&self) -> &[ChainConflict] {
        &self.head_conflicts
    }

    /// Borrow the cache's vector clock (read-only).
    ///
    /// `did -> {event_type -> max sequence}` across every folded envelope.
    pub fn clock(&self) -> &VectorClock {
        &self.clock
    }

    /// Borrow the current materialized [`AdminState`](crate::AdminState),
    /// auto-refreshing first if the cache holds a runtime backref.
    ///
    /// The returned JSON is the full admin document (`ceremony`, `groups`,
    /// `recipients`, `rotations`, `coupons`, `enrolments`, `vault_links`). When
    /// the cache was built via [`from_runtime_arc`](Self::from_runtime_arc) this
    /// re-pulls and folds any newly-arrived envelopes (then persists) before
    /// returning; otherwise it returns the last folded state as-is.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the auto-refresh (pull merged envelopes /
    /// persist LKV) fails.
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

    /// Return the recipients in `group`, sorted by leaf index.
    ///
    /// With `include_revoked = false` only `active` rows are returned; with
    /// `true` revoked and retired rows are included too. Auto-refreshes first
    /// when the cache holds a runtime backref (see [`state`](Self::state)).
    /// Mirrors Python's `cache.recipients()`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the auto-refresh fails.
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

    /// Return `true` iff a [`ChainConflict::SameCoordinateFork`] has been
    /// observed.
    ///
    /// The "this chain has equivocated" flag — a producer wrote two different
    /// events at one `(did, event_type, sequence)` coordinate. Other conflict
    /// kinds (leaf reuse, rotation conflict) do not set this; inspect
    /// [`head_conflicts`](Self::head_conflicts) for the full picture.
    pub fn diverged(&self) -> bool {
        self.head_conflicts
            .iter()
            .any(|c| matches!(c, ChainConflict::SameCoordinateFork { .. }))
    }
}
